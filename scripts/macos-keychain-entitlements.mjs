import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const KEYCHAIN_ENTITLEMENTS = path.join(
  scriptDirectory,
  "../apps/tauri-desktop/src-tauri/Entitlements.keychain.plist",
);
export const DESKTOP_KEYCHAIN_ACCESS_GROUP = "$(TeamIdentifierPrefix)com.vaultmesh.desktop";
const MAIN_EXECUTABLE = "vaultmesh-tauri-desktop";
const NATIVE_HOST = "vaultmesh-native-host";
const FORBIDDEN = ["bitwarden", "dev-host", "agent-mcp", "unsigned"];

export function keychainEntitlementsAreTeamScoped(plist = readFileSync(KEYCHAIN_ENTITLEMENTS, "utf8")) {
  if (FORBIDDEN.some((token) => plist.toLowerCase().includes(token))) return false;
  return plist.includes("<key>keychain-access-groups</key>")
    && plist.includes(DESKTOP_KEYCHAIN_ACCESS_GROUP)
    && !plist.includes("com.apple.security.app-sandbox");
}

export function shouldApplyTeamKeychainEntitlements(identity) {
  if (typeof identity !== "string") return false;
  const trimmed = identity.trim();
  if (!trimmed || trimmed === "-") return false;
  if (FORBIDDEN.some((token) => trimmed.toLowerCase().includes(token))) return false;
  return true;
}

function isDesktopAccessGroup(value) {
  return value === DESKTOP_KEYCHAIN_ACCESS_GROUP
    || /^[A-Z0-9]{10}\.com\.vaultmesh\.desktop$/.test(value);
}

function xmlEscape(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function plistXml(text) {
  const start = text.indexOf("<plist");
  if (start === -1) return "";
  return text.slice(start);
}

function entitlementKeys(xml) {
  return [...xml.matchAll(/<key>([^<]+)<\/key>/g)].map((match) => match[1]);
}

function emptyEntitlements() {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>${DESKTOP_KEYCHAIN_ACCESS_GROUP}</string>
    </array>
</dict>
</plist>
`;
}

function groupAlreadyPresent(arrayXml) {
  return [...arrayXml.matchAll(/<string>([^<]*)<\/string>/g)]
    .map((match) => match[1]
      .replaceAll("&lt;", "<")
      .replaceAll("&gt;", ">")
      .replaceAll("&amp;", "&"))
    .some(isDesktopAccessGroup);
}

/**
 * Merge the desktop Keychain access group into an existing entitlements plist.
 * Every existing key is kept. The static access-group plist must not replace
 * Hardened Runtime, WebKit/JIT, or any other entitlement.
 */
export function mergeKeychainAccessGroup(existing) {
  const text = typeof existing === "string" ? existing : "";
  const xml = plistXml(text);
  if (!xml.trim()) return emptyEntitlements();
  const plistAt = text.indexOf("<plist");
  const prefix = plistAt > 0 ? text.slice(0, plistAt) : "";
  const preserved = entitlementKeys(xml);
  let merged;
  const keyTag = "<key>keychain-access-groups</key>";
  const keyAt = xml.indexOf(keyTag);
  if (keyAt === -1) {
    const entry = `    <key>keychain-access-groups</key>
    <array>
        <string>${xmlEscape(DESKTOP_KEYCHAIN_ACCESS_GROUP)}</string>
    </array>
`;
    if (xml.includes("<dict/>")) {
      merged = xml.replace("<dict/>", `<dict>\n${entry}</dict>`);
    } else {
      const end = xml.lastIndexOf("</dict>");
      if (end === -1) throw new Error("entitlements plist 没有 dictionary");
      merged = `${xml.slice(0, end)}${entry}${xml.slice(end)}`;
    }
  } else {
    const arrayStart = xml.indexOf("<array>", keyAt);
    const arrayEnd = xml.indexOf("</array>", arrayStart);
    const dictEnd = xml.indexOf("</dict>", keyAt);
    if (arrayStart === -1 || arrayEnd === -1 || (dictEnd !== -1 && arrayStart > dictEnd)) {
      throw new Error("keychain-access-groups 缺少 array");
    }
    const arrayXml = xml.slice(arrayStart, arrayEnd + "</array>".length);
    merged = groupAlreadyPresent(arrayXml)
      ? xml
      : `${xml.slice(0, arrayEnd)}        <string>${xmlEscape(DESKTOP_KEYCHAIN_ACCESS_GROUP)}</string>\n${xml.slice(arrayEnd)}`;
  }
  for (const key of preserved) {
    if (!merged.includes(`<key>${key}</key>`)) {
      throw new Error(`重签不能删除已有 entitlement: ${key}`);
    }
  }
  if (!merged.includes(DESKTOP_KEYCHAIN_ACCESS_GROUP) && !groupAlreadyPresent(merged)) {
    throw new Error("合并后的 entitlements 缺少桌面钥匙串访问组");
  }
  return `${prefix}${merged}`;
}

export function keychainSignPlan(appPath, identity) {
  if (!shouldApplyTeamKeychainEntitlements(identity) || !keychainEntitlementsAreTeamScoped()) {
    return null;
  }
  const macos = path.join(appPath, "Contents", "MacOS");
  return {
    identity: identity.trim(),
    mergeAccessGroup: DESKTOP_KEYCHAIN_ACCESS_GROUP,
    preservesExistingEntitlements: true,
    signOrder: [
      path.join(macos, NATIVE_HOST),
      appPath,
    ],
    excluded: [
      path.join(macos, "vaultmesh-agent-mcp"),
      path.join(macos, "vaultmesh-bitwarden-dev-host"),
    ],
  };
}

export async function applyMacOSKeychainEntitlements(appPath, identity, platform = process.platform, io = {}) {
  const plan = keychainSignPlan(appPath, identity);
  if (!plan || platform !== "darwin") return plan;
  const dump = io.dumpEntitlements ?? dumpEntitlements;
  const sign = io.codesign ?? codesignMerged;
  const signed = [];
  for (const target of plan.signOrder) {
    const merged = mergeKeychainAccessGroup(await dump(target));
    await sign(plan.identity, merged, target);
    signed.push({ target, merged });
  }
  return { ...plan, signed };
}

function dumpEntitlements(target) {
  return new Promise((resolve) => {
    const child = spawn("codesign", ["-d", "--entitlements", ":-", target], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.once("error", () => resolve(""));
    child.once("exit", () => resolve(stdout));
  });
}

async function codesignMerged(identity, entitlementsXml, target) {
  const directory = await mkdtemp(path.join(tmpdir(), "vaultmesh-entitlements-"));
  const file = path.join(directory, "entitlements.plist");
  await writeFile(file, entitlementsXml);
  try {
    await codesign(identity, file, target);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function codesign(identity, entitlements, target) {
  return new Promise((resolve, reject) => {
    const child = spawn("codesign", [
      "--force",
      "--timestamp",
      "--options",
      "runtime",
      "--entitlements",
      entitlements,
      "--sign",
      identity,
      target,
    ], { stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`codesign 退出码 ${code}: ${target}`));
    });
  });
}
