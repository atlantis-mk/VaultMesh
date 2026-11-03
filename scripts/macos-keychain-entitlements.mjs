import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const KEYCHAIN_ENTITLEMENTS = path.join(
  scriptDirectory,
  "../apps/tauri-desktop/src-tauri/Entitlements.keychain.plist",
);
const MAIN_EXECUTABLE = "vaultmesh-tauri-desktop";
const NATIVE_HOST = "vaultmesh-native-host";
const FORBIDDEN = ["bitwarden", "dev-host", "agent-mcp", "unsigned"];

export function keychainEntitlementsAreTeamScoped(plist = readFileSync(KEYCHAIN_ENTITLEMENTS, "utf8")) {
  if (FORBIDDEN.some((token) => plist.toLowerCase().includes(token))) return false;
  return plist.includes("<key>keychain-access-groups</key>")
    && plist.includes("$(TeamIdentifierPrefix)com.vaultmesh.desktop")
    && !plist.includes("com.apple.security.app-sandbox");
}

export function shouldApplyTeamKeychainEntitlements(identity) {
  if (typeof identity !== "string") return false;
  const trimmed = identity.trim();
  if (!trimmed || trimmed === "-") return false;
  if (FORBIDDEN.some((token) => trimmed.toLowerCase().includes(token))) return false;
  return true;
}

export function keychainSignPlan(appPath, identity) {
  if (!shouldApplyTeamKeychainEntitlements(identity) || !keychainEntitlementsAreTeamScoped()) {
    return null;
  }
  const macos = path.join(appPath, "Contents", "MacOS");
  return {
    identity: identity.trim(),
    entitlements: KEYCHAIN_ENTITLEMENTS,
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

export async function applyMacOSKeychainEntitlements(appPath, identity, platform = process.platform) {
  const plan = keychainSignPlan(appPath, identity);
  if (!plan || platform !== "darwin") return plan;
  for (const target of plan.signOrder) {
    await codesign(plan.identity, plan.entitlements, target);
  }
  return plan;
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
