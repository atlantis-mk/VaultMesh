import { execFile } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { firefoxExtensionId } from "./browser-identity.mjs";
import { buildBrowserExtension } from "./build-browser-extension.mjs";

const execFileAsync = promisify(execFile);
const workspace = path.resolve(import.meta.dirname, "..");
const extensionRoot = path.join(workspace, "apps", "browser-extension");
const wxtOutput = path.join(extensionRoot, ".output");

export function extensionReleaseAssetNames(version) {
  if (!/^\d+\.\d+\.\d+-review(?:\.\d+)?$/.test(version)) {
    throw new Error("扩展发布版本必须是规范 Review SemVer。");
  }
  return {
    chrome: `VaultMesh_${version}_chrome-extension.zip`,
    firefox: `VaultMesh_${version}_firefox-extension.zip`,
  };
}

export function validateExtensionManifest(manifest, { target, version, chromeExtensionKey }) {
  const browserVersion = version.split("-", 1)[0];
  if (!manifest || typeof manifest !== "object" || manifest.version !== browserVersion) {
    throw new Error(`${target} extension manifest 版本不一致。`);
  }
  const permissions = Array.isArray(manifest.permissions) ? manifest.permissions : [];
  if (!permissions.includes("nativeMessaging")) {
    throw new Error(`${target} extension manifest 缺少 nativeMessaging。`);
  }
  if (target === "chrome") {
    if (manifest.manifest_version !== 3
      || manifest.key !== chromeExtensionKey
      || manifest.minimum_chrome_version !== "127"
      || manifest.version_name !== version) {
      throw new Error("Chrome extension manifest 身份或 MV3 基线无效。");
    }
    // ADR-0057: the browser-wide WebAuthn proxy is permanently removed from every target.
    if (permissions.includes("webAuthenticationProxy") || manifest.browser_specific_settings) {
      throw new Error("Chrome extension manifest 浏览器专属字段无效。");
    }
  } else if (target === "firefox") {
    if (manifest.manifest_version !== 2
      || manifest.browser_specific_settings?.gecko?.id !== firefoxExtensionId
      || JSON.stringify(manifest.browser_specific_settings?.gecko?.data_collection_permissions) !== JSON.stringify({ required: ["none"] })
      || "key" in manifest
      || "minimum_chrome_version" in manifest
      || permissions.includes("webAuthenticationProxy")) {
      throw new Error("Firefox extension manifest 身份、MV2 或权限边界无效。");
    }
  } else {
    throw new Error("未知 extension target。");
  }
}

export function validateExtensionArchiveEntries(entries) {
  if (!entries.includes("manifest.json")) throw new Error("Extension ZIP 缺少 manifest.json。");
  for (const entry of entries) {
    if (!entry || entry.startsWith("/") || entry.split("/").includes("..")) {
      throw new Error(`Extension ZIP 包含不安全路径：${entry}`);
    }
    if (/(^|\/)\.env(?:\.|$)|\.map$/i.test(entry)) {
      throw new Error(`Extension ZIP 包含禁止发布文件：${entry}`);
    }
  }
}

async function archiveEntries(archive) {
  const { stdout } = await execFileAsync("unzip", ["-Z1", archive], { maxBuffer: 4 * 1024 * 1024 });
  return stdout.split(/\r?\n/).filter(Boolean);
}

async function archiveManifest(archive) {
  const { stdout } = await execFileAsync("unzip", ["-p", archive, "manifest.json"], { maxBuffer: 1024 * 1024 });
  return JSON.parse(stdout);
}

async function findArchive(target) {
  const entries = await readdir(wxtOutput);
  const matches = entries.filter((entry) => entry.endsWith(`-${target}.zip`) && !entry.endsWith("-sources.zip"));
  if (matches.length !== 1) throw new Error(`预期恰好一个 ${target} extension ZIP，实际 ${matches.length}。`);
  return path.join(wxtOutput, matches[0]);
}

export async function buildBrowserExtensionRelease({ outputDirectory, environment = process.env } = {}) {
  const version = JSON.parse(await readFile(path.join(workspace, "package.json"), "utf8")).version;
  const names = extensionReleaseAssetNames(version);
  const destination = outputDirectory ?? path.join(workspace, "artifacts", "browser-extensions");
  await rm(wxtOutput, { recursive: true, force: true });
  const chromeIdentity = await buildBrowserExtension("zip", environment, { requireRelease: true, target: "chrome" });
  const chromeArchive = await findArchive("chrome");
  const firefoxIdentity = await buildBrowserExtension("zip", environment, { requireRelease: true, target: "firefox" });
  const firefoxArchive = await findArchive("firefox");
  if (chromeIdentity.chromeExtensionId !== firefoxIdentity.chromeExtensionId
    || chromeIdentity.firefoxExtensionId !== firefoxIdentity.firefoxExtensionId) {
    throw new Error("Chrome 与 Firefox 构建身份漂移。");
  }
  for (const [target, archive] of [["chrome", chromeArchive], ["firefox", firefoxArchive]]) {
    await execFileAsync("unzip", ["-tq", archive], { maxBuffer: 4 * 1024 * 1024 });
    validateExtensionArchiveEntries(await archiveEntries(archive));
    validateExtensionManifest(await archiveManifest(archive), {
      target,
      version,
      chromeExtensionKey: chromeIdentity.chromeExtensionKey,
    });
  }
  await mkdir(destination, { recursive: true });
  const chromeOutput = path.join(destination, names.chrome);
  const firefoxOutput = path.join(destination, names.firefox);
  await copyFile(chromeArchive, chromeOutput);
  await copyFile(firefoxArchive, firefoxOutput);
  return { version, chromeOutput, firefoxOutput, ...chromeIdentity };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const outputIndex = process.argv.indexOf("--output");
    if (process.argv.slice(2).some((argument, index, all) => argument !== "--output" && all[index - 1] !== "--output")) {
      throw new Error("用法：build-browser-extension-release.mjs [--output <directory>]");
    }
    const outputDirectory = outputIndex === -1 ? undefined : process.argv[outputIndex + 1];
    if (outputIndex !== -1 && !outputDirectory) throw new Error("--output 缺少目录。");
    const result = await buildBrowserExtensionRelease({ outputDirectory });
    console.log(`已生成 Chrome 与 Firefox Review ZIP：${result.version}`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
