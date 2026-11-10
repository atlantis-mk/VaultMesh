import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { lstat } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";

import { browserIdentityEnvironment } from "./browser-identity.mjs";
import { prepareAgentSidecar } from "./prepare-agent-sidecar.mjs";
import { applyMacOSKeychainEntitlements } from "./macos-keychain-entitlements.mjs";
import { prepareBrowserHostSidecar } from "./prepare-browser-host-sidecar.mjs";

const workspace = path.resolve(import.meta.dirname, "..");
const desktopWorkspace = path.join(workspace, "apps", "tauri-desktop");
const require = createRequire(import.meta.url);
const tauriCli = require.resolve("@tauri-apps/cli/tauri.js");
const tauriConfiguration = JSON.parse(
  readFileSync(path.join(desktopWorkspace, "src-tauri", "tauri.conf.json"), "utf8"),
);
const tauriSidecarConfiguration = JSON.parse(
  readFileSync(path.join(desktopWorkspace, "src-tauri", "tauri.agent.conf.json"), "utf8"),
);

export async function verifyPackagedMacOSSidecars(appPath) {
  for (const sidecar of tauriSidecarConfiguration.bundle.externalBin) {
    const sidecarPath = path.join(appPath, "Contents", "MacOS", path.basename(sidecar));
    let metadata;
    try {
      metadata = await lstat(sidecarPath);
    } catch (error) {
      throw new Error(`Tauri package sidecar 缺失：${sidecarPath}`, { cause: error });
    }
    if (!metadata.isFile() || metadata.size === 0 || (metadata.mode & 0o111) === 0) {
      throw new Error(`Tauri package sidecar 必须是非空普通可执行文件：${sidecarPath}`);
    }
  }
}

export function parseTauriBuildArguments(arguments_) {
  const options = {
    requireRelease: false,
    verbose: false,
    target: undefined,
    bundles: undefined,
    updaterVersion: undefined,
  };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--release-identity") {
      options.requireRelease = true;
      continue;
    }
    if (argument === "--verbose") {
      options.verbose = true;
      continue;
    }
    if (["--target", "--bundles", "--updater-version"].includes(argument)) {
      const value = arguments_[index + 1];
      if (!value) throw new Error(buildUsage());
      const key = argument === "--target" ? "target" : argument === "--bundles" ? "bundles" : "updaterVersion";
      if (options[key]) throw new Error(buildUsage());
      options[key] = value;
      index += 1;
      continue;
    }
    throw new Error(buildUsage());
  }
  if (options.target && !/^[A-Za-z0-9_.-]+$/.test(options.target)) throw new Error("Rust target triple 无效。");
  if (options.bundles && !/^[a-z]+(?:,[a-z]+)*$/.test(options.bundles)) throw new Error("Tauri bundle 列表无效。");
  if (options.updaterVersion && !isSemver(options.updaterVersion)) {
    throw new Error("更新版本必须是规范 SemVer。");
  }
  return options;
}

function buildUsage() {
  return "用法：build-tauri.mjs [--release-identity] [--verbose] [--target <triple>] [--bundles <list>] [--updater-version <semver>]";
}

export function tauriBuildEnvironment(baseEnvironment = process.env, options = {}) {
  const environment = browserIdentityEnvironment(baseEnvironment, options);
  delete environment.VAULTMESH_UPDATER_ENABLED;
  if (options.updaterEnabled) environment.VAULTMESH_UPDATER_ENABLED = "1";
  const isMacTarget = options.target
    ? options.target.endsWith("-apple-darwin")
    : process.platform === "darwin";
  if (options.target?.endsWith("-apple-darwin")) {
    const minimumSystemVersion = tauriConfiguration.bundle?.macOS?.minimumSystemVersion;
    if (!/^\d+\.\d+(?:\.\d+)?$/.test(minimumSystemVersion)) {
      throw new Error("Tauri macOS minimumSystemVersion 无效。");
    }
    environment.MACOSX_DEPLOYMENT_TARGET = minimumSystemVersion;
  }
  if (isMacTarget && !options.requireRelease && !environment.APPLE_SIGNING_IDENTITY?.trim()) {
    environment.APPLE_SIGNING_IDENTITY = "-";
  }
  return environment;
}

export function updaterBuildConfig(environment, version, { includeMsi = false } = {}) {
  if (!isSemver(version)) throw new Error("更新版本必须是规范 SemVer。");
  const endpoint = requiredEnvironment(environment, "VAULTMESH_UPDATER_ENDPOINT");
  const publicKey = requiredEnvironment(environment, "VAULTMESH_UPDATER_PUBLIC_KEY");
  requiredEnvironment(environment, "TAURI_SIGNING_PRIVATE_KEY");
  let parsedEndpoint;
  try {
    parsedEndpoint = new URL(endpoint);
  } catch {
    throw new Error("VAULTMESH_UPDATER_ENDPOINT 必须是有效 HTTPS URL。");
  }
  if (
    parsedEndpoint.protocol !== "https:" ||
    parsedEndpoint.username ||
    parsedEndpoint.password ||
    parsedEndpoint.search ||
    parsedEndpoint.hash
  ) {
    throw new Error("VAULTMESH_UPDATER_ENDPOINT 必须是不含凭据、query 或 fragment 的 HTTPS URL。");
  }
  if (publicKey.trim().length < 32) throw new Error("VAULTMESH_UPDATER_PUBLIC_KEY 无效。");
  const configuration = {
    version,
    bundle: {
      createUpdaterArtifacts: true,
      externalBin: [...tauriSidecarConfiguration.bundle.externalBin],
    },
    plugins: {
      updater: {
        pubkey: publicKey.trim(),
        endpoints: [parsedEndpoint.toString()],
        windows: { installMode: "passive" },
      },
    },
  };
  if (includeMsi) {
    configuration.bundle.windows = {
      wix: { version: windowsMsiVersion(version) },
    };
  }
  return configuration;
}

export function windowsMsiVersion(version) {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(version);
  if (!match) throw new Error("MSI 版本来源必须是规范 SemVer。");
  const [, majorText, minorText, patchText, prerelease] = match;
  const major = Number(majorText);
  const minor = Number(minorText);
  const patch = Number(patchText);
  if (major > 255 || minor > 255 || patch > 65_535) {
    throw new Error("MSI 版本超出 Windows Installer 数值范围。");
  }
  if (!prerelease) return `${major}.${minor}.${patch}`;
  if (prerelease === "review") return `${major}.${minor}.${patch}`;
  const buildText = prerelease.split(".").at(-1);
  if (!/^(0|[1-9]\d*)$/.test(buildText)) {
    throw new Error("包含 MSI 的预发布版本必须以数值序号结尾。");
  }
  const build = Number(buildText);
  if (build > 65_535) throw new Error("MSI 预发布序号超出 Windows Installer 数值范围。");
  return `${major}.${minor}.${patch}.${build}`;
}

export function tauriCliInvocation(arguments_, executable = process.execPath) {
  return {
    command: executable,
    arguments: [tauriCli, ...arguments_],
    cwd: desktopWorkspace,
  };
}

function requiredEnvironment(environment, key) {
  const value = environment[key];
  if (typeof value !== "string" || !value.trim()) throw new Error(`缺少 ${key}。`);
  return value.trim();
}

function isSemver(value) {
  return /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(value);
}

export async function buildTauri({
  environment = process.env,
  requireRelease = false,
  verbose = false,
  target,
  bundles,
  updaterVersion,
} = {}) {
  const buildEnvironment = tauriBuildEnvironment(environment, {
    requireRelease,
    updaterEnabled: Boolean(updaterVersion),
    target,
  });
  await prepareAgentSidecar({ target, environment: buildEnvironment });
  await prepareBrowserHostSidecar({ target, environment: buildEnvironment });
  const configuration = updaterVersion
    ? JSON.stringify(updaterBuildConfig(buildEnvironment, updaterVersion, {
      includeMsi: bundles?.split(",").includes("msi") ?? false,
    }))
    : "src-tauri/tauri.agent.conf.json";
  const arguments_ = [
    "build",
    "--config",
    configuration,
  ];
  if (target) arguments_.push("--target", target);
  if (bundles) arguments_.push("--bundles", bundles);
  if (verbose) arguments_.push("--verbose");
  const invocation = tauriCliInvocation(arguments_);
  await run(invocation.command, invocation.arguments, buildEnvironment, invocation.cwd);
  if (target ? target.endsWith("-apple-darwin") : process.platform === "darwin") {
    const appPath = path.join(
      workspace, "target", ...(target ? [target] : []), "release", "bundle", "macos",
      `${tauriConfiguration.productName}.app`,
    );
    await verifyPackagedMacOSSidecars(appPath);
    await applyMacOSKeychainEntitlements(appPath, buildEnvironment.APPLE_SIGNING_IDENTITY);
  }
  return buildEnvironment.VAULTMESH_BROWSER_EXTENSION_ID;
}

function run(command, arguments_, environment, cwd = workspace) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, arguments_, {
      cwd,
      env: environment,
      stdio: "inherit",
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} ${signal ? `被 ${signal} 终止` : `退出码 ${code ?? 1}`}`));
    });
  });
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const options = parseTauriBuildArguments(process.argv.slice(2));
    const extensionId = await buildTauri(options);
    console.log(`Tauri package 已绑定 Browser extension ID：${extensionId}`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
