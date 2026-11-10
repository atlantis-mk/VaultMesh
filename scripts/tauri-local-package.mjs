import { spawn } from "node:child_process";
import {
  access,
  cp,
  mkdir,
  mkdtemp,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";

import { developmentExtensionId, developmentExtensionKey } from "./browser-identity.mjs";
import { verifyPackagedMacOSSidecars } from "./build-tauri.mjs";
import { verifyBrowserHost } from "./tauri-browser-host-probe.mjs";
import {
  installedTauriApp,
  installedTauriHost,
  launchInstalledTauriApp,
} from "./tauri-local-launch.mjs";

const workspace = path.resolve(import.meta.dirname, "..");
const packagedApp = path.join(workspace, "target", "release", "bundle", "macos", "VaultMesh.app");
const extensionOut = path.join(workspace, "apps", "browser-extension", ".output");
const artifactsDir = path.join(workspace, "artifacts", "local");
const extensionZip = path.join(artifactsDir, "VaultMesh-browser-extension-local.zip");
const localDmg = path.join(artifactsDir, "VaultMesh-Tauri-local.dmg");
const backupApp = "/Applications/VaultMesh.local-package-backup.app";
const markerPath = path.join("Contents", "Resources", "vaultmesh-local-build.json");
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const buildEnvironment = {
  ...process.env,
  WXT_CHROME_EXTENSION_KEY: developmentExtensionKey,
  WXT_NATIVE_HOST_NAME: "com.vaultmesh.browser",
  VAULTMESH_BROWSER_EXTENSION_ID: developmentExtensionId,
};

let movedExistingApp = false;
let installAttempted = false;
let previousAppWasRunning = false;
try {
  if (process.platform !== "darwin") throw new Error("Tauri 本机打包安装目前仅支持 macOS。");
  await assertNoStaleBackup();
  await run(pnpm, ["--filter", "@vaultmesh/browser-extension", "zip"], buildEnvironment);
  const agentTarget = (await capture("rustc", ["--print", "host-tuple"])).trim();
  await run(process.execPath, [
    path.join(workspace, "scripts", "prepare-agent-sidecar.mjs"),
    "--target", agentTarget,
  ], buildEnvironment);
  await run(process.execPath, [
    path.join(workspace, "scripts", "prepare-browser-host-sidecar.mjs"),
    "--target", agentTarget,
  ], buildEnvironment);
  await run(pnpm, [
    "--filter", "@vaultmesh/tauri-desktop", "tauri", "build", "--bundles", "app",
    "--config", "src-tauri/tauri.agent.conf.json",
  ], buildEnvironment);
  await verifyPackagedMacOSSidecars(packagedApp);
  await writeFile(path.join(packagedApp, markerPath), JSON.stringify({
    kind: "vaultmesh-tauri-local-test-build",
    extensionId: developmentExtensionId,
    createdAt: new Date().toISOString(),
  }, null, 2));
  await run("codesign", ["--force", "--deep", "--sign", "-", packagedApp]);
  await run("codesign", ["--verify", "--deep", "--strict", "--verbose=2", packagedApp]);

  // Finish and verify every distributable before touching the installed app.
  await mkdir(artifactsDir, { recursive: true });
  await rm(localDmg, { force: true });
  const dmgStage = await mkdtemp(path.join(tmpdir(), "vaultmesh-local-dmg-"));
  try {
    await run("ditto", [packagedApp, path.join(dmgStage, "VaultMesh.app")]);
    await run("hdiutil", [
      "create", "-volname", "VaultMesh", "-srcfolder", dmgStage,
      "-ov", "-format", "UDZO", localDmg,
    ]);
  } finally {
    await rm(dmgStage, { recursive: true, force: true });
  }
  await run("hdiutil", ["verify", localDmg]);
  const generatedZip = await newestZip(extensionOut);
  await cp(generatedZip, extensionZip, { force: true });
  await run("unzip", ["-tq", extensionZip]);

  if (await exists(installedTauriApp)) {
    const bundleId = (await capture("/usr/bin/plutil", [
      "-extract", "CFBundleIdentifier", "raw", "-o", "-",
      path.join(installedTauriApp, "Contents", "Info.plist"),
    ])).trim();
    if (!["com.vaultmesh.desktop", "com.vaultmesh.tauri.preview"].includes(bundleId)) {
      throw new Error(`${installedTauriApp} 不是可识别的 VaultMesh 安装，拒绝覆盖。`);
    }
    previousAppWasRunning = (await installedVaultMeshPids()).length > 0;
    await stopInstalledVaultMesh(bundleId);
    await stopInstalledNativeHosts();
    await rename(installedTauriApp, backupApp);
    movedExistingApp = true;
  } else {
    await stopInstalledNativeHosts();
  }
  installAttempted = true;
  await run("ditto", [packagedApp, installedTauriApp]);
  await run("codesign", ["--verify", "--deep", "--strict", "--verbose=2", installedTauriApp]);

  await resetLocalBrowserPairing();
  const launch = await launchInstalledTauriApp();
  await verifyBrowserHost({
    nativeHostPath: installedTauriHost,
    extensionId: launch.extensionId,
  });

  if (movedExistingApp) {
    await rm(backupApp, { recursive: true, force: true });
    movedExistingApp = false;
  }

  console.log("\nVaultMesh Tauri 本机打包安装已完成：");
  console.log(`应用：${installedTauriApp}`);
  console.log(`Tauri DMG：${localDmg}`);
  console.log(`插件 ZIP：${extensionZip}`);
  console.log(`开发者模式目录：${path.join(extensionOut, "chrome-mv3")}`);
  console.log(`扩展 ID：${launch.extensionId}`);
  console.log("加密 Vault 未被本地打包脚本读取、复制或删除；本机浏览器配对凭据已按新签名刷新。");
} catch (error) {
  const rollbackErrors = [];
  let safeToReplaceInstalledApp = true;
  if (installAttempted || movedExistingApp) {
    await stopInstalledVaultMesh("com.vaultmesh.desktop")
      .catch((rollbackError) => {
        safeToReplaceInstalledApp = false;
        rollbackErrors.push(rollbackError);
      });
    await stopInstalledNativeHosts()
      .catch((rollbackError) => {
        safeToReplaceInstalledApp = false;
        rollbackErrors.push(rollbackError);
      });
    if (safeToReplaceInstalledApp) {
      await rm(installedTauriApp, { recursive: true, force: true })
        .catch((rollbackError) => {
          safeToReplaceInstalledApp = false;
          rollbackErrors.push(rollbackError);
        });
    }
  }
  if (movedExistingApp && safeToReplaceInstalledApp) {
    let restoredPreviousApp = false;
    await rename(backupApp, installedTauriApp)
      .then(() => { restoredPreviousApp = true; })
      .catch((rollbackError) => rollbackErrors.push(rollbackError));
    if (previousAppWasRunning && restoredPreviousApp) {
      await run("open", [installedTauriApp])
        .catch((rollbackError) => rollbackErrors.push(rollbackError));
    }
  }
  console.error(error instanceof Error ? error.message : error);
  if (rollbackErrors.length > 0) {
    console.error("本机应用回滚未完整完成：");
    for (const rollbackError of rollbackErrors) {
      console.error(`- ${rollbackError instanceof Error ? rollbackError.message : rollbackError}`);
    }
    if (await exists(backupApp)) console.error(`原应用备份仍保留在：${backupApp}`);
  }
  process.exitCode = 1;
}

async function stopInstalledVaultMesh(bundleId) {
  const pids = await installedVaultMeshPids();
  if (pids.length === 0) return;
  await run("/usr/bin/osascript", ["-e", `tell application id "${bundleId}" to quit`]).catch(() => {});
  await new Promise((resolve) => setTimeout(resolve, 1200));
  for (const pid of await installedVaultMeshPids()) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {}
  }
  await new Promise((resolve) => setTimeout(resolve, 250));
  if ((await installedVaultMeshPids()).length > 0) {
    throw new Error("已安装的 VaultMesh 未能退出，拒绝替换正在运行的应用。");
  }
}

async function installedVaultMeshPids() {
  const output = await capture("/usr/bin/pgrep", [
    "-f", "^/Applications/VaultMesh\\.app/Contents/MacOS/vaultmesh-tauri-desktop( |$)",
  ]).catch(() => "");
  return output
    .split("\n")
    .filter((line) => /^[1-9][0-9]*$/.test(line))
    .map(Number);
}

async function stopInstalledNativeHosts() {
  const pids = await installedNativeHostPids();
  for (const pid of pids) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {}
  }
  if (pids.length === 0) return;
  await new Promise((resolve) => setTimeout(resolve, 250));
  if ((await installedNativeHostPids()).length > 0) {
    throw new Error("已安装的 VaultMesh Native Host 未能退出，拒绝替换正在运行的应用。");
  }
}

async function installedNativeHostPids() {
  const output = await capture("/usr/bin/pgrep", [
    "-f", "^/Applications/VaultMesh\\.app/Contents/MacOS/vaultmesh-(?:native-host|agent-mcp)( |$)",
  ]).catch(() => "");
  return output
    .split("\n")
    .filter((line) => /^[1-9][0-9]*$/.test(line))
    .map(Number);
}

async function resetLocalBrowserPairing() {
  // Ad-hoc signing produces a new code identity on each local rebuild. Rotate
  // only the device-bound browser credential so the new App can provision it;
  // the encrypted Vault and migration receipt remain untouched.
  await run("/usr/bin/security", [
    "delete-generic-password",
    "-s", "com.vaultmesh.desktop.browser-pairing",
    "-a", "native-host-hmac-v1",
  ]).catch(() => {});
  await rm(path.join(
    homedir(), "Library", "Application Support", "com.vaultmesh.desktop", "browser-pairing.json",
  ), { force: true });
  await rm(path.join(tmpdir(), "vaultmesh-tauri-browser.sock"), { force: true });
}

async function assertNoStaleBackup() {
  if (await exists(backupApp)) {
    throw new Error(`检测到上次本机打包备份：${backupApp}。为避免误删，已停止。`);
  }
}

async function newestZip(directory) {
  const entries = await readdir(directory, { recursive: true, withFileTypes: true });
  const candidates = [];
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".zip")) continue;
    const candidate = path.join(entry.parentPath, entry.name);
    const metadata = await stat(candidate);
    candidates.push({ candidate, modifiedAt: metadata.mtimeMs });
  }
  candidates.sort((left, right) => right.modifiedAt - left.modifiedAt);
  if (!candidates[0]) throw new Error("扩展已构建，但没有找到 ZIP 产物。");
  return candidates[0].candidate;
}

async function exists(target) {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}

function run(command, args, environment = process.env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: workspace, env: environment, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} ${signal ? `被 ${signal} 终止` : `退出码 ${code ?? 1}`}`));
    });
  });
}

function capture(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) resolve(Buffer.concat(stdout).toString("utf8"));
      else reject(new Error(Buffer.concat(stderr).toString("utf8") || `${command} 退出码 ${code ?? 1}`));
    });
  });
}
