import { access, readFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import { developmentExtensionId } from "./browser-identity.mjs";

export const installedTauriApp = "/Applications/VaultMesh.app";
export const installedTauriHost = path.join(
  installedTauriApp, "Contents", "MacOS", "vaultmesh-native-host",
);
export const installedAgentMcp = path.join(
  installedTauriApp, "Contents", "MacOS", "vaultmesh-agent-mcp",
);

export async function launchInstalledTauriApp({
  extensionId = developmentExtensionId,
  environment = process.env,
} = {}) {
  await access(path.join(installedTauriApp, "Contents", "MacOS", "vaultmesh-tauri-desktop"));
  await run(
    "open",
    [installedTauriApp, "--args", "-ApplePersistenceIgnoreState", "YES"],
    environment,
  );
  const appData = path.join(homedir(), "Library", "Application Support", "com.vaultmesh.desktop");
  const pairingRecord = path.join(appData, "browser-pairing.json");
  const socket = path.join(tmpdir(), "vaultmesh-tauri-browser.sock");
  await waitFor(async () => {
    try {
      const record = JSON.parse(await readFile(pairingRecord, "utf8"));
      if (record.version !== 1 || record.enabled !== true) return false;
      return await canConnectUnixSocket(socket);
    } catch {
      return false;
    }
  }, 60_000, "Tauri 已启动，但浏览器 Broker 未在 60 秒内就绪。");

  await run(process.execPath, [path.resolve(import.meta.dirname, "tauri-macos-browser-host.mjs")], {
    ...environment,
    VAULTMESH_BROWSER_EXTENSION_ID: extensionId,
    VAULTMESH_TAURI_NATIVE_HOST: installedTauriHost,
  });
  return { appData, socket, extensionId };
}

async function waitFor(check, timeoutMs, message) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(message);
}

export function canConnectUnixSocket(socketPath, timeoutMs = 1_000) {
  return new Promise((resolve) => {
    const client = createConnection(socketPath);
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      client.destroy();
      resolve(ok);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    client.once("connect", () => finish(true));
    client.once("error", () => finish(false));
  });
}

function run(command, args, environment = process.env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env: environment, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} ${signal ? `被 ${signal} 终止` : `退出码 ${code ?? 1}`}`));
    });
  });
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const result = await launchInstalledTauriApp();
    console.log(`VaultMesh Tauri 已启动，Rust Native Host 已注册；扩展 ID：${result.extensionId}`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
