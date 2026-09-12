import { access, mkdir, rename, writeFile, lstat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { developmentIdentity as identity } from "./development-identity.mjs";

const workspace = fileURLToPath(new URL("../../../", import.meta.url));
export function nativeHostPlan({ platform = process.platform, userHome = homedir(), temporaryDirectory = tmpdir(), appData = process.env.APPDATA, nativeHostPath } = {}) {
  if (!["darwin", "win32"].includes(platform)) throw new Error("开发 Native Host 仅支持 macOS/Windows。");
  const paths = platform === "win32" ? path.win32 : path.posix;
  const root = paths.join(platform === "win32" ? (appData ?? paths.join(userHome, "AppData", "Roaming")) : paths.join(userHome, "Library", "Application Support"), "com.vaultmesh.desktop");
  nativeHostPath ??= paths.join(workspace, "target", "debug", `vaultmesh-bitwarden-dev-host${platform === "win32" ? ".exe" : ""}`);
  if (!paths.isAbsolute(nativeHostPath) || paths.basename(nativeHostPath) !== `vaultmesh-bitwarden-dev-host${platform === "win32" ? ".exe" : ""}`) throw new Error("必须选择专用 debug Native Host 的绝对路径。");
  const filename = `${identity.hostName}.json`;
  const chromiumPaths = platform === "win32" ? [paths.join(root, filename)] : ["Google/Chrome", "Microsoft Edge"].map((browser) => paths.join(userHome, "Library", "Application Support", browser, "NativeMessagingHosts", filename));
  const firefoxPath = platform === "win32" ? paths.join(root, `${identity.hostName}.firefox.json`) : paths.join(userHome, "Library", "Application Support", "Mozilla", "NativeMessagingHosts", filename);
  const brokerSocket = paths.join(temporaryDirectory, "vaultmesh-bitwarden-dev.sock");
  if (platform === "darwin" && Buffer.byteLength(brokerSocket) > 103) throw new Error("开发 socket 路径过长。");
  const config = { version: 2, ...(platform === "win32" ? { brokerPipe: "\\\\.\\pipe\\VaultMesh.BitwardenDevelopment.v2" } : { brokerSocket }),
    keychainService: "com.vaultmesh.desktop.bitwarden-dev-pairing", keychainAccount: "native-host-hmac-v1",
    chromiumAllowedOrigin: `chrome-extension://${identity.extensionId}/`, firefoxExtensionId: identity.firefoxId, firefoxManifestPath: firefoxPath };
  const base = { name: identity.hostName, description: "VaultMesh independent Bitwarden development host", path: nativeHostPath, type: "stdio" };
  return { nativeHostPath, files: [
    { path: paths.join(root, "bitwarden-dev-host-config.json"), value: config },
    ...chromiumPaths.map((filePath) => ({ path: filePath, value: { ...base, allowed_origins: [config.chromiumAllowedOrigin] } })),
    { path: firefoxPath, value: { ...base, allowed_extensions: [identity.firefoxId] } },
  ], registry: platform === "win32" ? [
    ...["Google\\Chrome", "Microsoft\\Edge"].map((browser) => ({ key: `HKCU\\Software\\${browser}\\NativeMessagingHosts\\${identity.hostName}`, value: chromiumPaths[0] })),
    { key: `HKCU\\Software\\Mozilla\\NativeMessagingHosts\\${identity.hostName}`, value: firefoxPath },
  ] : [] };
}

export async function installNativeHost(plan) {
  await access(plan.nativeHostPath);
  for (const file of plan.files) {
    await mkdir(path.dirname(file.path), { recursive: true });
    const existing = await lstat(file.path).catch((error) => { if (error.code !== "ENOENT") throw error; return null; });
    if (existing && !existing.isFile()) throw new Error("拒绝替换非普通 Host 文件。");
    const temporary = `${file.path}.${process.pid}.tmp`;
    await writeFile(temporary, JSON.stringify(file.value, null, 2), { mode: 0o600, flag: "wx" });
    await rename(temporary, file.path);
  }
  for (const entry of plan.registry) execFileSync("reg.exe", ["add", entry.key, "/ve", "/t", "REG_SZ", "/d", entry.value, "/f"], { stdio: "ignore" });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const plan = nativeHostPlan();
  if (process.argv.includes("--install")) {
    await installNativeHost(plan);
    console.log("已注册独立开发 Host；未修改既有 VaultMesh Host、凭据或授权。使用 VAULTMESH_BITWARDEN_DEVELOPMENT=1 启动 Tauri debug runtime。");
  } else console.log(JSON.stringify(plan, null, 2));
}
