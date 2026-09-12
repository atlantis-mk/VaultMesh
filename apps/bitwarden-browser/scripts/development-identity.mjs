import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

export const developmentIdentity = JSON.parse(await readFile(new URL("../development-identity.json", import.meta.url), "utf8"));
export function verifyDevelopmentIdentity(manifest) {
  const identity = developmentIdentity;
  const id = [...createHash("sha256").update(Buffer.from(identity.key, "base64")).digest().subarray(0, 16)]
    .map((byte) => String.fromCharCode(97 + (byte >> 4), 97 + (byte & 15))).join("");
  if (id !== identity.extensionId) throw new Error("开发身份 key 与 ID 不匹配。");
  if (manifest.browser_specific_settings?.gecko) {
    if (manifest.browser_specific_settings.gecko.id !== identity.firefoxId || manifest.key) throw new Error("Firefox 开发身份不匹配。");
  } else if (manifest.key !== identity.key) throw new Error("Chromium 开发身份不匹配。");
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  verifyDevelopmentIdentity(JSON.parse(await readFile(new URL("../build/manifest.json", import.meta.url), "utf8")));
  console.log("独立开发身份已验证；未修改 manifest 或现有插件身份。");
}
