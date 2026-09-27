import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import { androidReleaseAssetNames, androidReleaseVariants, androidVersionCode } from "./build-android-release.mjs";

export const androidUpdateManifestSchema = 1;

function normalizeBaseUrl(baseUrl) {
  const url = new URL(baseUrl);
  if (url.protocol !== "https:" || url.search || url.hash || url.username || url.password) {
    throw new Error("Android 更新清单 base URL 必须是无凭据、无查询的 HTTPS 地址。");
  }
  return url.href.replace(/\/+$/, "");
}

function normalizeDigest(value) {
  const digest = (value ?? "").toLowerCase().replaceAll(":", "");
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error("签名证书 SHA-256 无效。");
  return digest;
}

function sameAssets(left, right) {
  return androidReleaseVariants.every((variant) => left?.[variant]?.sha256 === right?.[variant]?.sha256
    && left?.[variant]?.url === right?.[variant]?.url);
}

// 当前 channel 只允许严格前进；同版本仅在资产完全相同时允许失败后重发。
export function assertAndroidChannelAdvance(current, next) {
  if (!current) return;
  if (current.schema !== androidUpdateManifestSchema || !Number.isSafeInteger(current.versionCode)) {
    throw new Error("当前 Android 更新清单格式无效。");
  }
  if (next.versionCode < current.versionCode) throw new Error("Android 更新清单 versionCode 不得回退。");
  if (next.versionCode === current.versionCode
    && (next.version !== current.version || !sameAssets(current.assets, next.assets))) {
    throw new Error("同版本 Android 更新清单只能以完全相同的资产重发。");
  }
}

async function sha256File(file) {
  return createHash("sha256").update(await readFile(file)).digest("hex");
}

export async function createAndroidUpdateManifest({
  inputDirectory, version, baseUrl, notes = "", signerSha256, pubDate = new Date().toISOString(), current,
}) {
  if (typeof notes !== "string" || notes.length > 4_000) throw new Error("更新说明无效或过长。");
  if (Number.isNaN(Date.parse(pubDate))) throw new Error("pub_date 必须是 RFC 3339 时间。");
  const base = normalizeBaseUrl(baseUrl);
  const names = androidReleaseAssetNames(version);
  const assets = {};
  for (const variant of androidReleaseVariants) {
    const file = path.join(inputDirectory, names[variant]);
    const { size } = await stat(file);
    if (size <= 0) throw new Error(`Android 资产为空：${names[variant]}`);
    assets[variant] = {
      url: `${base}/releases/v${version}/${names[variant]}`,
      sha256: await sha256File(file),
      size,
    };
  }
  const manifest = {
    schema: androidUpdateManifestSchema,
    version,
    versionCode: androidVersionCode(version),
    notes,
    pub_date: pubDate,
    signer_sha256: normalizeDigest(signerSha256),
    assets,
  };
  assertAndroidChannelAdvance(current, manifest);
  return manifest;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const names = {
      "--input": "inputDirectory", "--output": "output", "--version": "version", "--base-url": "baseUrl",
      "--notes": "notes", "--signer-sha256": "signerSha256", "--current": "current",
    };
    const options = {};
    const args = process.argv.slice(2);
    for (let index = 0; index < args.length; index += 2) {
      const key = names[args[index]];
      if (!key || args[index + 1] === undefined) throw new Error(`未知或缺少值的参数：${args[index]}`);
      options[key] = args[index + 1];
    }
    for (const required of ["inputDirectory", "output", "version", "baseUrl", "signerSha256"]) {
      if (!options[required]) throw new Error(`缺少参数：${required}`);
    }
    const current = options.current ? JSON.parse(await readFile(options.current, "utf8")) : undefined;
    const manifest = await createAndroidUpdateManifest({ ...options, current });
    await writeFile(options.output, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`已生成 Android 更新清单：${manifest.version}（versionCode ${manifest.versionCode}）`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
