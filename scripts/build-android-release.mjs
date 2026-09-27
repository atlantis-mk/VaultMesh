import { execFile } from "node:child_process";
import { copyFile, mkdir, readFile, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const workspace = path.resolve(import.meta.dirname, "..");
const androidRoot = path.join(workspace, "apps", "android");
const apkOutput = path.join(androidRoot, "app", "build", "outputs", "apk", "release");
const nativeLibrary = "libvaultmesh_android_runtime.so";

// 顺序与 build.gradle.kts 的 releaseAbis 一致，决定 versionCode 个位。
export const androidReleaseAbis = ["armeabi-v7a", "arm64-v8a", "x86_64"];
export const androidReleaseVariants = ["universal", ...androidReleaseAbis];
const signingVariables = [
  "VAULTMESH_ANDROID_KEYSTORE_PATH",
  "VAULTMESH_ANDROID_KEYSTORE_PASSWORD",
  "VAULTMESH_ANDROID_KEY_ALIAS",
  "VAULTMESH_ANDROID_KEY_PASSWORD",
];

function parseReleaseVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-review(?:\.(\d+))?)?$/.exec(version ?? "");
  if (!match) throw new Error("Android 发布版本必须是 <major>.<minor>.<patch>[-review[.<n>]]。");
  const [major, minor, patch] = match.slice(1, 4).map(Number);
  const review = version.includes("-review") ? Number(match[4] ?? 0) : null;
  return { major, minor, patch, review };
}

// versionCode = (((major*100 + minor)*100 + patch)*100 + stage)*10 + ABI 位；
// Review 阶段为 0..98 并低于同版本 Stable 的 99，保证侧载升级单调。
export function androidVersionCode(version) {
  const { major, minor, patch, review } = parseReleaseVersion(version);
  if (major > 20 || minor > 99 || patch > 99) {
    throw new Error("Android versionCode 仅支持 major≤20、minor≤99、patch≤99。");
  }
  if (review !== null && review > 98) throw new Error("Review 迭代号不得超过 98。");
  const stage = review ?? 99;
  return (((major * 100 + minor) * 100 + patch) * 100 + stage) * 10;
}

export function androidReleaseAssetNames(version) {
  parseReleaseVersion(version);
  return Object.fromEntries(androidReleaseVariants.map((variant) => [
    variant,
    `VaultMesh_${version}_android-${variant}.apk`,
  ]));
}

export function expectedVariantVersionCode(baseVersionCode, variant) {
  if (variant === "universal") return baseVersionCode;
  const index = androidReleaseAbis.indexOf(variant);
  if (index === -1) throw new Error(`未知 Android ABI：${variant}`);
  return baseVersionCode + index + 1;
}

export function validateApkEntries(entries, variant) {
  const expected = variant === "universal" ? androidReleaseAbis : [variant];
  const libraries = entries.filter((entry) => entry.startsWith("lib/"));
  const abis = new Set(libraries.map((entry) => entry.split("/")[1]));
  for (const abi of expected) {
    if (!entries.includes(`lib/${abi}/${nativeLibrary}`)) {
      throw new Error(`${variant} APK 缺少 ${abi} JNI runtime。`);
    }
  }
  for (const abi of abis) {
    if (!expected.includes(abi)) throw new Error(`${variant} APK 包含意外 ABI：${abi}`);
  }
  for (const entry of entries) {
    if (entry.startsWith("/") || entry.split("/").includes("..")) {
      throw new Error(`${variant} APK 包含不安全路径：${entry}`);
    }
  }
}

export function parseBadging(output) {
  const match = /^package: name='([^']+)' versionCode='(\d+)' versionName='([^']*)'/m.exec(output);
  if (!match) throw new Error("无法读取 APK 包信息。");
  return { applicationId: match[1], versionCode: Number(match[2]), versionName: match[3] };
}

export function parseSignerDigests(output) {
  return [...output.matchAll(/certificate SHA-256 digest: ([0-9a-f]{64})/g)].map((match) => match[1]);
}

export function requireSigningEnvironment(environment) {
  const missing = signingVariables.filter((name) => !environment[name]);
  if (missing.length > 0) throw new Error(`缺少 Android 签名配置：${missing.join(", ")}`);
}

async function latestBuildTool(environment, tool) {
  const sdk = environment.ANDROID_HOME ?? environment.ANDROID_SDK_ROOT;
  if (!sdk) throw new Error("ANDROID_HOME 未设置。");
  const buildTools = path.join(sdk, "build-tools");
  const versions = (await readdir(buildTools))
    .filter((entry) => /^\d+\.\d+\.\d+$/.test(entry))
    .sort((left, right) => left.localeCompare(right, undefined, { numeric: true }));
  if (versions.length === 0) throw new Error("Android SDK 缺少 build-tools。");
  return path.join(buildTools, versions.at(-1), tool);
}

async function run(command, args, options = {}) {
  const { stdout } = await execFileAsync(command, args, { maxBuffer: 16 * 1024 * 1024, ...options });
  return stdout;
}

export async function buildAndroidRelease({ outputDirectory, allowUnsigned = false, environment = process.env } = {}) {
  const version = JSON.parse(await readFile(path.join(workspace, "package.json"), "utf8")).version;
  const names = androidReleaseAssetNames(version);
  const baseVersionCode = androidVersionCode(version);
  if (!allowUnsigned) requireSigningEnvironment(environment);
  const destination = outputDirectory ?? path.join(workspace, "artifacts", "android");

  await rm(apkOutput, { recursive: true, force: true });
  await run(path.join(androidRoot, "gradlew"), [
    "-p", androidRoot,
    "assembleRelease",
    `-Pvaultmesh.versionName=${version}`,
    `-Pvaultmesh.versionCode=${baseVersionCode}`,
    "-Pvaultmesh.abiSplits=true",
  ], { env: environment, cwd: workspace });

  const aapt2 = await latestBuildTool(environment, "aapt2");
  const apksigner = await latestBuildTool(environment, "apksigner");
  const pinnedDigest = environment.VAULTMESH_ANDROID_CERT_SHA256?.toLowerCase().replaceAll(":", "");
  const outputs = {};
  let signerDigest = null;
  await mkdir(destination, { recursive: true });
  for (const variant of androidReleaseVariants) {
    const suffix = allowUnsigned && !environment.VAULTMESH_ANDROID_KEYSTORE_PATH ? "-unsigned" : "";
    const apk = path.join(apkOutput, `app-${variant}-release${suffix}.apk`);
    validateApkEntries((await run("unzip", ["-Z1", apk])).split(/\r?\n/).filter(Boolean), variant);
    const badging = parseBadging(await run(aapt2, ["dump", "badging", apk]));
    const expectedCode = expectedVariantVersionCode(baseVersionCode, variant);
    if (badging.applicationId !== "com.vaultmesh.app"
      || badging.versionName !== version
      || badging.versionCode !== expectedCode) {
      throw new Error(`${variant} APK 身份或版本不一致：${JSON.stringify(badging)}`);
    }
    if (!suffix) {
      const digests = parseSignerDigests(await run(apksigner, ["verify", "--print-certs", apk]));
      if (digests.length !== 1) throw new Error(`${variant} APK 必须恰好有一个签名证书。`);
      if (signerDigest && digests[0] !== signerDigest) throw new Error("各 ABI APK 签名证书不一致。");
      if (pinnedDigest && digests[0] !== pinnedDigest) throw new Error("APK 签名证书与固定指纹不一致。");
      signerDigest = digests[0];
    }
    outputs[variant] = path.join(destination, names[variant]);
    await copyFile(apk, outputs[variant]);
  }
  return { version, baseVersionCode, signerDigest, outputs };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const args = process.argv.slice(2);
    const outputIndex = args.indexOf("--output");
    const outputDirectory = outputIndex === -1 ? undefined : args[outputIndex + 1];
    const allowUnsigned = args.includes("--allow-unsigned");
    const known = new Set(["--allow-unsigned", "--output"]);
    if (args.some((argument, index) => !known.has(argument) && args[index - 1] !== "--output")
      || (outputIndex !== -1 && !outputDirectory)) {
      throw new Error("用法：build-android-release.mjs [--output <directory>] [--allow-unsigned]");
    }
    const result = await buildAndroidRelease({ outputDirectory, allowUnsigned });
    console.log(`已生成 Android ${result.version} APK（versionCode ${result.baseVersionCode}）：${androidReleaseVariants.join(", ")}`);
    if (result.signerDigest) console.log(`签名证书 SHA-256：${result.signerDigest}`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
