import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  androidReleaseAbis,
  androidReleaseAssetNames,
  androidVersionCode,
  expectedVariantVersionCode,
  parseBadging,
  parseSignerDigests,
  requireSigningEnvironment,
  validateApkEntries,
} from "./build-android-release.mjs";

const workspace = new URL("../", import.meta.url);

test("Android versionCode increases across review iterations and stable", () => {
  assert.equal(androidVersionCode("0.0.10-review"), 10000);
  assert.equal(androidVersionCode("0.0.10-review.2"), 10020);
  assert.equal(androidVersionCode("0.0.10"), 10990);
  assert.equal(androidVersionCode("0.1.0-review"), 100000);
  assert.ok(androidVersionCode("0.0.10") < androidVersionCode("0.0.11-review"));
  assert.ok(androidVersionCode("20.99.99") + 3 <= 2_100_000_000);
  assert.throws(() => androidVersionCode("21.0.0"), /major≤20/);
  assert.throws(() => androidVersionCode("0.0.1-review.99"), /98/);
  assert.throws(() => androidVersionCode("0.0.1-rc.1"), /Android 发布版本/);
});

test("each ABI APK gets a distinct versionCode above universal", () => {
  const base = androidVersionCode("0.0.10-review");
  assert.equal(expectedVariantVersionCode(base, "universal"), base);
  assert.deepEqual(androidReleaseAbis.map((abi) => expectedVariantVersionCode(base, abi)), [base + 1, base + 2, base + 3]);
  assert.throws(() => expectedVariantVersionCode(base, "x86"), /未知 Android ABI/);
});

test("Android asset names cover universal and every release ABI", () => {
  assert.deepEqual(androidReleaseAssetNames("0.0.10-review"), {
    universal: "VaultMesh_0.0.10-review_android-universal.apk",
    "armeabi-v7a": "VaultMesh_0.0.10-review_android-armeabi-v7a.apk",
    "arm64-v8a": "VaultMesh_0.0.10-review_android-arm64-v8a.apk",
    x86_64: "VaultMesh_0.0.10-review_android-x86_64.apk",
  });
});

test("APK entries must contain exactly the expected JNI ABIs", () => {
  const lib = (abi) => `lib/${abi}/libvaultmesh_android_runtime.so`;
  validateApkEntries(["AndroidManifest.xml", lib("arm64-v8a")], "arm64-v8a");
  validateApkEntries(["AndroidManifest.xml", ...androidReleaseAbis.map(lib)], "universal");
  assert.throws(() => validateApkEntries(["AndroidManifest.xml"], "x86_64"), /缺少 x86_64/);
  assert.throws(() => validateApkEntries([lib("arm64-v8a"), lib("x86_64")], "arm64-v8a"), /意外 ABI：x86_64/);
  assert.throws(() => validateApkEntries([lib("armeabi-v7a"), lib("arm64-v8a")], "universal"), /缺少 x86_64/);
  assert.throws(() => validateApkEntries([lib("x86_64"), "../evil"], "x86_64"), /不安全路径/);
});

test("APK badging and signer output are parsed strictly", () => {
  assert.deepEqual(
    parseBadging("package: name='com.vaultmesh.app' versionCode='10002' versionName='0.0.10-review' platformBuildVersionName='17'\n"),
    { applicationId: "com.vaultmesh.app", versionCode: 10002, versionName: "0.0.10-review" },
  );
  assert.throws(() => parseBadging("nothing"), /包信息/);
  const digest = "a".repeat(64);
  assert.deepEqual(parseSignerDigests(`Signer #1 certificate SHA-256 digest: ${digest}\n`), [digest]);
});

test("release builds require complete signing configuration", () => {
  assert.throws(() => requireSigningEnvironment({ VAULTMESH_ANDROID_KEYSTORE_PATH: "/k.jks" }), /KEYSTORE_PASSWORD/);
  requireSigningEnvironment({
    VAULTMESH_ANDROID_KEYSTORE_PATH: "/k.jks",
    VAULTMESH_ANDROID_KEYSTORE_PASSWORD: "x",
    VAULTMESH_ANDROID_KEY_ALIAS: "x",
    VAULTMESH_ANDROID_KEY_PASSWORD: "x",
  });
});

test("Gradle splits and Rust release ABIs stay aligned with the release script", async () => {
  const gradle = await readFile(new URL("apps/android/app/build.gradle.kts", workspace), "utf8");
  const rust = await readFile(new URL("apps/android/scripts/build-rust.sh", workspace), "utf8");
  assert.match(gradle, new RegExp(`releaseAbis = listOf\\(${androidReleaseAbis.map((abi) => `"${abi}"`).join(", ")}\\)`));
  assert.match(gradle, /isUniversalApk = true/);
  assert.match(gradle, /isEnable = abiSplitsEnabled/);
  assert.match(gradle, /VAULTMESH_ANDROID_KEYSTORE_PATH/);
  assert.match(rust, new RegExp(`default_abis="${androidReleaseAbis.join(" ")}"`));
});
