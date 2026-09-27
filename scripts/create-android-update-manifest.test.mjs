import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { androidReleaseAssetNames } from "./build-android-release.mjs";
import { assertAndroidChannelAdvance, createAndroidUpdateManifest } from "./create-android-update-manifest.mjs";

const workspace = new URL("../", import.meta.url);
const signer = "9C:42:0D:BF:96:8F:96:45:6A:44:91:34:E1:04:92:65:D8:41:95:AC:5F:9D:79:8D:07:E4:B6:1B:B6:D4:76:61";

async function fixture(version) {
  const directory = await mkdtemp(path.join(tmpdir(), "vaultmesh-android-update-"));
  for (const [variant, name] of Object.entries(androidReleaseAssetNames(version))) {
    await writeFile(path.join(directory, name), `apk-${variant}`);
  }
  return directory;
}

const create = async (version, extra = {}) => createAndroidUpdateManifest({
  inputDirectory: await fixture(version),
  version,
  baseUrl: "https://downloads.example.test/",
  notes: "notes",
  signerSha256: signer,
  pubDate: "2026-09-27T00:00:00.000Z",
  ...extra,
});

test("CT-ANDROID-UPDATE-001: manifest lists every APK with immutable URL, digest and size", async () => {
  const manifest = await create("0.1.0-review");
  assert.equal(manifest.schema, 1);
  assert.equal(manifest.versionCode, 100000);
  assert.equal(manifest.signer_sha256, "9c420dbf968f96456a449134e1049265d84195ac5f9d798d07e4b61bb6d47661");
  assert.deepEqual(Object.keys(manifest.assets), ["universal", "armeabi-v7a", "arm64-v8a", "x86_64"]);
  assert.equal(manifest.assets["arm64-v8a"].url,
    "https://downloads.example.test/releases/v0.1.0-review/VaultMesh_0.1.0-review_android-arm64-v8a.apk");
  assert.equal(manifest.assets["arm64-v8a"].size, "apk-arm64-v8a".length);
  assert.match(manifest.assets.universal.sha256, /^[0-9a-f]{64}$/);
});

test("CT-ANDROID-UPDATE-001: base URL, signer and missing assets fail closed", async () => {
  await assert.rejects(create("0.1.0-review", { baseUrl: "http://downloads.example.test" }), /HTTPS/);
  await assert.rejects(create("0.1.0-review", { baseUrl: "https://user:pw@downloads.example.test" }), /HTTPS/);
  await assert.rejects(create("0.1.0-review", { signerSha256: "abc" }), /SHA-256/);
  await assert.rejects(createAndroidUpdateManifest({
    inputDirectory: await fixture("0.0.9-review"), version: "0.1.0-review",
    baseUrl: "https://downloads.example.test", signerSha256: signer,
  }), /ENOENT/);
});

test("CT-ANDROID-UPDATE-001: channel advances strictly or republishes identical assets", async () => {
  const current = await create("0.1.0-review");
  const next = await create("0.1.1-review");
  assertAndroidChannelAdvance(undefined, current);
  assertAndroidChannelAdvance(current, next);
  assertAndroidChannelAdvance(current, { ...current, pub_date: "2026-09-28T00:00:00.000Z" });
  assert.throws(() => assertAndroidChannelAdvance(current, { ...current, assets: {
    ...current.assets, universal: { ...current.assets.universal, sha256: "0".repeat(64) },
  } }), /完全相同/);
  assert.throws(() => assertAndroidChannelAdvance(next, current), /回退/);
  assert.throws(() => assertAndroidChannelAdvance({ schema: 2, versionCode: 1 }, current), /格式无效/);
});

test("CT-ANDROID-UPDATE-001: workflow publishes android.json after APK checks and before latest.json", async () => {
  const workflow = await readFile(new URL(".github/workflows/r2-review-release.yml", workspace), "utf8");
  const generate = workflow.indexOf("node scripts/create-android-update-manifest.mjs");
  const apkCheck = workflow.indexOf('cmp "$RUNNER_TEMP/vaultmesh-android/$asset" "$published"');
  const publishManifests = workflow.indexOf("for manifest in android latest; do");
  assert.ok(generate > 0 && apkCheck > 0 && publishManifests > 0);
  assert.ok(generate < apkCheck && apkCheck < publishManifests);
  assert.match(workflow.slice(publishManifests),
    /"s3:\/\/\$\{R2_BUCKET\}\/channels\/review\/\$\{manifest\}\.json"[\s\S]*--cache-control "no-store, max-age=0"[\s\S]*cmp "\$source" "\$downloaded"/);
  assert.match(workflow, /--signer-sha256 "\$ANDROID_SIGNER_SHA256"/);
});
