import assert from "node:assert/strict";
import test from "node:test";

import { developmentExtensionKey, firefoxExtensionId } from "./browser-identity.mjs";
import {
  extensionReleaseAssetNames,
  validateExtensionArchiveEntries,
  validateExtensionManifest,
} from "./build-browser-extension-release.mjs";

test("creates stable Chrome and Firefox Review asset names", () => {
  assert.deepEqual(extensionReleaseAssetNames("0.0.10-review"), {
    chrome: "VaultMesh_0.0.10-review_chrome-extension.zip",
    firefox: "VaultMesh_0.0.10-review_firefox-extension.zip",
  });
  assert.throws(() => extensionReleaseAssetNames("0.0.4"), /Review SemVer/);
});

test("accepts browser-specific manifests and rejects identity or permission drift", () => {
  const productVersion = "0.0.10-review";
  const common = { version: "0.0.10", permissions: ["nativeMessaging", "storage"] };
  validateExtensionManifest({
    ...common,
    manifest_version: 3,
    key: developmentExtensionKey,
    minimum_chrome_version: "127",
    version_name: productVersion,
    permissions: [...common.permissions, "webAuthenticationProxy"],
  }, { target: "chrome", version: productVersion, chromeExtensionKey: developmentExtensionKey });
  validateExtensionManifest({
    ...common,
    manifest_version: 2,
    browser_specific_settings: { gecko: { id: firefoxExtensionId, data_collection_permissions: { required: ["none"] } } },
  }, { target: "firefox", version: productVersion, chromeExtensionKey: developmentExtensionKey });
  assert.throws(() => validateExtensionManifest({
    ...common,
    manifest_version: 2,
    browser_specific_settings: { gecko: { id: "other@example.test", data_collection_permissions: { required: ["none"] } } },
  }, { target: "firefox", version: productVersion, chromeExtensionKey: developmentExtensionKey }), /Firefox extension manifest/);
});

test("extension ZIP entries reject traversal, source maps and environment files", () => {
  validateExtensionArchiveEntries(["manifest.json", "background.js", "popup.html"]);
  assert.throws(() => validateExtensionArchiveEntries(["manifest.json", "../secret"]), /不安全路径/);
  assert.throws(() => validateExtensionArchiveEntries(["manifest.json", "background.js.map"]), /禁止发布文件/);
  assert.throws(() => validateExtensionArchiveEntries(["manifest.json", ".env.release"]), /禁止发布文件/);
});
