import assert from "node:assert/strict";
import test from "node:test";

import {
  parseRegistryDefaultValue,
  validateInstalledFirefoxManifest,
  validateInstalledManifest,
} from "./tauri-windows-browser-host-at.mjs";

test("Windows Browser AT parses the current-user Native Messaging manifest path", () => {
  assert.equal(
    parseRegistryDefaultValue(`
HKEY_CURRENT_USER\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.vaultmesh.browser
    (Default)    REG_SZ    C:\\Users\\tester\\AppData\\Roaming\\com.vaultmesh.desktop\\com.vaultmesh.browser.json
`),
    "C:\\Users\\tester\\AppData\\Roaming\\com.vaultmesh.desktop\\com.vaultmesh.browser.json",
  );
  assert.throws(() => parseRegistryDefaultValue("REG_SZ relative.json"));
});

test("Windows Browser AT requires one fixed Firefox extension and absolute Host", () => {
  const result = validateInstalledFirefoxManifest({
    name: "com.vaultmesh.browser",
    description: "VaultMesh",
    path: "C:\\Users\\tester\\AppData\\Local\\VaultMesh\\vaultmesh-native-host.exe",
    type: "stdio",
    allowed_extensions: ["vaultmesh@atlantis-mk.github.io"],
  }, "manifest.json");
  assert.equal(result.extensionId, "vaultmesh@atlantis-mk.github.io");
  assert.throws(() => validateInstalledFirefoxManifest({
    name: "com.vaultmesh.browser",
    path: "C:\\VaultMesh\\vaultmesh-native-host.exe",
    type: "stdio",
    allowed_extensions: ["other@example.test"],
  }, "manifest.json"));
});

test("Windows Browser AT requires one fixed extension origin and absolute Host", () => {
  const result = validateInstalledManifest({
    name: "com.vaultmesh.browser",
    description: "VaultMesh",
    path: "C:\\Users\\tester\\AppData\\Local\\VaultMesh\\vaultmesh-native-host.exe",
    type: "stdio",
    allowed_origins: ["chrome-extension://bdneegbnjbheblmamalplnddbodcghbg/"],
  }, "manifest.json");
  assert.equal(result.extensionId, "bdneegbnjbheblmamalplnddbodcghbg");
  assert.throws(() => validateInstalledManifest({
    name: "com.vaultmesh.browser",
    path: "relative.exe",
    type: "stdio",
    allowed_origins: ["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"],
  }, "manifest.json"));
  assert.throws(() => validateInstalledManifest({
    name: "com.vaultmesh.browser",
    path: "C:\\VaultMesh\\vaultmesh-native-host.exe",
    type: "stdio",
    allowed_origins: [
      "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
      "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/",
    ],
  }, "manifest.json"));
});
