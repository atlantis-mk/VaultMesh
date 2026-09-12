import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { nativeHostPlan } from "./native-host.mjs";
import { developmentIdentity as identity, verifyDevelopmentIdentity } from "./development-identity.mjs";
const require = createRequire(import.meta.url);
const { transform } = require("../webpack/manifest.js");

for (const browser of ["chrome", "edge", "firefox"]) test(`CT-BROWSER-PACKAGE-001 ${browser} has an independent fixed identity`, async () => {
  const source = await readFile(new URL(browser === "firefox" ? "../src/manifest.json" : "../src/manifest.v3.json", import.meta.url));
  const manifest = JSON.parse(transform(browser)(source));
  verifyDevelopmentIdentity(manifest);
  assert.deepEqual(manifest.content_scripts.map((script) => script.js), [["content/vaultmesh-native-fill.js"]]);
  assert.deepEqual(manifest.optional_permissions, ["nativeMessaging"]);
  assert.ok(manifest.permissions.includes("idle"));
  for (const permission of ["webRequest", "webRequestBlocking", "identity", "offscreen", "contextMenus"]) assert.ok(!manifest.permissions.includes(permission));
  if (browser === "firefox") {
    assert.equal(manifest.minimum_chrome_version, undefined);
    assert.ok(!manifest.permissions.includes("webAuthenticationProxy"));
  } else {
    assert.ok(manifest.permissions.includes("webAuthenticationProxy"));
    assert.equal(manifest.minimum_chrome_version, "127");
  }
});
test("runtime entrypoints do not bootstrap cloud/account/Vault services", async () => {
  const background = await readFile(new URL("../src/platform/background.ts", import.meta.url), "utf8");
  const popup = await readFile(new URL("../src/popup/main.ts", import.meta.url), "utf8");
  assert.ok(!background.includes("new MainBackground"));
  assert.ok(background.includes("new AutofillScriptGenerator()"));
  assert.ok(!popup.includes("bootstrapModule(AppModule"));
  assert.ok(popup.includes("bootstrapApplication(VaultMeshPopupComponent"));
  assert.ok(popup.includes("useClass: PopupLocationStrategy"));
});
for (const platform of ["darwin", "win32"]) test(`CT-BROWSER-001 ${platform} development host plan never broadens existing registration`, () => {
  const plan = nativeHostPlan({ platform, userHome: platform === "darwin" ? "/Users/synthetic" : "C:\\Users\\synthetic", appData: "C:\\Users\\synthetic\\AppData\\Roaming", temporaryDirectory: "/tmp", nativeHostPath: platform === "darwin" ? "/workspace/target/debug/vaultmesh-bitwarden-dev-host" : "C:\\workspace\\target\\debug\\vaultmesh-bitwarden-dev-host.exe" });
  for (const file of plan.files) {
    assert.ok(!file.path.endsWith("/com.vaultmesh.browser.json"));
    assert.ok(!file.path.endsWith("browser-host-config.json"));
    if (file.value.allowed_origins) assert.deepEqual(file.value.allowed_origins, [`chrome-extension://${identity.extensionId}/`]);
    if (file.value.allowed_extensions) assert.deepEqual(file.value.allowed_extensions, [identity.firefoxId]);
  }
  assert.equal(plan.files[0].value.keychainService, "com.vaultmesh.desktop.bitwarden-dev-pairing");
  assert.ok(plan.registry.every((entry) => entry.key.endsWith(identity.hostName)));
});
test("rejects generic or relative Native Host paths", () => {
  for (const nativeHostPath of ["./vaultmesh-bitwarden-dev-host", "/workspace/vaultmesh-native-host"]) assert.throws(() => nativeHostPlan({ platform: "darwin", nativeHostPath }));
});
