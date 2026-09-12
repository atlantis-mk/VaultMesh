import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(resolve(root, path), "utf8");
const json = (path) => JSON.parse(read(path));
const { transform } = createRequire(import.meta.url)("../webpack/manifest.js");

test("CT-BROWSER-PACKAGE-001 prototype metadata and both channel manifests use VaultMesh", () => {
  const pkg = json("package.json");
  assert.equal(pkg.name, "@vaultmesh/bitwarden-browser");
  assert.equal(pkg.private, true); assert.equal(pkg.license, "GPL-3.0");
  const before = process.env.CHANNEL;
  try {
    for (const channel of ["stable", "beta"]) for (const browser of ["chrome", "firefox"]) for (const file of ["src/manifest.json", "src/manifest.v3.json"]) {
      process.env.CHANNEL = channel;
      const manifest = JSON.parse(transform(browser)(Buffer.from(read(file))));
      const name = channel === "beta" ? "VaultMesh Beta" : "VaultMesh";
      assert.equal(manifest.short_name, name);
      assert.equal((manifest.action ?? manifest.browser_action).default_title, name);
      assert.equal(manifest.homepage_url, "https://github.com/atlantis-mk/VaultMesh");
      assert.equal(manifest.version, pkg.version.split("-")[0]);
      for (const path of Object.values(manifest.icons)) assert.ok(readFileSync(resolve(root, "src", path)).length);
    }
  } finally { if (before === undefined) delete process.env.CHANNEL; else process.env.CHANNEL = before; }
});

test("CT-BROWSER-PACKAGE-001 every locale exposes the new product without changing message keys", () => {
  for (const locale of readdirSync(resolve(root, "src/_locales"))) {
    const messages = json(`src/_locales/${locale}/messages.json`);
    assert.equal(messages.appName.message, "VaultMesh", locale);
    assert.equal(messages.extName.message, "VaultMesh", locale);
    assert.equal(messages.extNameBeta.message, "VaultMesh Beta", locale);
    assert.ok(messages.extDesc.message.length <= 112, locale);
    for (const key of ["appLogoLabel", "notificationAddDesc", "notificationChangeDesc", "bitwardenOverlayButton", "toggleBitwardenVaultOverlay"]) {
      if (messages[key]) assert.doesNotMatch(messages[key].message, /Bitwarden/, `${locale}:${key}`);
    }
  }
  const english = json("src/_locales/en/messages.json");
  assert.match(english.bitwardenAuthenticator.message, /Bitwarden Authenticator/);
  assert.match(english.bitwardenSecretsManager.message, /Bitwarden Secrets Manager/);
  assert.match(english.moreFromBitwarden.message, /Bitwarden/);
  assert.match(english.autofillIframeWarningTip.message, /\$HOSTNAME\$/);
});

test("CT-BROWSER-PACKAGE-001 toolbar artwork retains exact source assets and distinct states", () => {
  for (const size of [16, 32, 48, 128]) {
    assert.deepEqual(readFileSync(resolve(root, `src/images/icon${size}.png`)), readFileSync(resolve(root, `../browser-extension/public/icon-${size}.png`)));
  }
  for (const file of readdirSync(resolve(root, "src/images"))) {
    const match = /^icon(\d+)(.*)\.png$/.exec(file);
    if (!match || match[2].includes("safari")) continue;
    const png = readFileSync(resolve(root, "src/images", file));
    assert.equal(png.subarray(1, 4).toString(), "PNG");
    assert.equal(png.readUInt32BE(16), Number(match[1]), file);
    assert.equal(png.readUInt32BE(20), Number(match[1]), file);
  }
  for (const size of [19, 38]) {
    const normal = readFileSync(resolve(root, `src/images/icon${size}.png`));
    for (const suffix of ["gray", "locked", "beta"]) assert.notDeepEqual(normal, readFileSync(resolve(root, `src/images/icon${size}_${suffix}.png`)));
  }
});

test("CT-BROWSER-PACKAGE-001 popup and inline paths use bundled VaultMesh artwork", () => {
  for (const path of ["src/platform/popup/layout/popup-header.component.ts", "src/popup/components/extension-anon-layout-wrapper/extension-anon-layout-wrapper.component.ts", "src/autofill/popup/default-password-manager/default-password-manager-prompt.component.ts"]) {
    assert.match(read(path), /VaultMeshLogo/); assert.doesNotMatch(read(path), /BitwardenLogo/);
  }
  assert.match(read("src/autofill/utils/svg-icons.ts"), /logoIcon = vaultMeshIcon/);
  assert.match(read("src/autofill/content/components/icons/brand-icon-container.ts"), /unsafeSVG\(vaultMeshIcon\)/);
  assert.match(read("src/branding/vaultmesh-logo.ts"), /<title>VaultMesh<\/title>/);
  assert.doesNotMatch(read("src/branding/vaultmesh-logo.ts"), /\$\{/);
  assert.match(read("src/tools/popup/settings/about-dialog/about-dialog.component.html"), /bitDialogTitle>VaultMesh/);
  assert.match(read("src/tools/popup/settings/about-dialog/about-dialog.component.html"), /&copy; Bitwarden Inc\./);
  for (const path of ["src/popup/index.ejs", "src/autofill/notification/bar.html", "src/sidepanel-disabled.html"]) assert.match(read(path), /<title>VaultMesh<\/title>/);
});

test("CT-BROWSER-PACKAGE-001 upstream license and protocol identities are not rewritten as branding", () => {
  assert.match(read("LICENSE.txt"), /Bitwarden License/);
  assert.match(read("LICENSE_GPL.txt"), /GNU GENERAL PUBLIC LICENSE/);
  assert.equal(json("src/manifest.json").__firefox__browser_specific_settings.gecko.id, "{446900e4-71c2-419f-a6a7-df9c091e268b}");
  assert.match(read("VAULTMESH-FORK.md"), /not.*install/i);
});
