import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspace = new URL("../", import.meta.url);
const expectedVersion = "0.0.10-review";

async function json(relativePath) {
  return JSON.parse(await readFile(new URL(relativePath, workspace), "utf8"));
}

test("Review product manifests use one prerelease version", async () => {
  for (const relativePath of [
    "package.json",
    "apps/tauri-desktop/package.json",
    "apps/browser-extension/package.json",
    "packages/ssh-command-parser/package.json",
    "apps/tauri-desktop/src-tauri/tauri.conf.json",
  ]) {
    assert.equal((await json(relativePath)).version, expectedVersion, relativePath);
  }

  const cargoManifest = await readFile(new URL("Cargo.toml", workspace), "utf8");
  assert.match(cargoManifest, new RegExp(`^version = "${expectedVersion.replaceAll(".", "\\.")}"$`, "m"));
});

test("Review publication is isolated from the existing test channel", async () => {
  const workflow = await readFile(new URL(".github/workflows/r2-review-release.yml", workspace), "utf8");
  assert.match(workflow, /name: Publish R2 review release/);
  assert.match(workflow, /default: "0\.0\.10-review"/);
  assert.equal(workflow.match(/uses: pnpm\/action-setup@v6/g)?.length, 2);
  assert.doesNotMatch(workflow, /pnpm\/action-setup@v6\n\s+with:\n\s+version:/);
  assert.match(workflow, /channels\/review\/latest\.json/);
  assert.doesNotMatch(workflow, /channels\/test\/latest\.json/);
  assert.match(workflow, /Review version matches source metadata/);
  assert.match(workflow, /process\.env\.REVIEW_VERSION !== sourceVersion/);
  assert.match(workflow, /--updater-version "\$\{\{ inputs\.version \}\}"/);
  assert.match(workflow, /Build signed updater artifact and unsigned review installer[\s\S]*?--release-identity/);
  assert.match(workflow, /Publish immutable artifacts then review channel/);
  assert.match(workflow, /runner: macos-15\n\s+target: aarch64-apple-darwin/);
  assert.match(workflow, /runner: macos-15-intel\n\s+target: x86_64-apple-darwin/);
  assert.match(workflow, /runner: windows-2025\n\s+target: x86_64-pc-windows-msvc/);
  assert.match(workflow, /platform_key: windows-x86_64[\s\S]*?bundles: nsis,msi/);
  assert.match(workflow, /strategy:\n\s+fail-fast: false/);
  assert.match(workflow, /Verify GitHub-hosted runner matches target architecture/);
  const extensionJob = workflow.match(/\n  extension:[\s\S]*?\n  build:/)?.[0] ?? "";
  const buildJob = workflow.match(/\n  build:[\s\S]*?\n  publish:/)?.[0] ?? "";
  assert.doesNotMatch(extensionJob, /actions\/cache@v5/);
  assert.match(buildJob, /name: Compute Rust dependency cache key[\s\S]*rust-dependency-cache-key\.mjs --github-output/);
  assert.match(buildJob, /name: Restore Cargo downloads and dependency objects[\s\S]*uses: actions\/cache@v5/);
  assert.equal(workflow.match(/uses: actions\/cache@v5/g)?.length, 1);
  assert.match(workflow, /vaultmesh-cargo-deps-v2-\$\{\{ runner\.os \}\}-\$\{\{ runner\.arch \}\}-\$\{\{ matrix\.target \}\}-\$\{\{ steps\.cargo-cache-key\.outputs\.hash \}\}/);
  assert.match(buildJob, /name: Remove workspace release objects before saving dependency cache[\s\S]*cargo clean --release --target/);
  assert.ok(buildJob.indexOf("uses: actions/upload-artifact@v7") < buildJob.indexOf("name: Remove workspace release objects before saving dependency cache"));
  assert.doesNotMatch(workflow, /vaultmesh-cargo-v1-|hashFiles\(|sccache/);
  assert.match(workflow, /publish:\n\s+name: Publish immutable artifacts then review channel\n\s+needs: \[build, extension\]\n\s+if: \$\{\{ always\(\) && !cancelled\(\) \}\}/);
  assert.match(workflow, /name: Require successful platform and extension builds[\s\S]*BUILD_RESULT: \$\{\{ needs\.build\.result \}\}[\s\S]*EXTENSION_RESULT: \$\{\{ needs\.extension\.result \}\}/);
  assert.match(workflow, /github_prerelease:\n\s+name: Create GitHub draft prerelease/);
  assert.match(workflow, /needs: \[build, publish, extension\]\n\s+if: \$\{\{ always\(\) && !cancelled\(\) \}\}/);
  assert.match(workflow, /name: Require successful build, publish, and extension jobs/);
  assert.match(workflow, /Use Re-run failed jobs on this workflow run/);
  assert.match(workflow, /extension:\n\s+name: Build Chrome and Firefox extensions/);
  assert.match(workflow, /VAULTMESH_EXTENSION_DISTRIBUTION: sideload-review/);
  assert.match(workflow, /VAULTMESH_GOOGLE_OAUTH_CLIENT_ID: \$\{\{ secrets\.VAULTMESH_GOOGLE_OAUTH_CLIENT_ID \}\}/);
  assert.match(workflow, /VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET: \$\{\{ secrets\.VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET \}\}/);
  assert.match(workflow, /name: Validate required desktop OAuth build configuration/);
  assert.match(workflow, /node scripts\/validate-desktop-oauth-build-config\.mjs/);
  assert.doesNotMatch(workflow, /secrets\.WXT_CHROME_EXTENSION_KEY/);
  assert.match(workflow, /build-browser-extension-release\.mjs/);
  assert.match(workflow, /name: vaultmesh-browser-extensions/);
  assert.match(workflow, /needs: \[build, publish, extension\]/);
  assert.match(workflow, /permissions:\n\s+contents: write/);
  assert.match(workflow, /--draft\s+\\\n\s+--prerelease/);
  assert.match(workflow, /git ls-remote --exit-code --tags origin/);
  assert.match(workflow, /VaultMesh_\$\{RELEASE_VERSION\}_darwin-aarch64\.dmg/);
  assert.match(workflow, /VaultMesh_\$\{RELEASE_VERSION\}_darwin-x86_64\.dmg/);
  assert.match(workflow, /VaultMesh_\$\{RELEASE_VERSION\}_windows-x86_64-setup\.exe/);
  assert.match(workflow, /VaultMesh_\$\{RELEASE_VERSION\}_windows-x86_64-installer\.msi/);
  assert.match(workflow, /VaultMesh_\$\{RELEASE_VERSION\}_chrome-extension\.zip/);
  assert.match(workflow, /VaultMesh_\$\{RELEASE_VERSION\}_firefox-extension\.zip/);
  assert.match(workflow, /releases\/v\$\{RELEASE_VERSION\}\/\$\{asset\}/);
  assert.match(workflow, /"application\/zip"/);
  assert.match(workflow, /curl --fail --silent --show-error[\s\S]*releases\/v\$\{RELEASE_VERSION\}\/\$\{asset\}/);
  assert.match(workflow, /cmp "\$RUNNER_TEMP\/vaultmesh-browser-extensions\/\$asset" "\$published"/);
  assert.match(workflow, /Chrome\/Chromium extension ZIP/);
  assert.match(workflow, /Firefox extension ZIP/);
  assert.match(workflow, /\.isDraft.*== "true"/);
  assert.match(workflow, /\.isPrerelease.*== "true"/);
  assert.doesNotMatch(workflow, /gh release upload[^\n]*--clobber/);
  assert.doesNotMatch(workflow, /self-hosted/);
});

test("native hosted macOS packages can embed Review without publishing the channel", async () => {
  const workflow = await readFile(
    new URL(".github/workflows/r2-macos-experimental-package.yml", workspace),
    "utf8",
  );

  assert.match(
    workflow,
    /runs-on: \$\{\{ inputs\.platform == 'darwin-aarch64' && 'macos-15' \|\| 'macos-15-intel' \}\}/,
  );
  assert.match(workflow, /\[\[ "\$\(uname -m\)" == "\$HOST_ARCH" \]\]/);
  assert.match(workflow, /options:\n\s+- test\n\s+- review/);
  assert.match(workflow, /channels\/\$\{\{ inputs\.channel \}\}\/latest\.json/);
  assert.match(workflow, /VAULTMESH_GOOGLE_OAUTH_CLIENT_ID: \$\{\{ secrets\.VAULTMESH_GOOGLE_OAUTH_CLIENT_ID \}\}/);
  assert.match(workflow, /VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET: \$\{\{ secrets\.VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET \}\}/);
  assert.match(workflow, /name: Validate required desktop OAuth build configuration/);
  assert.match(workflow, /node scripts\/validate-desktop-oauth-build-config\.mjs/);
  assert.match(workflow, /Review channel requires a review prerelease version/);
  assert.match(workflow, /does not match source metadata/);
  assert.match(workflow, /The \$\{UPDATER_CHANNEL\} update channel was not modified/);
  assert.doesNotMatch(workflow, /channels\/(?:test|review)\/latest\.json.*--request PUT/);
});

test("Intel staged Review channel starts at the baseline and then advances strictly", async () => {
  const workflow = await readFile(
    new URL(".github/workflows/r2-review-intel-baseline.yml", workspace),
    "utf8",
  );

  assert.match(workflow, /runs-on: ubuntu-24\.04/);
  assert.match(workflow, /default: "0\.0\.8-review"/);
  assert.match(workflow, /RELEASE_VERSION.*-review/);
  assert.match(workflow, /create-review-baseline-manifest\.mjs/);
  assert.match(workflow, /arguments\+?=\(/);
  assert.match(workflow, /--current "\$RUNNER_TEMP\/review-channel-before\.json"/);
  assert.match(workflow, /experimental\/macos\/darwin-x86_64\/v\$\{RELEASE_VERSION\}/);
  assert.match(workflow, /Review channel state changed during publication/);
  assert.match(workflow, /review-channel-authoritative-before\.json/);
  assert.match(workflow, /channels\/review\/latest\.json/);
  assert.match(workflow, /cmp "\$RUNNER_TEMP\/test-channel-before\.json" "\$RUNNER_TEMP\/test-channel-after\.json"/);
  assert.doesNotMatch(workflow, /self-hosted|macos-15|windows-2025/);
  assert.doesNotMatch(workflow, /channels\/test\/latest\.json.*--request PUT/);
});

test("Windows Review packages use a frozen source and append only a same-version platform", async () => {
  const workflow = await readFile(
    new URL(".github/workflows/r2-windows-experimental-package.yml", workspace),
    "utf8",
  );

  assert.match(workflow, /runs-on: windows-2022/);
  assert.match(workflow, /options:\n\s+- test\n\s+- review/);
  assert.match(workflow, /ref: \$\{\{ inputs\.source_ref \|\| github\.sha \}\}/);
  assert.match(workflow, /channels\/\$\{\{ inputs\.channel \}\}\/latest\.json/);
  assert.match(workflow, /VAULTMESH_GOOGLE_OAUTH_CLIENT_ID: \$\{\{ secrets\.VAULTMESH_GOOGLE_OAUTH_CLIENT_ID \}\}/);
  assert.match(workflow, /VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET: \$\{\{ secrets\.VAULTMESH_GOOGLE_OAUTH_CLIENT_SECRET \}\}/);
  assert.match(workflow, /name: Validate required desktop OAuth build configuration/);
  assert.match(workflow, /node scripts\/validate-desktop-oauth-build-config\.mjs/);
  assert.match(workflow, /extend-review-windows-manifest\.mjs/);
  assert.match(workflow, /if: inputs\.publish_review_platform && inputs\.channel == 'review'/);
  assert.match(workflow, /Review channel state changed during Windows platform publication/);
  assert.match(workflow, /The test update channel changed/);
  assert.doesNotMatch(workflow, /self-hosted|runs-on: (?:ubuntu|macos)/);
  assert.doesNotMatch(workflow, /actions\/(?:upload|download)-artifact|needs: build/);
});
