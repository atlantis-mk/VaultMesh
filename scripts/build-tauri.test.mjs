import assert from "node:assert/strict";
import test from "node:test";

import {
  developmentExtensionId,
  developmentExtensionKey,
  sideloadReviewDistribution,
} from "./browser-identity.mjs";
import {
  parseTauriBuildArguments,
  tauriBuildEnvironment,
  tauriCliInvocation,
  updaterBuildConfig,
  windowsMsiVersion,
} from "./build-tauri.mjs";

test("Tauri package build derives the same extension identity for main binary and Host", () => {
  assert.deepEqual(parseTauriBuildArguments([]), {
    requireRelease: false,
    verbose: false,
    target: undefined,
    bundles: undefined,
    updaterVersion: undefined,
  });
  assert.deepEqual(parseTauriBuildArguments(["--release-identity"]), {
    requireRelease: true,
    verbose: false,
    target: undefined,
    bundles: undefined,
    updaterVersion: undefined,
  });
  assert.deepEqual(parseTauriBuildArguments(["--verbose", "--target", "aarch64-apple-darwin", "--bundles", "dmg"]), {
    requireRelease: false,
    verbose: true,
    target: "aarch64-apple-darwin",
    bundles: "dmg",
    updaterVersion: undefined,
  });
  assert.throws(() => parseTauriBuildArguments(["--target", "../unexpected"]));

  const releaseKey = Buffer.from("vaultmesh-test-release-public-key").toString("base64");
  const environment = tauriBuildEnvironment({
    PATH: "/usr/bin",
    WXT_CHROME_EXTENSION_KEY: releaseKey,
  }, { requireRelease: true });
  assert.notEqual(environment.VAULTMESH_BROWSER_EXTENSION_ID, developmentExtensionId);
  assert.equal(environment.WXT_CHROME_EXTENSION_KEY, releaseKey);
  assert.equal(environment.VAULTMESH_UPDATER_ENABLED, undefined);

  const updaterEnvironment = tauriBuildEnvironment({
    PATH: "/usr/bin",
    VAULTMESH_UPDATER_ENABLED: "stale-inherited-value",
  }, { updaterEnabled: true });
  assert.equal(updaterEnvironment.VAULTMESH_UPDATER_ENABLED, "1");
  assert.equal(
    tauriBuildEnvironment({ VAULTMESH_UPDATER_ENABLED: "1" }).VAULTMESH_UPDATER_ENABLED,
    undefined,
  );
  assert.equal(
    tauriBuildEnvironment({ MACOSX_DEPLOYMENT_TARGET: "15.2" }, {
      target: "x86_64-apple-darwin",
    }).MACOSX_DEPLOYMENT_TARGET,
    "12.0",
  );
  assert.equal(
    tauriBuildEnvironment({ MACOSX_DEPLOYMENT_TARGET: "15.2" }, {
      target: "aarch64-apple-darwin",
    }).MACOSX_DEPLOYMENT_TARGET,
    "12.0",
  );
  assert.equal(
    tauriBuildEnvironment({ MACOSX_DEPLOYMENT_TARGET: "15.2" }, {
      target: "x86_64-pc-windows-msvc",
    }).MACOSX_DEPLOYMENT_TARGET,
    "15.2",
  );
});

test("Updater release config requires HTTPS, public verification material and signing key", () => {
  const environment = {
    VAULTMESH_UPDATER_ENDPOINT: "https://updates.example.test/channels/test/latest.json",
    VAULTMESH_UPDATER_PUBLIC_KEY: "public-key-material-that-is-long-enough",
    TAURI_SIGNING_PRIVATE_KEY: "private-key-is-only-used-by-the-build",
  };
  const config = updaterBuildConfig(environment, "1.2.3-test.1");
  assert.equal(config.version, "1.2.3-test.1");
  assert.equal(config.bundle.createUpdaterArtifacts, true);
  assert.deepEqual(config.bundle.externalBin, ["binaries/vaultmesh-agent-mcp"]);
  assert.deepEqual(config.plugins.updater.endpoints, [environment.VAULTMESH_UPDATER_ENDPOINT]);
  assert.equal(config.plugins.updater.windows.installMode, "passive");
  assert.doesNotMatch(JSON.stringify(config), /private-key-is-only-used-by-the-build/);

  const msiConfig = updaterBuildConfig(environment, "1.2.3-test.4", { includeMsi: true });
  assert.equal(msiConfig.bundle.windows.wix.version, "1.2.3.4");
  assert.equal(windowsMsiVersion("1.2.3"), "1.2.3");
  assert.equal(windowsMsiVersion("0.0.1-review"), "0.0.1");
  assert.equal(windowsMsiVersion("0.0.2-review"), "0.0.2");
  assert.throws(() => windowsMsiVersion("1.2.3-test.preview"), /数值序号/);
  assert.throws(() => windowsMsiVersion("256.2.3-test.1"), /数值范围/);

  assert.throws(() => updaterBuildConfig({ ...environment, VAULTMESH_UPDATER_ENDPOINT: "http://updates.test/latest.json" }, "1.2.3"), /HTTPS/);
  assert.throws(() => updaterBuildConfig({ ...environment, TAURI_SIGNING_PRIVATE_KEY: "" }, "1.2.3"), /TAURI_SIGNING_PRIVATE_KEY/);
  assert.throws(() => updaterBuildConfig(environment, "01.2.3"), /SemVer/);
});

test("Tauri CLI is launched through Node instead of a Windows command shim", () => {
  const invocation = tauriCliInvocation(["build", "--bundles", "nsis"], "C:\\Program Files\\nodejs\\node.exe");
  assert.equal(invocation.command, "C:\\Program Files\\nodejs\\node.exe");
  assert.match(invocation.arguments[0], /@tauri-apps[\\/]cli[\\/]tauri\.js$/);
  assert.deepEqual(invocation.arguments.slice(1), ["build", "--bundles", "nsis"]);
  assert.match(invocation.cwd, /apps[\\/]tauri-desktop$/);
});

test("Tauri release build packages the pinned store extension identity", () => {
  assert.equal(
    tauriBuildEnvironment({}, { requireRelease: true }).VAULTMESH_BROWSER_EXTENSION_ID,
    developmentExtensionId,
  );
  const environment = tauriBuildEnvironment({
    VAULTMESH_EXTENSION_DISTRIBUTION: sideloadReviewDistribution,
  }, { requireRelease: true });
  assert.equal(environment.WXT_CHROME_EXTENSION_KEY, developmentExtensionKey);
  assert.equal(environment.VAULTMESH_BROWSER_EXTENSION_ID, developmentExtensionId);
});
