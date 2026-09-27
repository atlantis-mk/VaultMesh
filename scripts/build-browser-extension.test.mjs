import assert from "node:assert/strict";
import test from "node:test";

import {
  developmentExtensionId,
  developmentExtensionKey,
  sideloadReviewDistribution,
} from "./browser-identity.mjs";
import {
  browserExtensionBuildEnvironment,
  browserExtensionBuildInvocation,
} from "./build-browser-extension.mjs";

test("Extension build invokes pnpm.cmd through the Windows command interpreter", () => {
  assert.deepEqual(
    browserExtensionBuildInvocation("zip", "firefox", "win32", { ComSpec: "C:\\Windows\\System32\\cmd.exe" }),
    {
      command: "C:\\Windows\\System32\\cmd.exe",
      arguments: ["/d", "/s", "/c", "pnpm.cmd", "--filter", "@vaultmesh/browser-extension", "exec", "wxt", "zip", "-b", "firefox"],
    },
  );
  assert.deepEqual(browserExtensionBuildInvocation("build", "chrome", "linux"), {
    command: "pnpm",
    arguments: ["--filter", "@vaultmesh/browser-extension", "exec", "wxt", "build", "-b", "chrome"],
  });
});

test("Extension release build defaults to the same fixed development identity as the Host", () => {
  const environment = browserExtensionBuildEnvironment({ PATH: "/usr/bin" });
  assert.equal(environment.WXT_CHROME_EXTENSION_KEY, developmentExtensionKey);
  assert.equal(environment.VAULTMESH_BROWSER_EXTENSION_ID, developmentExtensionId);
  assert.equal(environment.WXT_NATIVE_HOST_NAME, "com.vaultmesh.browser");
  assert.equal(environment.VAULTMESH_FIREFOX_EXTENSION_ID, "vaultmesh@atlantis-mk.github.io");
});

test("Extension release build rejects mismatched identity or Host name", () => {
  assert.throws(() => browserExtensionBuildEnvironment({
    WXT_CHROME_EXTENSION_KEY: developmentExtensionKey,
    VAULTMESH_BROWSER_EXTENSION_ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  }), /manifest key 不匹配/);
  assert.throws(() => browserExtensionBuildEnvironment({
    WXT_NATIVE_HOST_NAME: "com.example.host",
  }), /com\.vaultmesh\.browser/);
  assert.throws(() => browserExtensionBuildEnvironment({
    VAULTMESH_FIREFOX_EXTENSION_ID: "other@example.test",
  }), /固定为/);
});

test("Explicit extension key derives one shared identity and release mode defaults to the pinned store key", () => {
  const releaseKey = Buffer.from("vaultmesh-test-release-public-key").toString("base64");
  const environment = browserExtensionBuildEnvironment({
    WXT_CHROME_EXTENSION_KEY: releaseKey,
  }, { requireRelease: true });
  assert.notEqual(environment.VAULTMESH_BROWSER_EXTENSION_ID, developmentExtensionId);
  const storeEnvironment = browserExtensionBuildEnvironment({}, { requireRelease: true });
  assert.equal(storeEnvironment.WXT_CHROME_EXTENSION_KEY, developmentExtensionKey);
  assert.equal(storeEnvironment.VAULTMESH_BROWSER_EXTENSION_ID, "bdneegbnjbheblmamalplnddbodcghbg");
  const sideloadEnvironment = browserExtensionBuildEnvironment({
    VAULTMESH_EXTENSION_DISTRIBUTION: sideloadReviewDistribution,
  }, { requireRelease: true });
  assert.equal(sideloadEnvironment.WXT_CHROME_EXTENSION_KEY, developmentExtensionKey);
  assert.equal(sideloadEnvironment.VAULTMESH_BROWSER_EXTENSION_ID, developmentExtensionId);
});
