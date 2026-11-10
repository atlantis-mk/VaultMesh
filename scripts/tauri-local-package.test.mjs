import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const script = await readFile(new URL("./tauri-local-package.mjs", import.meta.url), "utf8");

test("local package asks Tauri for the app bundle only", () => {
  assert.match(
    script,
    /"tauri", "build", "--bundles", "app",\s+"--config", "src-tauri\/tauri\.agent\.conf\.json"/,
    "local packaging must finish the signed app before creating its verified DMG",
  );
});

test("local package prepares the Browser Host sidecar before Tauri bundles the app", () => {
  const prepare = script.indexOf('"prepare-browser-host-sidecar.mjs"');
  const bundle = script.indexOf('"tauri", "build", "--bundles", "app"');
  assert.ok(prepare >= 0);
  assert.ok(bundle > prepare);
});

test("CT-BROWSER-PACKAGE-001: local package verifies Tauri-bundled sidecars before signing without patching them", () => {
  const prepare = script.indexOf('"prepare-agent-sidecar.mjs"');
  const bundle = script.indexOf('"tauri", "build", "--bundles", "app"');
  const verify = script.indexOf('await verifyPackagedMacOSSidecars(packagedApp);');
  const sign = script.indexOf('await run("codesign", ["--force", "--deep", "--sign", "-", packagedApp]);');
  assert.ok(prepare >= 0);
  assert.ok(bundle > prepare);
  assert.ok(verify > bundle);
  assert.ok(sign > verify);
  assert.doesNotMatch(script, /\b(?:cp|chmod)\([^\n]*vaultmesh-(?:native-host|agent-mcp)/);
  assert.doesNotMatch(script, /\bbuilt(?:Host|AgentMcp)\b/);
});

test("local package verifies artifacts before replacing the installed app", () => {
  const verifyDmg = script.indexOf('await run("hdiutil", ["verify", localDmg]);');
  const verifyZip = script.indexOf('await run("unzip", ["-tq", extensionZip]);');
  const moveInstalledApp = script.indexOf("await rename(installedTauriApp, backupApp);");

  assert.ok(verifyDmg >= 0);
  assert.ok(verifyZip > verifyDmg);
  assert.ok(moveInstalledApp > verifyZip);
});

test("local package cleans up a failed first-time installation", () => {
  assert.match(script, /installAttempted = true;\s+await run\("ditto", \[packagedApp, installedTauriApp\]\);/);
  assert.match(script, /if \(installAttempted \|\| movedExistingApp\)/);
  assert.match(script, /await rm\(installedTauriApp, \{ recursive: true, force: true \}\)/);
});

test("local package clears stale browser socket and verifies live socket listener without crash-restoration modal", async () => {
  const launchScript = await readFile(new URL("./tauri-local-launch.mjs", import.meta.url), "utf8");
  const cargoToml = await readFile(new URL("../Cargo.toml", import.meta.url), "utf8");
  assert.match(script, /await rm\(path\.join\(tmpdir\(\), "vaultmesh-tauri-browser\.sock"\), \{ force: true \}\);/);
  assert.match(launchScript, /"-ApplePersistenceIgnoreState", "YES"/);
  assert.match(launchScript, /return await canConnectUnixSocket\(socket\);/);
  assert.doesNotMatch(launchScript, /await access\(socket\);/);
  assert.match(cargoToml, /\[profile\.release\]\s+strip = "none"/);
  assert.match(cargoToml, /\[profile\.release\.build-override\]\s+strip = "none"/);

  if (process.platform !== "win32") {
    const { createServer } = await import("node:net");
    const { mkdtemp, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const path = await import("node:path");
    const { canConnectUnixSocket } = await import("./tauri-local-launch.mjs");

    const dir = await mkdtemp(path.join(tmpdir(), "vm-sock-test-"));
    const sockPath = path.join(dir, "broker.sock");
    try {
      assert.equal(await canConnectUnixSocket(sockPath, 200), false);
      const server = createServer((conn) => conn.end());
      await new Promise((resolve) => server.listen(sockPath, resolve));
      assert.equal(await canConnectUnixSocket(sockPath, 500), true);
      await new Promise((resolve) => server.close(resolve));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});
