import assert from "node:assert/strict";
import test from "node:test";

import {
  applyMacOSKeychainEntitlements,
  DESKTOP_KEYCHAIN_ACCESS_GROUP,
  keychainEntitlementsAreTeamScoped,
  keychainSignPlan,
  mergeKeychainAccessGroup,
  shouldApplyTeamKeychainEntitlements,
} from "./macos-keychain-entitlements.mjs";

const EXISTING = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
</dict>
</plist>
`;

test("keychain entitlements name only the desktop access group", () => {
  assert.equal(keychainEntitlementsAreTeamScoped(), true);
  assert.equal(shouldApplyTeamKeychainEntitlements("-"), false);
  assert.equal(shouldApplyTeamKeychainEntitlements(""), false);
  assert.equal(shouldApplyTeamKeychainEntitlements("  "), false);
  assert.equal(shouldApplyTeamKeychainEntitlements("Developer ID Application: Example (AB12CD34EF)"), true);
});

test("team signing reseals the main app and in-bundle host only", () => {
  const plan = keychainSignPlan(
    "/Applications/VaultMesh.app",
    "Developer ID Application: VaultMesh (ABCD123456)",
  );
  assert.ok(plan);
  assert.equal(plan.preservesExistingEntitlements, true);
  assert.equal(plan.mergeAccessGroup, DESKTOP_KEYCHAIN_ACCESS_GROUP);
  assert.equal(plan.entitlements, undefined);
  assert.deepEqual(plan.signOrder, [
    "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-native-host",
    "/Applications/VaultMesh.app",
  ]);
  assert.ok(plan.signOrder.every((target) => !target.includes("agent-mcp")));
  assert.ok(plan.signOrder.every((target) => !target.includes("bitwarden")));
  assert.ok(plan.excluded.some((target) => target.endsWith("vaultmesh-agent-mcp")));
  assert.equal(keychainSignPlan("/Applications/VaultMesh.app", "-"), null);
});

test("resign merges the access group and keeps existing entitlements", async () => {
  const merged = mergeKeychainAccessGroup(EXISTING);
  assert.match(merged, /<key>com\.apple\.security\.cs\.allow-jit<\/key>/);
  assert.match(merged, /<key>com\.apple\.security\.cs\.allow-unsigned-executable-memory<\/key>/);
  assert.match(merged, /<key>com\.apple\.security\.device\.audio-input<\/key>/);
  assert.match(merged, /<key>keychain-access-groups<\/key>/);
  assert.match(merged, /\$\(TeamIdentifierPrefix\)com\.vaultmesh\.desktop/);
  assert.equal(merged.includes("com.apple.security.app-sandbox"), false);

  const again = mergeKeychainAccessGroup(merged);
  assert.equal(again, merged);

  const expanded = EXISTING.replace(
    "</dict>",
    `    <key>keychain-access-groups</key>
    <array>
        <string>ABCD123456.com.vaultmesh.desktop</string>
    </array>
</dict>`,
  );
  const kept = mergeKeychainAccessGroup(expanded);
  assert.equal(kept, expanded);
  assert.equal(kept.includes(DESKTOP_KEYCHAIN_ACCESS_GROUP), false);

  const calls = [];
  const result = await applyMacOSKeychainEntitlements(
    "/Applications/VaultMesh.app",
    "Developer ID Application: VaultMesh (ABCD123456)",
    "darwin",
    {
      dumpEntitlements: async (target) => (target.endsWith(".app") ? EXISTING : ""),
      codesign: async (identity, entitlementsXml, target) => {
        calls.push({ identity, entitlementsXml, target });
      },
    },
  );
  assert.equal(calls.length, 2);
  assert.match(calls[1].entitlementsXml, /allow-jit/);
  assert.match(calls[1].entitlementsXml, /keychain-access-groups/);
  assert.match(calls[0].entitlementsXml, /keychain-access-groups/);
  assert.equal(calls[0].entitlementsXml.includes("allow-jit"), false);
  assert.equal(result.signed[1].target, "/Applications/VaultMesh.app");
});
