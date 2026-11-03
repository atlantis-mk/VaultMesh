import assert from "node:assert/strict";
import test from "node:test";

import {
  keychainEntitlementsAreTeamScoped,
  keychainSignPlan,
  shouldApplyTeamKeychainEntitlements,
} from "./macos-keychain-entitlements.mjs";

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
  assert.deepEqual(plan.signOrder, [
    "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-native-host",
    "/Applications/VaultMesh.app",
  ]);
  assert.ok(plan.signOrder.every((target) => !target.includes("agent-mcp")));
  assert.ok(plan.signOrder.every((target) => !target.includes("bitwarden")));
  assert.ok(plan.excluded.some((target) => target.endsWith("vaultmesh-agent-mcp")));
  assert.equal(keychainSignPlan("/Applications/VaultMesh.app", "-"), null);
});
