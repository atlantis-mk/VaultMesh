// CT-AUTOFILL-001. Vendored wire projections have one authoritative desktop owner.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

for (const name of ['autofill-field-policy.json', 'browser-generated-value.ts', 'browser-native-item-plan.ts', 'browser-native-login-plan.ts', 'browser-native-login-profile.ts', 'browser-recovery-file.ts']) {
  test(`isolated fork projection matches shared owner: ${name}`, () => {
    assert.equal(readFileSync(new URL(`../src/vaultmesh/vendor/${name}`, import.meta.url), 'utf8'),
      readFileSync(new URL(`../../tauri-desktop/src/shared/${name}`, import.meta.url), 'utf8'));
  });
}

test('isolated model contracts are an exact desktop projection without desktop-only re-exports', () => {
  const owner = readFileSync(new URL('../../tauri-desktop/src/shared/contracts.ts', import.meta.url), 'utf8');
  assert.equal(readFileSync(new URL('../src/vaultmesh/vendor/model-contracts.ts', import.meta.url), 'utf8'),
    owner.split("export * from './service-contracts';")[0]);
});
