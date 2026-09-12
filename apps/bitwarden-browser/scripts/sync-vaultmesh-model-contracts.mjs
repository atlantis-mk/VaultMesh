// Mechanical projection of the desktop-owned model contracts. No desktop services
// or product-only re-exports are part of the isolated extension runtime.
import { readFileSync, writeFileSync } from 'node:fs';
const source = readFileSync(new URL('../../tauri-desktop/src/shared/contracts.ts', import.meta.url), 'utf8');
const projection = source.split("export * from './service-contracts';")[0];
if (!projection.includes('export const IdentityInputSchema') || projection === source) throw new Error('Contract projection boundary changed');
writeFileSync(new URL('../src/vaultmesh/vendor/model-contracts.ts', import.meta.url), projection);
