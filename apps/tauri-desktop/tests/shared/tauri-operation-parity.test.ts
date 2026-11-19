import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

const adapterSource = readFileSync(resolve(process.cwd(), 'src/tauri-api.ts'), 'utf8');
const dispatcherSource = [
  'src-tauri/src/lib.rs',
  'src-tauri/src/agent_admin.rs',
  'src-tauri/src/desktop_runtime.rs',
  'src-tauri/src/desktop_email.rs',
].map((path) => readFileSync(resolve(process.cwd(), path), 'utf8'))
  .join('\n')
  .split('\n#[cfg(test)]\nmod tests')[0]!;

function adapterOperations(): string[] {
  return [...adapterSource.matchAll(/(?:call|copy)(?:<[^>]+>)?\(\s*'([^']+)'/g)]
    .map((match) => match[1]!)
    .filter((operation, index, operations) => operations.indexOf(operation) === index)
    .sort();
}

describe('Tauri typed desktop operation parity', () => {
  it('routes every typed adapter operation through the Rust dispatcher', () => {
    const operations = adapterOperations();
    expect(operations.length).toBeGreaterThan(100);
    expect(operations.filter((operation) => !dispatcherSource.includes(`"${operation}"`))).toEqual([]);
  });

  it('does not retain the superseded renderer browser-fill approval channel', () => {
    expect(adapterSource).not.toContain('browser-fill-requested');
    expect(adapterOperations()).not.toEqual(expect.arrayContaining([
      'browser-fill.preview',
      'browser-fill.approve',
      'browser-fill.cancel',
    ]));
  });

  it('keeps the generic fallback as a denied unknown operation, not a migration placeholder', () => {
    expect(dispatcherSource).not.toContain('尚未迁移');
    expect(dispatcherSource).toContain('该桌面操作不被允许。');
  });

  it('exposes explicit literal routes for browser and agent PIN management before test blocks', () => {
    for (const operation of [
      'browser.pin.status',
      'browser.pin.enable',
      'browser.pin.disable',
      'agent.pin.status',
      'agent.pin.enable',
      'agent.pin.disable',
    ]) {
      expect(dispatcherSource).toContain(`"${operation}"`);
    }
  });
});
