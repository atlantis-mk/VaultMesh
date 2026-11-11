import { beforeEach, describe, expect, it } from 'vitest';

import { clearPasskeyDiagnostics, explainPasskeyDiagnostic, MAX_PASSKEY_DIAGNOSTICS, readPasskeyDiagnostics, recordPasskeyDiagnostic } from './passkey-diagnostics';

beforeEach(async () => {
  await clearPasskeyDiagnostics();
  await browser.storage.local.clear();
});

describe('passkey diagnostics', () => {
  it('records in order and keeps only the most recent entries', async () => {
    for (let index = 0; index < MAX_PASSKEY_DIAGNOSTICS + 5; index += 1) await recordPasskeyDiagnostic(`entry ${index}`, () => index);
    const entries = await readPasskeyDiagnostics();
    expect(entries).toHaveLength(MAX_PASSKEY_DIAGNOSTICS);
    expect(entries[0]).toEqual({ at: 5, message: 'entry 5' });
    expect(entries.at(-1)?.message).toBe(`entry ${MAX_PASSKEY_DIAGNOSTICS + 4}`);
  });

  it('keeps every entry when requests record concurrently', async () => {
    await Promise.all(Array.from({ length: 8 }, (_, index) => recordPasskeyDiagnostic(`parallel ${index}`)));
    expect((await readPasskeyDiagnostics()).map((entry) => entry.message).sort()).toEqual(Array.from({ length: 8 }, (_, index) => `parallel ${index}`).sort());
  });

  it('strips control characters and bounds the message', async () => {
    await recordPasskeyDiagnostic(`line1\nline2\u0000${'x'.repeat(1_000)}`);
    const [entry] = await readPasskeyDiagnostics();
    expect(entry.message).not.toMatch(/[\u0000-\u001f]/);
    expect(entry.message.length).toBe(300);
  });

  it('lives in session storage only and can be cleared', async () => {
    await recordPasskeyDiagnostic('[VaultMesh Passkey] get https://example.test -> browser (no-matching-passkey)');
    expect(Object.keys(await browser.storage.local.get(null))).toEqual([]);
    await clearPasskeyDiagnostics();
    await expect(readPasskeyDiagnostics()).resolves.toEqual([]);
  });

  it('ignores corrupted stored data', async () => {
    await browser.storage.session.set({ 'vaultmesh.passkey.diagnostics.v1': [{ at: 'x' }, 7, { at: 1, message: 'ok' }] });
    await expect(readPasskeyDiagnostics()).resolves.toEqual([{ at: 1, message: 'ok' }]);
  });
});

describe('explaining diagnostic lines', () => {
  it.each([
    ['[VaultMesh Passkey] get https://github.com -> browser (no-matching-passkey)', 'VaultMesh 里没有该网站的通行密钥'],
    ['[VaultMesh Passkey] create https://github.com -> VaultMesh (served)', '是网站拒绝了这份凭据'],
    ['[VaultMesh Passkey] create https://github.com -> VaultMesh (chose-vaultmesh)', '你选择了使用 VaultMesh'],
    ['[VaultMesh Passkey] create https://github.com -> prompt (choose, in-page)', '已在页面里显示 VaultMesh 对话框'],
    ['[VaultMesh Passkey] create https://github.com -> prompt (unlock, extension-window)', '已改为打开插件窗口'],
    ['[VaultMesh Passkey] create https://github.com -> browser (desktop-unpaired)', '还没有与桌面端配对'],
    ['[VaultMesh Passkey] create https://github.com -> browser (desktop-desktop-unavailable)', '连接不上 VaultMesh 桌面端'],
    ['[VaultMesh Passkey] create https://github.com -> cancelled (unlock-timed-out)', '5 分钟内没有解锁'],
    ['[VaultMesh Passkey] create https://github.com -> cancelled (desktop-confirmation-declined)', '原生确认框里点了取消'],
    ['[VaultMesh Passkey] https://github.com -> browser (unsupported-extension:prf, decided in page)', '不支持的扩展（prf）'],
    ['[VaultMesh Passkey] create https://github.com -> error (NotAllowedError, desktop-invalid-input: Passkey 请求格式无效。)', '桌面端未能完成：Passkey 请求格式无效。'],
  ])('explains %s', (message, expected) => {
    expect(explainPasskeyDiagnostic(message)).toContain(expected);
  });

  it('says nothing for lines it does not recognise', () => {
    expect(explainPasskeyDiagnostic('something else')).toBeNull();
    expect(explainPasskeyDiagnostic('[VaultMesh Passkey] get https://x.test -> browser (brand-new-reason)')).toBeNull();
  });
});
