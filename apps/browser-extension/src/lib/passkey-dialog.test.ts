import { afterEach, describe, expect, it, vi } from 'vitest';

import { createPasskeyDialog, passkeyDialogCopy, passkeyPromptText, type PasskeyPromptView } from './passkey-dialog';

const token = '3f6a5a0c-6b0e-4a3c-9d57-3c2c8d1f9a11';
const choose: PasskeyPromptView = { token, operation: 'get', origin: 'https://example.test', stage: 'choose' };

function harness(options: { requireTrustedEvents?: boolean; shadowMode?: 'open' | 'closed' } = { requireTrustedEvents: false, shadowMode: 'open' }) {
  const handlers = { choose: vi.fn(), openUnlock: vi.fn() };
  const dialog = createPasskeyDialog(document, handlers, options);
  const buttons = () => [...(dialog.element()?.shadowRoot?.querySelectorAll('button') ?? [])] as HTMLButtonElement[];
  const byText = (text: string) => buttons().find((button) => button.textContent === text)!;
  return { dialog, handlers, buttons, byText };
}

afterEach(() => { document.documentElement.querySelectorAll('[data-vaultmesh-passkey]').forEach((node) => node.remove()); });

describe('in-page passkey dialog', () => {
  it('asks to choose between VaultMesh and the browser and reports the remembered choice', () => {
    const { dialog, handlers, byText } = harness();
    dialog.show(choose);
    const root = dialog.element()!.shadowRoot!;
    expect(root.querySelector('.title')?.textContent).toBe('使用通行密钥登录');
    expect(root.querySelector('.brand')?.textContent).toBe('VaultMesh');
    expect(root.querySelector('.site')?.textContent).toBe('https://example.test');
    expect(root.querySelector('.desc')?.textContent).toContain('要使用 VaultMesh');
    (dialog.element()!.shadowRoot!.querySelector('input[type=checkbox]') as HTMLInputElement).click();
    byText('使用 VaultMesh').click();
    expect(handlers.choose).toHaveBeenCalledWith(token, 'vaultmesh', true);
    byText('使用浏览器/系统').click();
    expect(handlers.choose).toHaveBeenLastCalledWith(token, 'native', true);
    byText('取消').click();
    expect(handlers.choose).toHaveBeenLastCalledWith(token, 'cancel', false);
  });

  it('offers unlock-window, browser and cancel while locked, without a remember option or credential fields', () => {
    const { dialog, handlers, buttons, byText } = harness();
    dialog.show({ ...choose, stage: 'unlock', operation: 'create' });
    const root = dialog.element()!.shadowRoot!;
    expect(buttons().map((button) => button.textContent)).toEqual(['取消', '改用浏览器/系统', '打开解锁窗口']);
    expect(root.querySelector('.title')?.textContent).toBe('创建通行密钥');
    expect(root.querySelector('.desc')?.textContent).toContain('已锁定');
    expect(root.querySelector('input')).toBeNull();
    byText('打开解锁窗口').click();
    expect(handlers.openUnlock).toHaveBeenCalledWith(token);
    byText('改用浏览器/系统').click();
    expect(handlers.choose).toHaveBeenCalledWith(token, 'native', false);
  });

  it('cancels on Escape and removes itself only for the matching token', () => {
    const { dialog, handlers } = harness();
    dialog.show(choose);
    dialog.hide('00000000-0000-4000-8000-000000000000');
    expect(dialog.element()).not.toBeNull();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(handlers.choose).toHaveBeenCalledWith(token, 'cancel', false);
    dialog.hide(token);
    expect(dialog.element()).toBeNull();
    expect(document.querySelector('[data-vaultmesh-passkey]')).toBeNull();
  });

  it('replaces a previous prompt when the stage changes', () => {
    const { dialog, buttons } = harness();
    dialog.show(choose);
    dialog.show({ ...choose, token: '9d5f0c40-0e4b-4f2b-8f7a-6a0e6f1b2c33', stage: 'unlock' });
    expect(document.querySelectorAll('[data-vaultmesh-passkey]')).toHaveLength(1);
    expect(buttons().map((button) => button.textContent)).toContain('打开解锁窗口');
    expect(buttons().map((button) => button.textContent)).not.toContain('使用 VaultMesh');
  });

  it('hides its contents from the page with a closed shadow root and ignores script-made clicks', () => {
    const handlers = { choose: vi.fn(), openUnlock: vi.fn() };
    const dialog = createPasskeyDialog(document, handlers);
    dialog.show(choose);
    expect(dialog.element()!.shadowRoot).toBeNull();
    // A page script cannot reach the buttons, and a synthetic Escape is not trusted.
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(handlers.choose).not.toHaveBeenCalled();
  });

  it('renders the site as text, never as markup', () => {
    const { dialog } = harness();
    dialog.show({ ...choose, origin: '<img src=x onerror=alert(1)>' });
    const root = dialog.element()!.shadowRoot!;
    expect(root.querySelector('img')).toBeNull();
    expect(root.querySelector('.site')?.textContent).toBe('<img src=x onerror=alert(1)>');
  });

  it('puts the primary action last and focuses it', () => {
    const { dialog, buttons } = harness();
    dialog.show(choose);
    const all = buttons();
    expect(all.map((button) => button.className)).toEqual(['', 'outline', 'primary']);
    expect(dialog.element()!.shadowRoot!.activeElement).toBe(all[2]);
  });

  it('words the dialog for each operation and stage', () => {
    expect(passkeyDialogCopy(choose)).toEqual({ title: '使用通行密钥登录', description: '要使用 VaultMesh，还是使用浏览器/系统？' });
    expect(passkeyDialogCopy({ ...choose, operation: 'create' }).description).toContain('保存到 VaultMesh');
    expect(passkeyDialogCopy({ ...choose, stage: 'unlock' }).description).toContain('已锁定');
  });

  it('words the popup prompt for each operation and stage', () => {
    expect(passkeyPromptText({ ...choose, operation: 'create' })).toContain('保存到 VaultMesh');
    expect(passkeyPromptText({ ...choose, origin: null })).toContain('当前网站');
    expect(passkeyPromptText({ ...choose, stage: 'unlock' })).toContain('已锁定');
  });
});
