// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';

import {
  AgentUnlockSurfaceAdapter,
  BrowserRepromptUnlockSurfaceAdapter,
  BrowserSessionUnlockSurfaceAdapter,
  DesktopUnlockSurfaceAdapter,
  UnlockSurfaceUiFactory,
  type UnlockWindowRequest,
} from './unlock-surface-adapter';

describe('UnlockSurfaceUiFactory & UnlockSurfaceUiAdapter variants', () => {
  it('creates all four stateless unlock surface adapters via createFor and all()', () => {
    const all = UnlockSurfaceUiFactory.all();
    expect(all.map((adapter) => adapter.kind)).toEqual([
      'desktop',
      'browser-session',
      'browser-reprompt',
      'agent',
    ]);

    expect(UnlockSurfaceUiFactory.createFor('desktop')).toBeInstanceOf(DesktopUnlockSurfaceAdapter);
    expect(UnlockSurfaceUiFactory.createFor('browser-session')).toBeInstanceOf(BrowserSessionUnlockSurfaceAdapter);
    expect(UnlockSurfaceUiFactory.createFor('browser-reprompt')).toBeInstanceOf(BrowserRepromptUnlockSurfaceAdapter);
    expect(UnlockSurfaceUiFactory.createFor('agent')).toBeInstanceOf(AgentUnlockSurfaceAdapter);
  });

  it('resolves desktop adapter when request is null or desktop, with dynamic Touch ID and PIN hints', () => {
    const adapter = UnlockSurfaceUiFactory.fromWindowRequest(null);
    expect(adapter.kind).toBe('desktop');
    expect(adapter.title).toBe('解锁 VaultMesh');
    expect(adapter.forceMasterPassword).toBe(false);
    expect(adapter.showAgentScopeSwitch).toBe(false);
    expect(adapter.showCancelAction).toBe(false);
    expect(adapter.showSetupWhenVaultMissing).toBe(true);
    expect(adapter.hasCountdown).toBe(false);
    expect(adapter.usesErrorBanner).toBe(true);
    expect(adapter.pinLabel).toBe('6 位 PIN');
    expect(adapter.pinSwitchLabel(true, false)).toBe('改用主密码');
    expect(adapter.pinSwitchLabel(false, false)).toBe('改用 PIN');
    expect(adapter.pinSwitchLabel(false, true)).toBe('PIN 已锁定');
    expect(adapter.submitLabel(false)).toBe('使用主密码解锁');
    expect(adapter.submitLabel(true)).toBe('正在解锁…');
    expect(adapter.buildTouchIdHint(true)).toContain('PIN');
    expect(adapter.buildTouchIdHint(false)).toContain('主密码');
    expect(adapter.buildDescription({
      pinPreferred: true,
      pinLocked: false,
      pinRemainingAttempts: 4,
      biometricEnabled: true,
    })).toContain('4 次');
    expect(adapter.buildDescription({
      pinPreferred: false,
      pinLocked: true,
      biometricEnabled: false,
    })).toContain('PIN 已锁定');
  });

  it('resolves browser-session adapter for popup, autofill, and passkey session unlocks', () => {
    const popupRequest: UnlockWindowRequest = {
      kind: 'browser-session',
      source: 'popup',
      unlockRef: 'req-popup',
      origin: '',
      itemTitle: '',
      itemKind: '',
      masterPasswordReprompt: false,
      createdAt: 1_000,
      expiresAt: 31_000,
    };
    const popupAdapter = UnlockSurfaceUiFactory.fromWindowRequest(popupRequest);
    expect(popupAdapter.kind).toBe('browser-session');
    expect(popupAdapter.title).toBe('解锁 VaultMesh 浏览器插件');
    expect(popupAdapter.forceMasterPassword).toBe(false);
    expect(popupAdapter.showAgentScopeSwitch).toBe(false);
    expect(popupAdapter.showCancelAction).toBe(true);
    expect(popupAdapter.hasCountdown).toBe(true);
    expect(popupAdapter.pinLabel).toBe('浏览器插件 PIN');
    expect(popupAdapter.pinSwitchLabel(false, false)).toBe('改用浏览器插件 PIN');
    expect(popupAdapter.submitLabel(false)).toBe('解锁浏览器插件');
    expect(popupAdapter.buildDescription({
      pinPreferred: false,
      pinLocked: false,
      biometricEnabled: true,
      request: popupRequest,
    })).toBe('在桌面端完成解锁以启用浏览器插件');
    expect(popupAdapter.buildTouchIdHint(true)).toContain('PIN');
    expect(popupAdapter.buildTouchIdHint(false)).toContain('主密码');

    const autofillRequest: UnlockWindowRequest = {
      kind: 'browser-session',
      source: 'autofill',
      unlockRef: 'req-autofill',
      origin: 'https://github.com',
      itemTitle: 'GitHub Work',
      itemKind: 'login',
      masterPasswordReprompt: false,
      createdAt: 1_000,
      expiresAt: 31_000,
    };
    expect(UnlockSurfaceUiFactory.fromWindowRequest(autofillRequest).buildDescription({
      pinPreferred: false,
      pinLocked: false,
      biometricEnabled: false,
      request: autofillRequest,
    })).toContain('https://github.com · GitHub Work');
  });

  it('resolves browser-reprompt adapter when masterPasswordReprompt is true', () => {
    const repromptRequest: UnlockWindowRequest = {
      kind: 'browser-autofill',
      source: 'autofill',
      unlockRef: 'req-card',
      origin: 'https://pay.example.com',
      itemTitle: 'Corporate Visa',
      itemKind: 'card',
      masterPasswordReprompt: true,
      createdAt: 2_000,
      expiresAt: 32_000,
    };
    const adapter = UnlockSurfaceUiFactory.fromWindowRequest(repromptRequest);
    expect(adapter.kind).toBe('browser-reprompt');
    expect(adapter.title).toBe('解锁 VaultMesh 浏览器插件');
    expect(adapter.forceMasterPassword).toBe(true);
    expect(adapter.showAgentScopeSwitch).toBe(false);
    expect(adapter.showCancelAction).toBe(true);
    expect(adapter.hasCountdown).toBe(true);
    expect(adapter.submitLabel(false)).toBe('解锁并填充');
    expect(adapter.buildDescription({
      pinPreferred: false,
      pinLocked: false,
      biometricEnabled: false,
      request: repromptRequest,
    })).toContain('此条目受主密码保护，需要输入主密码确认填充');

    const lockedRepromptSession: UnlockWindowRequest = {
      ...repromptRequest,
      kind: 'browser-session',
    };
    expect(UnlockSurfaceUiFactory.fromWindowRequest(lockedRepromptSession).kind).toBe('browser-reprompt');
  });

  it('resolves agent adapter with scope switch and client key context', () => {
    const agentRequest: UnlockWindowRequest = {
      kind: 'agent',
      unlockRef: 'req-agent',
      clientId: 'client-1',
      clientKey: 'codex',
      createdAt: 1_000,
      expiresAt: 31_000,
    };
    const adapter = UnlockSurfaceUiFactory.fromWindowRequest(agentRequest);
    expect(adapter.kind).toBe('agent');
    expect(adapter.title).toBe('解锁 VaultMesh Agent工具');
    expect(adapter.forceMasterPassword).toBe(false);
    expect(adapter.showAgentScopeSwitch).toBe(true);
    expect(adapter.showCancelAction).toBe(true);
    expect(adapter.hasCountdown).toBe(true);
    expect(adapter.pinLabel).toBe('Agent 专用 PIN');
    expect(adapter.pinSwitchLabel(false, false)).toBe('改用 Agent PIN');
    expect(adapter.submitLabel(false)).toBe('解锁 MCP');
    expect(adapter.buildDescription({
      pinPreferred: false,
      pinLocked: false,
      biometricEnabled: false,
      request: agentRequest,
      unlockScope: 'connection',
    })).toContain('codex');
    expect(adapter.buildDescription({
      pinPreferred: false,
      pinLocked: false,
      biometricEnabled: false,
      request: agentRequest,
      unlockScope: 'client',
    })).toContain('并行 MCP 连接共享');
  });
});
