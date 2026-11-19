// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AgentUnlockWindow } from '../../src/agent-unlock';
import { COMPACT_WINDOW_HEIGHT_SLACK_PX } from '../../src/renderer/src/components/UnlockCard';
import type { BrowserUnlockRequest } from '../../src/renderer/src/lib/unlock-surface-adapter';
import type { DesktopAuthenticationEvent } from '../../src/shared/api';

const { hide, invoke, listeners } = vi.hoisted(() => ({
  hide: vi.fn(),
  invoke: vi.fn(),
  listeners: new Map<string, Set<(event: { payload: unknown }) => void>>(),
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke }));
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (event: string, callback: (event: { payload: unknown }) => void) => {
    let set = listeners.get(event);
    if (!set) {
      set = new Set();
      listeners.set(event, set);
    }
    set.add(callback);
    return () => {
      set?.delete(callback);
    };
  }),
}));
vi.mock('@tauri-apps/api/window', () => ({ getCurrentWindow: () => ({ hide }) }));
vi.mock('../../src/renderer/src/components/ui/switch', () => ({
  Switch: ({ checked, onCheckedChange, ...props }: { checked: boolean; onCheckedChange: (checked: boolean) => void; id?: string; disabled?: boolean }) => (
    <button type="button" role="switch" aria-checked={checked} onClick={() => onCheckedChange(!checked)} {...props} />
  ),
}));

function emitTauriEvent(name: string, payload: unknown = null) {
  act(() => {
    listeners.get(name)?.forEach((cb) => cb({ payload }));
  });
}

function lastAuthSessionId(): string {
  const calls = invoke.mock.calls.filter(([cmd]) => cmd === 'desktop_authentication_begin');
  return (calls.at(-1)?.[1] as { sessionId: string }).sessionId;
}

const agentStatus = {
  now: 1_000,
  request: {
    kind: 'agent' as const,
    unlockRef: '22222222-2222-4222-8222-222222222222',
    clientId: '33333333-3333-4333-8333-333333333333',
    clientKey: 'codex',
    createdAt: 1_000,
    expiresAt: 601_000,
  },
  access: {
    hasVault: true,
    clientUnlocked: false,
    settings: { unlockScope: 'connection' as const },
  },
  pin: { enabled: false, locked: false, remainingAttempts: 5 },
  biometric: { available: true, enabled: false, kind: 'touchId' as const },
};

interface BrowserUnlockTestStatus {
  now: number;
  request: BrowserUnlockRequest;
  access: {
    hasVault: boolean;
    clientUnlocked: boolean;
    settings: { unlockScope: 'connection' | 'client' };
  };
  pin: { enabled: boolean; locked: boolean; remainingAttempts: number };
  biometric: { available: boolean; enabled: boolean; kind: 'touchId' | null };
}

const browserSessionPopupStatus: BrowserUnlockTestStatus = {
  now: 2_000,
  request: {
    kind: 'browser-session',
    source: 'popup',
    unlockRef: '55555555-5555-4555-8555-555555555555',
    origin: '',
    itemTitle: '',
    itemKind: '',
    masterPasswordReprompt: false,
    createdAt: 2_000,
    expiresAt: 32_000,
  },
  access: {
    hasVault: true,
    clientUnlocked: false,
    settings: { unlockScope: 'connection' },
  },
  pin: { enabled: true, locked: false, remainingAttempts: 5 },
  biometric: { available: true, enabled: true, kind: 'touchId' },
};

const browserRepromptStatus: BrowserUnlockTestStatus = {
  now: 3_000,
  request: {
    kind: 'browser-autofill',
    source: 'autofill',
    unlockRef: '44444444-4444-4444-8444-444444444444',
    origin: 'https://github.com',
    itemTitle: 'Corporate Visa',
    itemKind: 'card',
    masterPasswordReprompt: true,
    createdAt: 3_000,
    expiresAt: 33_000,
  },
  access: {
    hasVault: true,
    clientUnlocked: false,
    settings: { unlockScope: 'connection' },
  },
  pin: { enabled: true, locked: false, remainingAttempts: 5 },
  biometric: { available: true, enabled: true, kind: 'touchId' },
};

describe('CT-AGENT-UNLOCK-001 & AT-AUTOFILL-001 unified compact unlock window', () => {
  beforeEach(() => {
    vi.stubGlobal('ResizeObserver', class {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    });
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({ x: 80, y: 80, width: 64, height: 64 } as DOMRect);
    invoke.mockReset();
    hide.mockReset();
    listeners.clear();
    let statusReads = 0;
    invoke.mockImplementation(async (command: string) => {
      if (command === 'desktop_authentication_status') {
        return { supported: true, label: 'Touch ID' };
      }
      if (command === 'agent_unlock_status') {
        statusReads += 1;
        return statusReads === 1 ? agentStatus : { ...agentStatus, request: null };
      }
      return { unlocked: true };
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('renders shared compact UnlockCard for Agent MCP, binds password, and hides after success', async () => {
    const { container } = render(<AgentUnlockWindow />);

    expect(await screen.findByText('解锁 VaultMesh Agent工具')).toBeTruthy();
    expect(screen.getByText(/客户端 codex/)).toBeTruthy();
    expect(screen.getByText(/仅授权当前 MCP 连接/)).toBeTruthy();
    const main = container.querySelector('main');
    expect(main?.className).toContain('w-full');
    expect(main?.className).toContain('max-w-[460px]');
    expect(main?.className).toContain('overflow-x-hidden');
    const card = container.querySelector('[data-slot="card"]');
    expect(card).toBeTruthy();
    expect(card?.className).toContain('w-full');
    expect(card?.className).toContain('max-w-[460px]');
    expect(card?.className).not.toContain('min-h-svh');
    expect(card?.parentElement?.className).toContain('min-h-svh');
    const footer = container.querySelector('[data-slot="card-footer"]');
    expect(footer?.className).toContain('rounded-none');
    expect(invoke).toHaveBeenCalledWith('desktop_window_set_compact_mode', {
      compact: true,
      contentHeight: 64 + COMPACT_WINDOW_HEIGHT_SLACK_PX,
    });

    fireEvent.change(screen.getByLabelText('主密码'), {
      target: { value: 'correct horse battery staple' },
    });
    fireEvent.click(screen.getByRole('button', { name: '解锁 MCP' }));

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('agent_unlock_password', {
      password: 'correct horse battery staple',
    }));
    await waitFor(() => expect(hide).toHaveBeenCalled());
  });

  it('measures max(getBoundingClientRect().height, scrollHeight) + slack so overflowing standalone unlock card has no scrollbar', async () => {
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({ x: 0, y: 0, width: 460, height: 390 } as DOMRect);
    const scrollHeightDescriptor = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollHeight');
    Object.defineProperty(HTMLElement.prototype, 'scrollHeight', {
      configurable: true,
      get: () => 442,
    });
    try {
      render(<AgentUnlockWindow />);
      expect(await screen.findByText('解锁 VaultMesh Agent工具')).toBeTruthy();
      expect(COMPACT_WINDOW_HEIGHT_SLACK_PX).toBe(8);
      expect(invoke).toHaveBeenCalledWith('desktop_window_set_compact_mode', {
        compact: true,
        contentHeight: 450,
      });
    } finally {
      if (scrollHeightDescriptor) {
        Object.defineProperty(HTMLElement.prototype, 'scrollHeight', scrollHeightDescriptor);
      } else {
        delete (HTMLElement.prototype as { scrollHeight?: number }).scrollHeight;
      }
    }
  });

  it('re-syncs compact window height when unlockRef changes to a new request', async () => {
    let current = {
      ...agentStatus,
      request: { ...agentStatus.request, unlockRef: '11111111-1111-4111-8111-111111111111' },
    };
    invoke.mockImplementation(async (command: string) => {
      if (command === 'desktop_authentication_status') return { supported: true, label: 'Touch ID' };
      if (command === 'agent_unlock_status') return current;
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);
    expect(await screen.findByText('解锁 VaultMesh Agent工具')).toBeTruthy();
    await waitFor(() => {
      const compactCalls = invoke.mock.calls.filter(([cmd]) => cmd === 'desktop_window_set_compact_mode');
      expect(compactCalls).toHaveLength(1);
    });

    current = {
      ...agentStatus,
      request: { ...agentStatus.request, unlockRef: '77777777-7777-4777-8777-777777777777' },
    };
    emitTauriEvent('agent-unlock-requested');

    await waitFor(() => {
      const compactCalls = invoke.mock.calls.filter(([cmd]) => cmd === 'desktop_window_set_compact_mode');
      expect(compactCalls).toHaveLength(2);
      expect(compactCalls[1]?.[1]).toEqual({
        compact: true,
        contentHeight: 64 + COMPACT_WINDOW_HEIGHT_SLACK_PX,
      });
    });
  });

  it('AT-AGENT-UNLOCK-001: cancels expired request and automatically hides on agent-unlock-expired', async () => {
    render(<AgentUnlockWindow />);

    expect(await screen.findByText('解锁 VaultMesh Agent工具')).toBeTruthy();
    await waitFor(() => expect(listeners.get('agent-unlock-expired')?.size).toBe(1));
    emitTauriEvent('agent-unlock-expired');

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('agent_unlock_cancel'));
    await waitFor(() => expect(hide).toHaveBeenCalledTimes(1));
  });

  it('AT-AGENT-UNLOCK-001: automatically cancels and hides when the 30s countdown reaches zero', async () => {
    vi.useFakeTimers();
    render(<AgentUnlockWindow />);

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByText('解锁 VaultMesh Agent工具')).toBeTruthy();
    expect(hide).not.toHaveBeenCalled();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_200);
    });

    expect(invoke).toHaveBeenCalledWith('agent_unlock_cancel');
    expect(hide).toHaveBeenCalledTimes(1);
  });

  it('transitions to the next queued unlock request instead of hiding when an earlier request expires', async () => {
    let statusReads = 0;
    invoke.mockImplementation(async (command: string) => {
      if (command === 'desktop_authentication_status') return { supported: true, label: 'Touch ID' };
      if (command === 'agent_unlock_status') {
        statusReads += 1;
        return statusReads === 1
          ? agentStatus
          : { ...browserSessionPopupStatus, biometric: { available: false, enabled: false, kind: null }, pin: { enabled: false, locked: false, remainingAttempts: 5 } };
      }
      return { cancelled: true };
    });

    render(<AgentUnlockWindow />);

    expect(await screen.findByText('解锁 VaultMesh Agent工具')).toBeTruthy();
    await waitFor(() => expect(listeners.get('agent-unlock-expired')?.size).toBe(1));
    emitTauriEvent('agent-unlock-expired');

    expect(await screen.findByText('解锁 VaultMesh 浏览器插件')).toBeTruthy();
    expect(screen.getByText('在桌面端完成解锁以启用浏览器插件')).toBeTruthy();
    expect(hide).not.toHaveBeenCalled();
  });

  it('can share one unlock with parallel connections of the same paired client', async () => {
    invoke.mockImplementation(async (command: string, input?: { scope?: string }) => {
      if (command === 'desktop_authentication_status') return { supported: true, label: 'Touch ID' };
      if (command === 'agent_unlock_status') return agentStatus;
      if (command === 'agent_unlock_set_scope') {
        return { unlockScope: input?.scope };
      }
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    const scope = await screen.findByRole('switch', { name: '同一客户端只解锁一次' });
    expect(scope.getAttribute('aria-checked')).toBe('false');
    fireEvent.click(scope);

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('agent_unlock_set_scope', {
      scope: 'client',
    }));
    await waitFor(() => expect(screen.getByText(/并行 MCP 连接共享/)).toBeTruthy());
    expect(scope.getAttribute('aria-checked')).toBe('true');
  });

  it('supports embedded Touch ID alongside Agent PIN, hides agent_unlock_biometric modal, and keeps failure inline only', async () => {
    let unlocked = false;
    invoke.mockImplementation(async (command: string) => {
      if (command === 'desktop_authentication_status') return { supported: true, label: 'Touch ID' };
      if (command === 'agent_unlock_status') {
        if (unlocked) return { ...agentStatus, request: null };
        return {
          ...agentStatus,
          pin: { enabled: true, locked: false, remainingAttempts: 5 },
          biometric: { available: true, enabled: true, kind: 'touchId' },
        };
      }
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    const pinLabel = await screen.findByText('Agent 专用 PIN');
    expect(pinLabel.className).toContain('justify-center');
    expect(document.querySelector('.cn-input-otp.justify-center')).toBeTruthy();

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('desktop_authentication_begin', expect.objectContaining({
      sessionId: expect.any(String),
    })));
    expect(invoke.mock.calls.some(([cmd]) => cmd === 'agent_unlock_biometric')).toBe(false);

    const sessionId = lastAuthSessionId();
    emitTauriEvent('desktop-authentication', { sessionId, status: 'listening' } satisfies DesktopAuthenticationEvent);
    expect(screen.getByRole('status', { name: '解锁状态' }).textContent).toContain('输入下方 PIN');

    emitTauriEvent('desktop-authentication', { sessionId, status: 'failed', message: 'Touch ID 未匹配' } satisfies DesktopAuthenticationEvent);
    expect(screen.getByRole('status', { name: '解锁状态' }).textContent).toContain('Touch ID 未匹配');
    expect(screen.queryByRole('alert')).toBeNull();

    // Switching to Master Password updates Touch ID hint accurately.
    fireEvent.click(screen.getByRole('button', { name: '改用主密码' }));
    expect(screen.getByLabelText('主密码')).toBeTruthy();

    // Embedded Touch ID completion refreshes status and hides window.
    unlocked = true;
    fireEvent.click(screen.getByRole('button', { name: '重试 Touch ID' }));
    await waitFor(() => expect(invoke.mock.calls.filter(([cmd]) => cmd === 'desktop_authentication_begin')).toHaveLength(2));
    emitTauriEvent('desktop-authentication', { sessionId: lastAuthSessionId(), status: 'unlocked' } satisfies DesktopAuthenticationEvent);
    await waitFor(() => expect(hide).toHaveBeenCalledTimes(1));
  });

  it('shows a wrong-password error inline and submits password form on Enter', async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === 'desktop_authentication_status') return { supported: true, label: 'Touch ID' };
      if (command === 'agent_unlock_status') return agentStatus;
      if (command === 'agent_unlock_password') throw new Error('主密码不正确。');
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    const password = await screen.findByLabelText('主密码');
    fireEvent.change(password, { target: { value: 'wrong password value' } });
    fireEvent.submit(password.closest('form')!);

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('agent_unlock_password', {
      password: 'wrong password value',
    }));
    expect((await screen.findByRole('alert')).textContent).toContain('主密码不正确。');
  });

  it('renders unified Browser Session card without Agent scope switch, embeds Touch ID + Browser PIN, and cancels on 30s expiry', async () => {
    vi.useFakeTimers();
    let unlocked = false;
    invoke.mockImplementation(async (command: string) => {
      if (command === 'desktop_authentication_status') return { supported: true, label: 'Touch ID' };
      if (command === 'agent_unlock_status') {
        return unlocked ? { ...browserSessionPopupStatus, request: null } : browserSessionPopupStatus;
      }
      if (command === 'agent_unlock_pin') {
        unlocked = true;
        return { unlocked: true };
      }
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByText('解锁 VaultMesh 浏览器插件')).toBeTruthy();
    expect(screen.getByText(/在桌面端完成解锁以启用浏览器插件/)).toBeTruthy();
    expect(screen.queryByRole('switch', { name: '同一客户端只解锁一次' })).toBeNull();
    expect(screen.getByText('浏览器插件 PIN')).toBeTruthy();
    expect(invoke).toHaveBeenCalledWith('desktop_authentication_begin', expect.any(Object));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_200);
    });
    expect(invoke).toHaveBeenCalledWith('agent_unlock_cancel');
    expect(hide).toHaveBeenCalledTimes(1);
  });

  it('resets biometric state cleanly when unlockRef changes from a failed session to reprompt or another session', async () => {
    let current: BrowserUnlockTestStatus = {
      ...browserSessionPopupStatus,
      request: {
        ...browserSessionPopupStatus.request,
        source: 'autofill',
        origin: 'https://github.com',
        itemTitle: 'GitHub Work',
        itemKind: 'login',
      },
    };
    invoke.mockImplementation(async (command: string) => {
      if (command === 'desktop_authentication_status') return { supported: true, label: 'Touch ID' };
      if (command === 'agent_unlock_status') return current;
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('desktop_authentication_begin', expect.any(Object)));
    const firstSession = lastAuthSessionId();
    emitTauriEvent('desktop-authentication', { sessionId: firstSession, status: 'failed', message: '旧请求生物识别失败' } satisfies DesktopAuthenticationEvent);
    expect(screen.getByRole('status', { name: '解锁状态' }).textContent).toContain('旧请求生物识别失败');

    // Switch to a second browser-session request with new unlockRef -> must cancel old session and start new one without old failure.
    current = {
      ...current,
      request: { ...current.request, unlockRef: '66666666-6666-4666-8666-666666666666' },
    };
    emitTauriEvent('agent-unlock-requested');
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('desktop_authentication_cancel', { sessionId: firstSession }));
    await waitFor(() => expect(invoke.mock.calls.filter(([cmd]) => cmd === 'desktop_authentication_begin')).toHaveLength(2));
    expect(screen.getByRole('status', { name: '解锁状态' }).textContent).not.toContain('旧请求生物识别失败');

    // Switch to BrowserReprompt -> must cancel active Touch ID and force master password only.
    const secondSession = lastAuthSessionId();
    current = browserRepromptStatus;
    emitTauriEvent('agent-unlock-requested');
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('desktop_authentication_cancel', { sessionId: secondSession }));
    expect(await screen.findByText(/此条目受主密码保护，需要输入主密码确认填充/)).toBeTruthy();
    expect(screen.queryByLabelText('浏览器插件 PIN')).toBeNull();
    expect(screen.queryByRole('status', { name: '解锁状态' })).toBeNull();
    expect(screen.getByLabelText('主密码')).toBeTruthy();
  });

  it('CT-BROWSER-002: requires Master Password directly without quick-unlock factors when masterPasswordReprompt is true', async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === 'desktop_authentication_status') return { supported: true, label: 'Touch ID' };
      if (command === 'agent_unlock_status') return browserRepromptStatus;
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    expect(await screen.findByText('解锁 VaultMesh 浏览器插件')).toBeTruthy();
    expect(screen.getByText(/https:\/\/github\.com · Corporate Visa/)).toBeTruthy();
    expect(screen.getByText(/此条目受主密码保护，需要输入主密码确认填充/)).toBeTruthy();
    expect(invoke.mock.calls.some(([cmd]) => cmd === 'desktop_authentication_begin')).toBe(false);
    expect(screen.queryByRole('button', { name: /PIN/ })).toBeNull();
    expect(screen.getByLabelText('主密码')).toBeTruthy();
  });
});
