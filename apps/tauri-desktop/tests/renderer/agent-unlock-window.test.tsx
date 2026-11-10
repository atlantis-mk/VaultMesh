// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AgentUnlockWindow } from '../../src/agent-unlock';

const { hide, invoke, listeners } = vi.hoisted(() => ({
  hide: vi.fn(),
  invoke: vi.fn(),
  listeners: new Map<string, () => void>(),
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke }));
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (event: string, callback: () => void) => {
    listeners.set(event, callback);
    return () => listeners.delete(event);
  }),
}));
vi.mock('@tauri-apps/api/window', () => ({ getCurrentWindow: () => ({ hide }) }));
vi.mock('../../src/renderer/src/components/ui/switch', () => ({
  Switch: ({ checked, onCheckedChange, ...props }: { checked: boolean; onCheckedChange: (checked: boolean) => void; id?: string; disabled?: boolean }) => (
    <button type="button" role="switch" aria-checked={checked} onClick={() => onCheckedChange(!checked)} {...props} />
  ),
}));

const status = {
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

const browserAutofillStatus = {
  request: {
    kind: 'browser-autofill' as const,
    unlockRef: '44444444-4444-4444-8444-444444444444',
    origin: 'https://github.com',
    itemTitle: 'GitHub Work',
    itemKind: 'login' as const,
    masterPasswordReprompt: false,
    createdAt: 2_000,
    expiresAt: 32_000,
  },
  access: {
    hasVault: true,
    clientUnlocked: false,
    settings: { unlockScope: 'connection' as const },
  },
  pin: { enabled: true, locked: false, remainingAttempts: 5 },
  biometric: { available: true, enabled: true, kind: 'touchId' as const },
};

describe('CT-AGENT-UNLOCK-001 & AT-AUTOFILL-001 unified temporary unlock window', () => {
  beforeEach(() => {
    vi.stubGlobal('ResizeObserver', class {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    });
    invoke.mockReset();
    hide.mockReset();
    listeners.clear();
    let statusReads = 0;
    invoke.mockImplementation(async (command: string) => {
      if (command === 'agent_unlock_status') {
        statusReads += 1;
        return statusReads === 1 ? status : { ...status, request: null };
      }
      return { unlocked: true };
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    cleanup();
    vi.unstubAllGlobals();
  });

  it('binds the factor to the displayed MCP connection and hides after success', async () => {
    const { container } = render(<AgentUnlockWindow />);

    const title = await screen.findByText('解锁 codex 的 MCP 访问');
    expect(title.parentElement?.querySelector('svg')).toBeTruthy();
    expect(container.querySelector('[data-slot^="card"]')).toBeNull();
    expect(container.querySelector('main')?.className).toContain('min-h-svh');
    expect(container.querySelector('main > footer')).toBeTruthy();
    expect(screen.getByText(/只授权当前 MCP 连接/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText('主密码'), {
      target: { value: 'correct horse battery staple' },
    });
    fireEvent.click(screen.getByRole('button', { name: '解锁 MCP' }));

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('agent_unlock_password', {
      password: 'correct horse battery staple',
    }));
    await waitFor(() => expect(hide).toHaveBeenCalled());
  });

  it('AT-AGENT-UNLOCK-001: cancels the expired request and automatically hides the window when agent-unlock-expired fires', async () => {
    render(<AgentUnlockWindow />);

    expect(await screen.findByText('解锁 codex 的 MCP 访问')).toBeTruthy();
    await waitFor(() => expect(listeners.has('agent-unlock-expired')).toBe(true));
    await act(async () => {
      listeners.get('agent-unlock-expired')?.();
    });

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('agent_unlock_cancel'));
    await waitFor(() => expect(hide).toHaveBeenCalledTimes(1));
  });

  it('AT-AGENT-UNLOCK-001: automatically cancels and hides the window when the 30s countdown reaches zero', async () => {
    vi.useFakeTimers();
    render(<AgentUnlockWindow />);

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByText('解锁 codex 的 MCP 访问')).toBeTruthy();
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
      if (command === 'agent_unlock_status') {
        statusReads += 1;
        return statusReads === 1 ? status : { ...browserAutofillStatus, biometric: { available: false, enabled: false, kind: null } };
      }
      return { cancelled: true };
    });

    render(<AgentUnlockWindow />);

    expect(await screen.findByText('解锁 codex 的 MCP 访问')).toBeTruthy();
    await waitFor(() => expect(listeners.has('agent-unlock-expired')).toBe(true));
    await act(async () => {
      listeners.get('agent-unlock-expired')?.();
    });

    expect(await screen.findByText('解锁自动填充 · GitHub Work')).toBeTruthy();
    expect(hide).not.toHaveBeenCalled();
  });

  it('can share one unlock with parallel connections of the same paired client', async () => {
    invoke.mockImplementation(async (command: string, input?: { scope?: string }) => {
      if (command === 'agent_unlock_status') return status;
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

  it('centers the Agent PIN label and input', async () => {
    vi.stubGlobal('ResizeObserver', class {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    });
    invoke.mockImplementation(async (command: string) => {
      if (command === 'agent_unlock_status') {
        return { ...status, pin: { enabled: true, locked: false, remainingAttempts: 5 } };
      }
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    const label = await screen.findByText('Agent 专用 PIN');
    expect(label.className).toContain('justify-center');
    expect(document.querySelector('.cn-input-otp.justify-center')).toBeTruthy();
  });

  it('automatically tries Agent Touch ID once and keeps the master-password fallback visible', async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === 'agent_unlock_status') {
        return {
          ...status,
          pin: { enabled: true, locked: false, remainingAttempts: 5 },
          biometric: { available: true, enabled: true, kind: 'touchId' },
        };
      }
      if (command === 'agent_unlock_biometric') throw new Error('Touch ID 验证未完成。');
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    expect(await screen.findByLabelText('主密码')).toBeTruthy();
    expect(screen.queryByLabelText('Agent 专用 PIN')).toBeNull();
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('agent_unlock_biometric'));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Touch ID 验证未完成。'));
    expect(invoke.mock.calls.filter(([command]) => command === 'agent_unlock_biometric')).toHaveLength(1);
  });

  it('shows a wrong-password error and submits the password form used by Enter', async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === 'agent_unlock_status') return status;
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

  it('AT-AUTOFILL-001 / CT-BROWSER-002: renders browser one-shot autofill context, hides Agent scope switch, auto-triggers Touch ID, and falls back to Desktop PIN / Master Password', async () => {
    vi.stubGlobal('ResizeObserver', class {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    });
    let unlocked = false;
    invoke.mockImplementation(async (command: string) => {
      if (command === 'agent_unlock_status') {
        return unlocked ? { ...browserAutofillStatus, request: null } : browserAutofillStatus;
      }
      if (command === 'agent_unlock_biometric') {
        throw new Error('Touch ID 已取消。');
      }
      if (command === 'agent_unlock_password') {
        unlocked = true;
        return { unlocked: true };
      }
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    expect(await screen.findByText('解锁自动填充 · GitHub Work')).toBeTruthy();
    expect(screen.getByText(/仅填充当前网页（https:\/\/github\.com）的所选凭据/)).toBeTruthy();
    expect(screen.queryByRole('switch', { name: '同一客户端只解锁一次' })).toBeNull();

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('agent_unlock_biometric'));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Touch ID 已取消。'));

    expect(screen.getByRole('button', { name: '改用桌面端 PIN' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '改用桌面端 PIN' }));
    expect(await screen.findByText('桌面端 PIN')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: '改用主密码' }));
    const password = await screen.findByLabelText('主密码');
    fireEvent.change(password, { target: { value: 'correct horse battery staple' } });
    fireEvent.click(screen.getByRole('button', { name: '解锁并填充' }));

    await waitFor(() => expect(invoke).toHaveBeenCalledWith('agent_unlock_password', {
      password: 'correct horse battery staple',
    }));
    await waitFor(() => expect(hide).toHaveBeenCalledTimes(1));
  });

  it('CT-BROWSER-002: requires Master Password directly without quick-unlock factors when masterPasswordReprompt is true', async () => {
    invoke.mockImplementation(async (command: string) => {
      if (command === 'agent_unlock_status') {
        return {
          ...browserAutofillStatus,
          request: {
            ...browserAutofillStatus.request,
            itemTitle: 'Corporate Visa',
            itemKind: 'card' as const,
            masterPasswordReprompt: true,
          },
          pin: { enabled: false, locked: false, remainingAttempts: 0 },
          biometric: { available: false, enabled: false, kind: null },
        };
      }
      return { unlocked: true };
    });

    render(<AgentUnlockWindow />);

    expect(await screen.findByText('解锁自动填充 · Corporate Visa')).toBeTruthy();
    expect(screen.getByText(/此条目受主密码保护，需要输入主密码确认填充/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Touch ID/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /PIN/ })).toBeNull();
    expect(screen.getByLabelText('主密码')).toBeTruthy();
  });
});
