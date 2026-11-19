// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from 'react';
import { toast } from 'sonner';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AgentManagementPage } from '../../src/renderer/src/pages/AgentManagementPage';
import { SecurityCenterPage } from '../../src/renderer/src/pages/SecurityCenterPage';
import { useVaultStore } from '../../src/renderer/src/stores/vault-store';
import type { VaultMeshApi } from '../../src/shared/api';
import { DEFAULT_SECURITY_SETTINGS, type PinStatus } from '../../src/shared/contracts';
import type { AgentBrokerStatus } from '../../src/shared/service-contracts';

vi.mock('sonner', () => ({
  toast: { error: vi.fn(), info: vi.fn(), success: vi.fn() },
}));
vi.mock('@/components/DesktopStartupCard', () => ({ DesktopStartupCard: () => null }));
vi.mock('@/components/DesktopBrowserIntegrationCard', () => ({ DesktopBrowserIntegrationCard: () => null }));
vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, onOpenChange }: { children: ReactNode; open?: boolean; onOpenChange?: (open: boolean) => void }) => (
    <div data-testid="mock-dialog">
      {onOpenChange ? (
        <button type="button" onClick={() => onOpenChange(false)}>模拟关闭弹窗</button>
      ) : null}
      {children}
    </div>
  ),
  DialogContent: ({ children, ...props }: HTMLAttributes<HTMLDivElement>) => <div {...props}>{children}</div>,
  DialogDescription: ({ children, ...props }: HTMLAttributes<HTMLParagraphElement>) => <p {...props}>{children}</p>,
  DialogFooter: ({ children, ...props }: HTMLAttributes<HTMLDivElement>) => <div {...props}>{children}</div>,
  DialogHeader: ({ children, ...props }: HTMLAttributes<HTMLDivElement>) => <div {...props}>{children}</div>,
  DialogTitle: ({ children, ...props }: HTMLAttributes<HTMLHeadingElement>) => <h2 {...props}>{children}</h2>,
  DialogTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
}));
vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children, ...props }: HTMLAttributes<HTMLDivElement>) => <div {...props}>{children}</div>,
}));
vi.mock('@/components/ui/switch', () => ({
  Switch: ({ checked, onCheckedChange, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & {
    checked?: boolean;
    onCheckedChange?: (checked: boolean) => void;
  }) => (
    <button
      {...props}
      type="button"
      role="switch"
      aria-checked={checked}
      data-state={checked ? 'checked' : 'unchecked'}
      onClick={() => onCheckedChange?.(!checked)}
    />
  ),
}));

const initialStore = useVaultStore.getState();

function makePinStatus(overrides: Partial<PinStatus> = {}): PinStatus {
  return {
    enabled: false,
    locked: false,
    failureLimit: 5,
    failedAttempts: 0,
    remainingAttempts: 5,
    ...overrides,
  };
}

const baseAgentStatus: AgentBrokerStatus = {
  protocolVersion: 2,
  shimPath: '/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-agent-mcp',
  shimAvailable: false,
  confirmations: [],
  permissionRequests: [],
  authorizationRules: [],
  auditEvents: [],
  clients: [],
  access: {
    hasVault: true,
    runtimeUnlocked: false,
    clientUnlocked: false,
    activeLeaseCount: 1,
    settings: { unlockScope: 'connection', idleTimeoutMs: 900000, maxUnlockDurationMs: 28800000 },
  },
  pin: makePinStatus(),
  tools: [],
};

describe('Unified 3-domain PIN settings in Security Center and Agent Management', () => {
  let desktopPin: PinStatus;
  let browserPin: PinStatus;
  let agentPin: PinStatus;

  beforeEach(() => {
    desktopPin = makePinStatus({ enabled: true, failureLimit: 5, remainingAttempts: 5 });
    browserPin = makePinStatus({ enabled: false, failureLimit: 5, remainingAttempts: 5 });
    agentPin = makePinStatus({ enabled: true, locked: true, failureLimit: 3, failedAttempts: 3, remainingAttempts: 0 });

    useVaultStore.setState({
      items: [],
      cards: [],
      sshCredentials: [],
      identities: [],
      secrets: [],
    });

    Object.defineProperty(window, 'vaultMesh', {
      configurable: true,
      value: {
        items: {
          passwordHealth: vi.fn().mockResolvedValue({ weakItemIds: [], reusedItemIds: [], oldItemIds: [], score: 100 }),
          trash: vi.fn().mockResolvedValue([]),
          history: vi.fn().mockResolvedValue([]),
        },
        cards: { trash: vi.fn().mockResolvedValue([]) },
        ssh: { trash: vi.fn().mockResolvedValue([]) },
        identities: { trash: vi.fn().mockResolvedValue([]) },
        security: { settings: vi.fn().mockResolvedValue(DEFAULT_SECURITY_SETTINGS) },
        vault: {
          pinStatus: vi.fn(async () => desktopPin),
          enablePin: vi.fn(async ({ failureLimit }: { pin: string; failureLimit: number }) => {
            desktopPin = makePinStatus({ enabled: true, failureLimit, remainingAttempts: failureLimit });
            return desktopPin;
          }),
          disablePin: vi.fn(async () => {
            desktopPin = makePinStatus({ enabled: false });
            return desktopPin;
          }),
          changeMasterPassword: vi.fn(async () => {
            return { hasVault: true, unlocked: false, itemCount: 0 };
          }),
        },
        browser: {
          pinStatus: vi.fn(async () => browserPin),
          enablePin: vi.fn(async ({ failureLimit }: { pin: string; failureLimit: number }) => {
            browserPin = makePinStatus({ enabled: true, failureLimit, remainingAttempts: failureLimit });
            return browserPin;
          }),
          disablePin: vi.fn(async () => {
            browserPin = makePinStatus({ enabled: false });
            return browserPin;
          }),
        },
        agent: {
          status: vi.fn(async () => ({ ...baseAgentStatus, pin: agentPin })),
          pinStatus: vi.fn(async () => agentPin),
          enablePin: vi.fn(async ({ failureLimit }: { pin: string; failureLimit: number }) => {
            agentPin = makePinStatus({ enabled: true, failureLimit, remainingAttempts: failureLimit });
            return agentPin;
          }),
          disablePin: vi.fn(async () => {
            agentPin = makePinStatus({ enabled: false });
            return agentPin;
          }),
          lockAllAccess: vi.fn().mockResolvedValue({ locked: true }),
          onPairingRequested: vi.fn().mockReturnValue(vi.fn()),
        },
      } as unknown as VaultMeshApi,
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    useVaultStore.setState(initialStore, true);
  });

  it('displays unified PIN 快速解锁 card with 3-domain summary and manages all 3 domains independently', async () => {
    render(<SecurityCenterPage />);

    expect((await screen.findAllByText('PIN 快速解锁')).length).toBeGreaterThanOrEqual(1);
    await waitFor(() => {
      const summary = screen.getByText(/桌面端已启用.*浏览器插件未启用.*Agent 工具已锁定/);
      expect(summary).toBeTruthy();
    });

    // Configure Desktop PIN (update & disable).
    const desktopPinInput = screen.getByLabelText('新 6 位 PIN') as HTMLInputElement;
    const desktopConfirmInput = screen.getByLabelText('确认 6 位 PIN') as HTMLInputElement;
    fireEvent.change(desktopPinInput, { target: { value: '123456' } });
    fireEvent.change(desktopConfirmInput, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: '更新 PIN' }));

    await waitFor(() => expect(window.vaultMesh.vault.enablePin).toHaveBeenCalledWith({
      pin: '123456',
      failureLimit: 5,
    }));
    expect(desktopPinInput.value).toBe('');
    expect(desktopConfirmInput.value).toBe('');

    // Switch to Browser PIN tab and enable Browser PIN.
    fireEvent.click(screen.getByRole('tab', { name: /浏览器插件/ }));
    const browserPinInput = await screen.findByLabelText('6 位 PIN') as HTMLInputElement;
    const browserConfirmInput = screen.getByLabelText('确认 6 位 PIN') as HTMLInputElement;
    fireEvent.change(browserPinInput, { target: { value: '654321' } });
    fireEvent.change(browserConfirmInput, { target: { value: '654321' } });
    fireEvent.click(screen.getByRole('button', { name: '启用 PIN 解锁' }));

    await waitFor(() => expect(window.vaultMesh.browser.enablePin).toHaveBeenCalledWith({
      pin: '654321',
      failureLimit: 5,
    }));
    expect(screen.getByText(/浏览器插件已启用/)).toBeTruthy();

    // Switch to Agent PIN tab, verify locked warning, and disable Agent PIN.
    fireEvent.click(screen.getByRole('tab', { name: /Agent 工具/ }));
    expect(await screen.findByText('Agent PIN已锁定')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '关闭 Agent PIN' }));

    await waitFor(() => expect(window.vaultMesh.agent.disablePin).toHaveBeenCalledOnce());
    await waitFor(() => expect(screen.getByText(/Agent 工具未启用/)).toBeTruthy());
  });

  it('clears PIN drafts when switching domain tabs, closing the dialog, or hiding the page', async () => {
    render(<SecurityCenterPage />);

    const desktopPinInput = await screen.findByLabelText('新 6 位 PIN') as HTMLInputElement;
    const desktopConfirmInput = screen.getByLabelText('确认 6 位 PIN') as HTMLInputElement;
    fireEvent.change(desktopPinInput, { target: { value: '112233' } });
    fireEvent.change(desktopConfirmInput, { target: { value: '112233' } });
    expect(desktopPinInput.value).toBe('112233');

    // Switching domain clears drafts.
    fireEvent.click(screen.getByRole('tab', { name: /浏览器插件/ }));
    expect((screen.getByLabelText('6 位 PIN') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('确认 6 位 PIN') as HTMLInputElement).value).toBe('');

    // Hiding the page clears drafts.
    fireEvent.change(screen.getByLabelText('6 位 PIN'), { target: { value: '445566' } });
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
    act(() => { document.dispatchEvent(new Event('visibilitychange')); });
    expect((screen.getByLabelText('6 位 PIN') as HTMLInputElement).value).toBe('');
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });

    // Closing dialog clears drafts.
    fireEvent.change(screen.getByLabelText('6 位 PIN'), { target: { value: '778899' } });
    for (const button of screen.getAllByRole('button', { name: '模拟关闭弹窗' })) {
      fireEvent.click(button);
    }
    expect((screen.getByLabelText('6 位 PIN') as HTMLInputElement).value).toBe('');

    // pagehide clears drafts and mismatched confirmation clears drafts without calling enablePin.
    fireEvent.change(screen.getByLabelText('6 位 PIN'), { target: { value: '135790' } });
    act(() => { window.dispatchEvent(new Event('pagehide')); });
    expect((screen.getByLabelText('6 位 PIN') as HTMLInputElement).value).toBe('');

    fireEvent.change(screen.getByLabelText('6 位 PIN'), { target: { value: '123456' } });
    fireEvent.change(screen.getByLabelText('确认 6 位 PIN'), { target: { value: '654321' } });
    fireEvent.submit((screen.getByLabelText('6 位 PIN') as HTMLInputElement).closest('form')!);
    expect(toast.error).toHaveBeenCalledWith('两次输入的 PIN 不一致。');
    expect(window.vaultMesh.browser.enablePin).not.toHaveBeenCalled();
    expect((screen.getByLabelText('6 位 PIN') as HTMLInputElement).value).toBe('');
  });

  it('preserves quick unlock PIN statuses without refreshing after changing master password', async () => {
    browserPin = makePinStatus({ enabled: true, failureLimit: 5, remainingAttempts: 5 });
    render(<SecurityCenterPage />);

    await waitFor(() => expect(screen.getByText(/桌面端已启用.*浏览器插件已启用.*Agent 工具已锁定/)).toBeTruthy());

    fireEvent.change(screen.getByLabelText('当前主密码'), { target: { value: 'old-master-password' } });
    fireEvent.change(screen.getByLabelText('新主密码'), { target: { value: 'new-master-password' } });
    fireEvent.change(screen.getByLabelText('确认新主密码'), { target: { value: 'new-master-password' } });
    fireEvent.click(screen.getByRole('button', { name: '更新主密码' }));

    await waitFor(() => expect(window.vaultMesh.vault.changeMasterPassword).toHaveBeenCalledOnce());
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('主密码已更新，所有端已锁定，请重新解锁。'));
    expect(window.vaultMesh.vault.pinStatus).toHaveBeenCalledOnce();
    expect(window.vaultMesh.browser.pinStatus).toHaveBeenCalledOnce();
    expect(window.vaultMesh.agent.pinStatus).toHaveBeenCalledOnce();
    expect(screen.getByText(/桌面端已启用.*浏览器插件已启用.*Agent 工具已锁定/)).toBeTruthy();
  });

  it('reuses PinDomainSettingsForm inside AgentManagementPage without duplicate form logic and zeroes leases on agent PIN change', async () => {
    vi.mocked(window.vaultMesh.agent.status).mockResolvedValueOnce({
      ...baseAgentStatus,
      pin: agentPin,
      access: { ...baseAgentStatus.access, clientUnlocked: true, activeLeaseCount: 2 },
    });
    render(<AgentManagementPage />);

    expect(await screen.findByText('独立 MCP 解锁')).toBeTruthy();
    expect(screen.getByText('Agent PIN已锁定')).toBeTruthy();
    const lockAllButton = screen.getByRole('button', { name: '锁定全部 MCP 连接' }) as HTMLButtonElement;
    expect(lockAllButton.disabled).toBe(false);

    const pinInput = screen.getByLabelText('新 6 位 PIN') as HTMLInputElement;
    const confirmInput = screen.getByLabelText('确认 6 位 PIN') as HTMLInputElement;
    fireEvent.change(pinInput, { target: { value: '246810' } });
    fireEvent.change(confirmInput, { target: { value: '246810' } });
    fireEvent.click(screen.getByRole('button', { name: '更新 PIN' }));

    await waitFor(() => expect(window.vaultMesh.agent.enablePin).toHaveBeenCalledWith({
      pin: '246810',
      failureLimit: 3,
    }));
    await waitFor(() => expect(lockAllButton.disabled).toBe(true));
    expect(screen.getByText(/0 条 MCP 解锁租约/)).toBeTruthy();
    expect(toast.success).toHaveBeenCalledWith(expect.stringContaining('Agent 已锁定。'));
  });
});
