// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from 'react';
import { toast } from 'sonner';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SecurityCenterPage } from '../../src/renderer/src/pages/SecurityCenterPage';
import { AgentManagementPage } from '../../src/renderer/src/pages/AgentManagementPage';
import { useVaultStore } from '../../src/renderer/src/stores/vault-store';
import type { VaultMeshApi } from '../../src/shared/api';
import type { AgentBrokerStatus } from '../../src/shared/contracts';
import { DEFAULT_SECURITY_SETTINGS } from '../../src/shared/contracts';

vi.mock('sonner', () => ({
  toast: { error: vi.fn(), info: vi.fn(), success: vi.fn() },
}));
vi.mock('@/components/DesktopStartupCard', () => ({ DesktopStartupCard: () => null }));
vi.mock('@/components/DesktopBrowserIntegrationCard', () => ({ DesktopBrowserIntegrationCard: () => null }));
vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children }: { children: ReactNode }) => <>{children}</>,
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

const itemId = '11111111-1111-4111-8111-111111111111';
const status = {
  protocolVersion: 2,
  shimPath: '/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-agent-mcp',
  shimAvailable: true,
  confirmations: [],
  permissionRequests: [{
    permissionRef: '22222222-2222-4222-8222-222222222222',
    clientId: '33333333-3333-4333-8333-333333333333',
    sessionId: '44444444-4444-4444-8444-444444444444',
    accountRef: itemId,
    accountLabel: 'Example SSH',
    environment: 'production',
    tool: 'vaultmesh_ssh_exec',
    operation: 'hostname',
    risk: 'R1',
    approvedDisplay: '需要本地授权',
    actionDisplay: 'hostname',
    sourceItemRef: itemId,
    sourceItemKind: 'ssh',
    activationRequired: true,
    availableScopes: ['exact', 'safe', 'all'],
    availableAllowDurations: ['once', 'connection', 'permanent'],
    availableDenyDurations: ['once', 'connection', 'permanent'],
    recommendedScope: 'safe',
    recommendedDuration: 'connection',
    freshConfirmationRequired: false,
    createdAt: 1_700_000_000,
    expiresAt: 1_700_000_900,
  }],
  authorizationRules: [],
  auditEvents: [],
  clients: [],
  access: {
    hasVault: true,
    runtimeUnlocked: false,
    clientUnlocked: false,
    activeLeaseCount: 0,
    settings: { unlockScope: 'connection', idleTimeoutMs: 900000, maxUnlockDurationMs: 28800000 },
  },
  pin: { enabled: false, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 },
  tools: [],
} satisfies AgentBrokerStatus;

const initialStore = useVaultStore.getState();
describe('CT-AGENT-PERMISSION-001 system-generated session policy', () => {
  beforeEach(() => {
    useVaultStore.setState({
      items: [{
        id: itemId,
        title: 'Example login',
        username: 'ada',
        url: 'https://service.example.test/login',
        notes: null,
        hasPassword: true,
        hasTotpSecret: false,
        hasRecoveryCodes: false,
        autofillOnPageLoad: true,
        masterPasswordReprompt: false,
      }],
      cards: [],
      sshCredentials: [],
      identities: [],
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
        vault: { pinStatus: vi.fn().mockResolvedValue({ enabled: false, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 }) },
        browser: {
          pinStatus: vi.fn().mockResolvedValue({ enabled: false, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 }),
          enablePin: vi.fn(),
          disablePin: vi.fn(),
        },
        agent: {
          status: vi.fn().mockResolvedValue(status),
          pinStatus: vi.fn().mockResolvedValue({ enabled: false, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 }),
          enablePin: vi.fn(),
          disablePin: vi.fn(),
          activateAction: vi.fn().mockResolvedValue({
            request: status.permissionRequests[0],
            choice: { effect: 'allow', scope: 'exact', duration: 'connection' },
          }),
          resolvePermission: vi.fn().mockResolvedValue({
            request: status.permissionRequests[0],
            choice: { effect: 'allow', scope: 'exact', duration: 'connection' },
          }),
          resetAuthorizationRule: vi.fn().mockResolvedValue({ deleted: true }),
          updateAccessSettings: vi.fn().mockResolvedValue({ unlockScope: 'connection', idleTimeoutMs: 900000, maxUnlockDurationMs: 28800000 }),
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

  it('opens Agent management as a dedicated route instead of a dialog', async () => {
    render(<SecurityCenterPage />);

    const link = await screen.findByRole('link', { name: '管理 Agent 授权' });
    expect(link.getAttribute('href')).toBe('#/vault/security/agent');
    expect(screen.queryByRole('button', { name: '当前命令 · 当前连接' })).toBeNull();
  });

  it('approves the direct action without exposing a second account model or Vault format editor', async () => {
    render(<AgentManagementPage />);

    expect(await screen.findByRole('button', { name: '安全命令 · 本次连接' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '所有命令 · 本次连接' })).toBeTruthy();

    fireEvent.click(await screen.findByRole('button', { name: '当前命令 · 本次连接' }));

    await waitFor(() => expect(window.vaultMesh.agent.activateAction).toHaveBeenCalledWith(
      status.permissionRequests[0].permissionRef,
      { effect: 'allow', scope: 'exact', duration: 'connection' },
    ));
    expect(screen.queryByText(/加密账号配置/)).toBeNull();
    expect(screen.queryByText(/Vault format/)).toBeNull();
    expect(screen.queryByLabelText('固定站点 Origin')).toBeNull();
    expect(toast.success).toHaveBeenCalledWith('本次 Agent 连接可执行该精确命令。');
  });

  it('saves the independent Agent idle and absolute unlock limits', async () => {
    render(<AgentManagementPage />);

    fireEvent.click(await screen.findByRole('button', { name: '保存自动锁定策略' }));
    await waitFor(() => expect(window.vaultMesh.agent.updateAccessSettings).toHaveBeenCalledWith({
      unlockScope: 'connection',
      idleTimeoutMs: 900000,
      maxUnlockDurationMs: 28800000,
    }));
    expect(screen.getByText('系统锁屏、睡眠、撤销和退出仍会立即锁定；共享模式在客户端最后一条连接断开时锁定。')).toBeTruthy();
  });

  it('saves until-shutdown without disabling the idle or forced lock policy', async () => {
    const untilShutdownStatus: AgentBrokerStatus = {
      ...status,
      access: {
        ...status.access,
        settings: { unlockScope: 'connection', idleTimeoutMs: 900000, maxUnlockDurationMs: null },
      },
    };
    vi.mocked(window.vaultMesh.agent.status).mockResolvedValue(untilShutdownStatus);
    vi.mocked(window.vaultMesh.agent.updateAccessSettings).mockResolvedValue(
      untilShutdownStatus.access.settings,
    );
    render(<AgentManagementPage />);

    await waitFor(() => expect(
      document.getElementById('agent-max-unlock-duration')?.textContent,
    ).toContain('直到关机'));
    fireEvent.click(screen.getByRole('button', { name: '保存自动锁定策略' }));
    await waitFor(() => expect(window.vaultMesh.agent.updateAccessSettings).toHaveBeenCalledWith({
      unlockScope: 'connection',
      idleTimeoutMs: 900000,
      maxUnlockDurationMs: null,
    }));
    expect(screen.getByText('系统锁屏、睡眠、撤销和退出仍会立即锁定；共享模式在客户端最后一条连接断开时锁定。')).toBeTruthy();
  });

  it('shares one unlock only within the same paired client when enabled', async () => {
    render(<AgentManagementPage />);

    const sharing = await screen.findByRole('switch', { name: '同一客户端只解锁一次' });
    expect(sharing.getAttribute('data-state')).toBe('unchecked');
    fireEvent.click(sharing);
    fireEvent.click(screen.getByRole('button', { name: '保存自动锁定策略' }));
    await waitFor(() => expect(window.vaultMesh.agent.updateAccessSettings).toHaveBeenCalledWith({
      unlockScope: 'client',
      idleTimeoutMs: 900000,
      maxUnlockDurationMs: 28800000,
    }));
  });

  it('offers persistent exact, safe and all-command authorization choices', async () => {
    render(<AgentManagementPage />);

    expect(await screen.findByRole('button', { name: '当前命令 · 永久' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '安全命令 · 永久' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '所有命令 · 永久' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '安全命令 · 永久' }));

    await waitFor(() => expect(window.vaultMesh.agent.activateAction).toHaveBeenCalledWith(
      status.permissionRequests[0].permissionRef,
      { effect: 'allow', scope: 'safe', duration: 'permanent' },
    ));
  });

  it('offers connector-scoped website permission while preserving risk and hard policy', async () => {
    const request: AgentBrokerStatus['permissionRequests'][number] = {
      ...status.permissionRequests[0],
      sourceItemRef: null,
      sourceItemKind: null,
      activationRequired: false,
      tool: 'vaultmesh_http_request',
      operation: 'restart_service',
      risk: 'R2',
      approvedDisplay: 'https://api.example.test',
      actionDisplay: 'POST /service/restart',
      availableScopes: ['exact', 'all'],
    };
    vi.mocked(window.vaultMesh.agent.status).mockResolvedValue({
      ...status,
      permissionRequests: [request],
    });
    vi.mocked(window.vaultMesh.agent.resolvePermission).mockResolvedValue({
      request,
      choice: { effect: 'allow', scope: 'all', duration: 'permanent' },
    });
    render(<AgentManagementPage />);

    expect(await screen.findByRole('button', { name: '永久允许' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '此网站此能力 · 永久' }));

    await waitFor(() => expect(window.vaultMesh.agent.resolvePermission).toHaveBeenCalledWith(
      request.permissionRef,
      { effect: 'allow', scope: 'all', duration: 'permanent' },
    ));
    expect(toast.success).toHaveBeenCalledWith('已永久允许此网站此能力；风险等级和硬策略保持不变。');
  });

  it('offers native exact and wildcard path rules for a direct access-token Secret', async () => {
    const request: AgentBrokerStatus['permissionRequests'][number] = {
      ...status.permissionRequests[0],
      sourceItemKind: 'secret',
      tool: 'vaultmesh_http_request',
      operation: '/projects/42',
      risk: 'R1',
      approvedDisplay: 'https://api.example.test/v1/projects/42',
      actionDisplay: 'GET /projects/42',
      availableScopes: ['exact', 'path'],
      availablePathPatterns: ['/projects/42', '/projects/*', '/projects/**'],
      recommendedScope: 'path',
    };
    vi.mocked(window.vaultMesh.agent.status).mockResolvedValue({
      ...status,
      permissionRequests: [request],
    });
    vi.mocked(window.vaultMesh.agent.activateAction).mockResolvedValue({
      request,
      choice: {
        effect: 'allow',
        scope: 'path',
        duration: 'permanent',
        pathPattern: '/projects/*',
      },
    });
    render(<AgentManagementPage />);

    expect(await screen.findByText('VaultMesh 由 access-token Secret 固定 HTTPS 目标，Agent 只提交方法、路径和请求数据。')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '/projects/* · 永久' }));

    await waitFor(() => expect(window.vaultMesh.agent.activateAction).toHaveBeenCalledWith(
      request.permissionRef,
      {
        effect: 'allow',
        scope: 'path',
        duration: 'permanent',
        pathPattern: '/projects/*',
      },
    ));
    expect(toast.success).toHaveBeenCalledWith('已记住同方法路径规则 /projects/*。');
  });

  it('only offers exact once Allow for R4 while keeping persistent Deny', async () => {
    const request: AgentBrokerStatus['permissionRequests'][number] = {
      ...status.permissionRequests[0],
      risk: 'R4',
      availableScopes: ['exact'],
      availableAllowDurations: ['once'],
      availableDenyDurations: ['once', 'connection', 'permanent'],
      recommendedScope: 'exact',
      recommendedDuration: 'once',
      freshConfirmationRequired: true,
    };
    vi.mocked(window.vaultMesh.agent.status).mockResolvedValue({
      ...status,
      permissionRequests: [request],
    });
    render(<AgentManagementPage />);

    expect(await screen.findByRole('button', { name: '当前命令 · 一次' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: '当前命令 · 本次连接' })).toBeNull();
    expect(screen.queryByRole('button', { name: '当前命令 · 永久' })).toBeNull();
    expect(screen.getByRole('button', { name: '当前命令 · 永久拒绝' })).toBeTruthy();
  });

  it('lists and deletes persistent authorization rules', async () => {
    vi.mocked(window.vaultMesh.agent.status).mockResolvedValue({
      ...status,
      permissionRequests: [],
      authorizationRules: [{
        id: '55555555-5555-4555-8555-555555555555',
        clientKey: 'codex',
        accountRef: itemId,
        tool: 'vaultmesh_ssh_exec',
        scope: 'safe',
        effect: 'allow',
        createdAt: 1,
        updatedAt: 1,
      }],
    });
    render(<AgentManagementPage />);

    expect(await screen.findByText('永久允许 · 安全动作')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '删除规则' }));
    await waitFor(() => expect(window.vaultMesh.agent.resetAuthorizationRule).toHaveBeenCalledWith(
      '55555555-5555-4555-8555-555555555555',
    ));
  });
});
