// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { toast } from 'sonner';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DesktopBrowserIntegrationCard } from '../../src/renderer/src/components/DesktopBrowserIntegrationCard';
import type { VaultMeshApi } from '../../src/shared/api';

vi.mock('sonner', () => ({
  toast: { error: vi.fn(), success: vi.fn() },
}));

const unavailable = {
  supported: true,
  ready: false,
  brokerReady: true,
  hostRegistered: false,
  extensionId: 'bdneegbnjbheblmamalplnddbodcghbg',
  errorCode: 'registration-unavailable' as const,
};

describe('CT-TAURI-BROWSER-001 Windows browser integration diagnostics', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'vaultMesh', {
      configurable: true,
      value: {
        desktop: {
          browserIntegrationStatus: vi.fn().mockResolvedValue(unavailable),
          retryBrowserIntegration: vi.fn().mockResolvedValue({
            ...unavailable,
            ready: true,
            hostRegistered: true,
            errorCode: null,
          }),
        },
      } as unknown as VaultMeshApi,
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('shows a stable failure category and repairs registration without exposing paths', async () => {
    render(<DesktopBrowserIntegrationCard />);
    expect(await screen.findByText('无法注册 Chrome/Edge Browser Native Host。')).toBeTruthy();
    expect(screen.queryByText(/HKCU|AppData|browser-pairing/i)).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: '重新检查并修复' }));

    await waitFor(() => expect(window.vaultMesh.desktop.retryBrowserIntegration).toHaveBeenCalledOnce());
    await waitFor(() => expect(screen.getByText('Chrome/Edge 插件连接服务已就绪。')).toBeTruthy());
    expect(toast.success).toHaveBeenCalledWith('Chrome/Edge 插件连接服务已就绪。');
  });

  it('does not render the Windows-only card on other platforms', async () => {
    vi.mocked(window.vaultMesh.desktop.browserIntegrationStatus).mockResolvedValue({
      supported: false,
      ready: false,
      brokerReady: false,
      hostRegistered: false,
      extensionId: '',
      errorCode: null,
    });
    const view = render(<DesktopBrowserIntegrationCard />);
    await waitFor(() => expect(view.container.firstChild).toBeNull());
  });

  it('renders Doctor check items and opens store when browser has no extension installed', async () => {
    const doctorReport = {
      supported: true,
      ready: false,
      brokerReady: true,
      hostRegistered: true,
      extensionId: 'bdneegbnjbheblmamalplnddbodcghbg',
      errorCode: null,
      apiPort: 42800,
      checkItems: [
        {
          id: 'loopback-api',
          label: '本地回环 API 服务',
          status: 'ok' as const,
          message: '服务运行正常（端口: 42800）',
        },
        {
          id: 'extension-install',
          label: '浏览器插件安装',
          status: 'warn' as const,
          message: '检测到已安装浏览器但尚未安装 VaultMesh 扩展',
        },
      ],
      browsers: [
        {
          id: 'chrome',
          name: 'Google Chrome',
          installed: true,
          manifestRegistered: true,
          manifestPath: '/tmp/chrome.json',
          extensionInstalled: false,
          storeUrl: 'https://chromewebstore.google.com/...',
        },
        {
          id: 'edge',
          name: 'Microsoft Edge',
          installed: true,
          manifestRegistered: true,
          manifestPath: '/tmp/edge.json',
          extensionInstalled: false,
          storeUrl: 'https://github.com/atlantis-mk/VaultMesh/releases/tag/v0.1.7-review',
        },
        {
          id: 'firefox',
          name: 'Mozilla Firefox',
          installed: false,
          manifestRegistered: false,
          manifestPath: null,
          extensionInstalled: false,
          storeUrl: 'https://github.com/atlantis-mk/VaultMesh/releases/tag/v0.1.7-review',
        },
      ],
    };

    const openBrowserStore = vi.fn().mockResolvedValue({ opened: true });
    Object.defineProperty(window, 'vaultMesh', {
      configurable: true,
      value: {
        desktop: {
          browserIntegrationStatus: vi.fn().mockResolvedValue(doctorReport),
          retryBrowserIntegration: vi.fn(),
          openBrowserStore,
        },
      } as unknown as VaultMeshApi,
    });

    render(<DesktopBrowserIntegrationCard />);

    expect(await screen.findByText('Doctor 连通性体检')).toBeTruthy();
    expect(screen.getByText('本地回环 API 服务:')).toBeTruthy();
    expect(screen.getByText('服务运行正常（端口: 42800）')).toBeTruthy();

    expect(screen.getByText('Google Chrome')).toBeTruthy();
    expect(screen.getByText('Microsoft Edge')).toBeTruthy();
    expect(screen.getByText('未安装此浏览器')).toBeTruthy();

    const chromeBtn = screen.getByRole('button', { name: '去插件市场安装' });
    fireEvent.click(chromeBtn);
    await waitFor(() => expect(openBrowserStore).toHaveBeenCalledWith('chrome'));

    const edgeBtn = screen.getByRole('button', { name: '前往 Release 下载' });
    fireEvent.click(edgeBtn);
    await waitFor(() => expect(openBrowserStore).toHaveBeenCalledWith('edge'));
  });
});
