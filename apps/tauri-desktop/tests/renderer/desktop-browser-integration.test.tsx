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
});
