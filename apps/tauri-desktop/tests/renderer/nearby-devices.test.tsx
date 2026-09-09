// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { NearbyDevicesPage } from '../../src/renderer/src/pages/NearbyDevicesPage';
import { keepsIndependentPageOnVaultLock } from '../../src/renderer/src/App';
import type { VaultMeshApi } from '../../src/shared/api';
import type { LanPairingStatus } from '../../src/shared/contracts';

vi.mock('sonner', () => ({
  toast: { error: vi.fn(), success: vi.fn() },
}));

const emptyStatus: LanPairingStatus = {
  discoverable: false,
  expiresAt: null,
  pairingCode: null,
  nearby: [],
  trusted: [],
};

describe('CT-LAN-PAIRING-001 nearby devices UI', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'vaultMesh', {
      configurable: true,
      value: {
        lan: {
          status: vi.fn().mockResolvedValue(emptyStatus),
          startDiscovery: vi.fn().mockResolvedValue({
            ...emptyStatus,
            discoverable: true,
            expiresAt: Date.now() + 600_000,
          }),
          stopDiscovery: vi.fn().mockResolvedValue(emptyStatus),
          scan: vi.fn().mockResolvedValue(emptyStatus),
          listTrusted: vi.fn().mockResolvedValue([]),
          begin: vi.fn().mockResolvedValue({ started: true }),
          rename: vi.fn().mockResolvedValue({ renamed: true }),
          revoke: vi.fn().mockResolvedValue({ revoked: true }),
        },
      } as unknown as VaultMeshApi,
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('keeps only the non-secret nearby page mounted when the Vault locks', () => {
    expect(keepsIndependentPageOnVaultLock('/nearby')).toBe(true);
    expect(keepsIndependentPageOnVaultLock('/vault')).toBe(false);
    expect(keepsIndependentPageOnVaultLock('/vault/security')).toBe(false);
  });

  it('starts only on explicit action and stops discovery when the page closes', async () => {
    const view = render(<NearbyDevicesPage />);
    const start = await screen.findByRole('button', { name: '开启 10 分钟' });
    expect(window.vaultMesh.lan.startDiscovery).not.toHaveBeenCalled();

    fireEvent.click(start);
    await waitFor(() => expect(window.vaultMesh.lan.startDiscovery).toHaveBeenCalledOnce());

    view.unmount();
    await waitFor(() => expect(window.vaultMesh.lan.stopDiscovery).toHaveBeenCalledOnce());
  });

  it('requires the displayed six-digit code before starting a pairing', async () => {
    const pairingRef = 'lan-peer-00112233445566778899aabbccddeeff';
    const discovered: LanPairingStatus = {
      ...emptyStatus,
      discoverable: true,
      expiresAt: Date.now() + 60_000,
      nearby: [{ pairingRef, status: 'unverified' }],
    };
    vi.mocked(window.vaultMesh.lan.status)
      .mockResolvedValueOnce(discovered)
      .mockResolvedValue({
        ...discovered,
        nearby: [{ pairingRef, status: 'connecting' }],
      });
    render(<NearbyDevicesPage />);

    fireEvent.click(await screen.findByRole('button', { name: '配对' }));
    expect(window.vaultMesh.lan.begin).not.toHaveBeenCalled();
    const input = screen.getByRole('textbox', { name: '六位配对码' });
    fireEvent.change(input, { target: { value: '12a3456' } });
    expect((input as HTMLInputElement).value).toBe('123456');
    fireEvent.click(screen.getByRole('button', { name: '开始配对' }));
    await waitFor(() => expect(window.vaultMesh.lan.begin).toHaveBeenCalledWith(pairingRef, '123456'));
    expect(await screen.findByText('正在配对')).toBeTruthy();
    expect(screen.queryByRole('button', { name: '配对' })).toBeNull();
  });

  it('returns transport, TLS, and identity failures to actionable retry states', async () => {
    const pairingRef = 'lan-peer-00112233445566778899aabbccddeeff';
    vi.mocked(window.vaultMesh.lan.status).mockResolvedValue({
      ...emptyStatus,
      discoverable: true,
      expiresAt: Date.now() + 60_000,
      nearby: [
        { pairingRef, status: 'transport-failed' },
        { pairingRef: 'lan-peer-ffeeddccbbaa99887766554433221100', status: 'tls-failed' },
        { pairingRef: 'lan-peer-aabbccddeeff00112233445566778899', status: 'peer-identity-rejected' },
      ],
    });
    render(<NearbyDevicesPage />);

    expect(await screen.findByText('无法连接该设备，请检查双方防火墙和局域网访问权限')).toBeTruthy();
    expect(screen.getByText('TLS 握手失败，请检查系统时间和安全软件')).toBeTruthy();
    expect(screen.getByText('另一台设备拒绝了本机身份，请在对端撤销旧信任')).toBeTruthy();
    expect(screen.getAllByRole('button', { name: '配对' })).toHaveLength(3);
  });

  it('shows an explicit rejected-code state and allows retry', async () => {
    const pairingRef = 'lan-peer-00112233445566778899aabbccddeeff';
    vi.mocked(window.vaultMesh.lan.status).mockResolvedValue({
      ...emptyStatus,
      discoverable: true,
      expiresAt: Date.now() + 60_000,
      nearby: [{ pairingRef, status: 'code-rejected' }],
    });
    render(<NearbyDevicesPage />);

    expect(await screen.findByText('配对码不正确或安全验证失败')).toBeTruthy();
    expect(screen.getByRole('button', { name: '配对' })).toBeTruthy();
  });

  it('distinguishes local and peer trust-storage failures without exposing internals', async () => {
    vi.mocked(window.vaultMesh.lan.status).mockResolvedValue({
      ...emptyStatus,
      discoverable: true,
      expiresAt: Date.now() + 60_000,
      nearby: [
        { pairingRef: 'lan-peer-00112233445566778899aabbccddeeff', status: 'local-storage-failed' },
        { pairingRef: 'lan-peer-ffeeddccbbaa99887766554433221100', status: 'peer-storage-failed' },
      ],
    });
    render(<NearbyDevicesPage />);

    expect(await screen.findByText('本机无法安全保存设备信任')).toBeTruthy();
    expect(screen.getByText('另一台设备无法安全保存信任')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/DACL|Keychain|Credential Manager|fingerprint/i);
  });

  it('shows only this discovery window code and never exposes network or PAKE material', async () => {
    const pairingRef = 'lan-peer-00112233445566778899aabbccddeeff';
    vi.mocked(window.vaultMesh.lan.status).mockResolvedValue({
      ...emptyStatus,
      discoverable: true,
      expiresAt: Date.now() + 60_000,
      pairingCode: '482913',
      nearby: [{ pairingRef, status: 'unverified' }],
    });
    render(<NearbyDevicesPage />);

    expect(await screen.findByText('482913')).toBeTruthy();
    expect(screen.getByText(/验证成功后会自动完成配对/)).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/192\.168\.|证书指纹|公钥|TLS exporter|PAKE/i);
  });
});
