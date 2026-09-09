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
  nearby: [],
  pending: [],
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
          confirm: vi.fn().mockResolvedValue({ resolved: true }),
          cancel: vi.fn().mockResolvedValue({ resolved: true }),
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

  it('shows an in-flight pairing immediately and prevents a duplicate begin', async () => {
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
    expect(await screen.findByText('正在配对')).toBeTruthy();
    expect(screen.queryByRole('button', { name: '配对' })).toBeNull();
    expect(window.vaultMesh.lan.begin).toHaveBeenCalledOnce();
  });

  it('returns a failed pre-prompt handshake to a visible retry action', async () => {
    const pairingRef = 'lan-peer-00112233445566778899aabbccddeeff';
    vi.mocked(window.vaultMesh.lan.status).mockResolvedValue({
      ...emptyStatus,
      discoverable: true,
      expiresAt: Date.now() + 60_000,
      nearby: [{ pairingRef, status: 'failed' }],
    });
    render(<NearbyDevicesPage />);

    expect(await screen.findByText('配对未完成，请重试')).toBeTruthy();
    expect(screen.getByRole('button', { name: '配对' })).toBeTruthy();
  });

  it('shows the Bluetooth-style wait state after this device confirms', async () => {
    const pairingRef = 'lan-peer-00112233445566778899aabbccddeeff';
    vi.mocked(window.vaultMesh.lan.status).mockResolvedValue({
      ...emptyStatus,
      discoverable: true,
      expiresAt: Date.now() + 60_000,
      nearby: [{ pairingRef, status: 'confirming' }],
    });
    render(<NearbyDevicesPage />);

    expect(await screen.findByText('本机已确认，正在等待另一台设备')).toBeTruthy();
    expect(screen.getByText('等待确认')).toBeTruthy();
    expect(screen.queryByRole('button', { name: '配对' })).toBeNull();
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

  it('shows only the six-digit comparison code and routes both decisions by opaque peer ref', async () => {
    const pairingRef = 'lan-peer-00112233445566778899aabbccddeeff';
    vi.mocked(window.vaultMesh.lan.status).mockResolvedValue({
      ...emptyStatus,
      discoverable: true,
      expiresAt: Date.now() + 60_000,
      pending: [{ pairingRef, safetyCode: '482913', expiresAt: Date.now() + 60_000 }],
    });
    render(<NearbyDevicesPage />);

    expect(await screen.findByText('482913')).toBeTruthy();
    expect(screen.getByText(/蓝牙数字比较/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '短码一致' }));
    await waitFor(() => expect(window.vaultMesh.lan.confirm).toHaveBeenCalledWith(pairingRef));

    vi.mocked(window.vaultMesh.lan.status).mockResolvedValue({
      ...emptyStatus,
      discoverable: true,
      expiresAt: Date.now() + 60_000,
      pending: [{ pairingRef, safetyCode: '482913', expiresAt: Date.now() + 60_000 }],
    });
    fireEvent.click(screen.getByRole('button', { name: '取消' }));
    await waitFor(() => expect(window.vaultMesh.lan.cancel).toHaveBeenCalledWith(pairingRef));

    expect(document.body.textContent).not.toMatch(/192\.168\.|证书指纹|公钥|TLS exporter/i);
  });
});
