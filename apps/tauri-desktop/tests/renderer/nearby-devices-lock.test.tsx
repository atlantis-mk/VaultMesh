import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { createMemoryHistory } from '@tanstack/react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../../src/renderer/src/App';
import { router } from '../../src/renderer/src/routes';
import { useVaultStore } from '../../src/renderer/src/stores/vault-store';
import type { VaultMeshApi } from '../../src/shared/api';
import type { LanPairingStatus, VaultStatus } from '../../src/shared/contracts';

const initialStore = useVaultStore.getInitialState();
const activeDiscovery: LanPairingStatus = {
  discoverable: true,
  expiresAt: Date.now() + 600_000,
  pairingCode: '482913',
  nearby: [],
  trusted: [{ pairingRef: 'lan-peer-00112233445566778899aabbccddeeff', label: 'Test peer', protocolMajor: 1 }],
};
let vaultStatus: VaultStatus;
let onLocked: () => void;

describe('CT-LAN-PAIRING-001 nearby page requires desktop unlock', () => {
  beforeEach(() => {
    vi.spyOn(window, 'scrollTo').mockImplementation(() => undefined);
    useVaultStore.setState(initialStore, true);
    vaultStatus = { hasVault: true, unlocked: true, itemCount: 0 };
    router.update({ history: createMemoryHistory({ initialEntries: ['/nearby'] }) });
    Object.defineProperty(window, 'vaultMesh', {
      configurable: true,
      value: {
        activity: vi.fn(),
        vault: {
          status: vi.fn(async () => vaultStatus),
          biometricStatus: vi.fn().mockResolvedValue(null),
          pinStatus: vi.fn().mockResolvedValue(null),
          onChanged: vi.fn(() => vi.fn()),
          onLocked: vi.fn((listener: () => void) => { onLocked = listener; return vi.fn(); }),
          lock: vi.fn(async () => { vaultStatus = { ...vaultStatus, unlocked: false }; return vaultStatus; }),
          unlock: vi.fn(async () => {
            vaultStatus = { ...vaultStatus, unlocked: true };
            return { cancelled: false, status: vaultStatus };
          }),
        },
        items: { list: vi.fn().mockResolvedValue([]) },
        cards: { list: vi.fn().mockResolvedValue([]) },
        ssh: { list: vi.fn().mockResolvedValue([]) },
        identities: { list: vi.fn().mockResolvedValue([]) },
        secrets: { list: vi.fn().mockResolvedValue([]) },
        lan: {
          syncStatus: vi.fn().mockResolvedValue({ peers: [], conflictCount: 0 }),
          syncConflicts: vi.fn().mockResolvedValue([]),
          status: vi.fn().mockResolvedValue(activeDiscovery),
          stopDiscovery: vi.fn().mockResolvedValue({ ...activeDiscovery, discoverable: false, pairingCode: null }),
        },
      } as unknown as VaultMeshApi,
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    useVaultStore.setState(initialStore, true);
  });

  async function expectUnlockPage() {
    await waitFor(() => expect(router.state.location.pathname).toBe('/unlock'));
    expect(await screen.findByText('解锁 VaultMesh')).toBeTruthy();
    expect(screen.queryByRole('region', { name: '附近设备管理' })).toBeNull();
    expect(screen.queryByText('482913')).toBeNull();
    expect(screen.queryByText('Test peer')).toBeNull();
  }

  it('blocks direct entry while locked without loading device data', async () => {
    vaultStatus = { ...vaultStatus, unlocked: false };
    render(<App />);
    await expectUnlockPage();
    expect(window.vaultMesh.lan.status).not.toHaveBeenCalled();

    await act(async () => { await router.navigate({ to: '/nearby' }); });
    await expectUnlockPage();
    expect(window.vaultMesh.lan.status).not.toHaveBeenCalled();
  });

  it('allows the nearby page after desktop unlock', async () => {
    vaultStatus = { ...vaultStatus, unlocked: false };
    render(<App />);
    await expectUnlockPage();
    await act(async () => {
      expect(await useVaultStore.getState().unlockVault('test-only-password')).toBe(true);
      await router.navigate({ to: '/nearby' });
    });
    expect(await screen.findByText('482913')).toBeTruthy();
    expect(screen.getAllByText('Test peer')).toHaveLength(2);
    expect(router.state.location.pathname).toBe('/nearby');
  });

  it.each(['event', 'focus refresh', 'lock button'] as const)('removes device data and stops discovery on %s', async (source) => {
    render(<App />);
    expect(await screen.findByText('482913')).toBeTruthy();
    if (source === 'lock button') {
      fireEvent.click(screen.getByRole('button', { name: '锁定' }));
    } else {
      vaultStatus = { ...vaultStatus, unlocked: false };
      if (source === 'event') act(() => onLocked());
      else fireEvent.focus(window);
    }
    await expectUnlockPage();
    expect(window.vaultMesh.lan.stopDiscovery).toHaveBeenCalledOnce();
  });
});
