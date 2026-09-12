// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { StrictMode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { UnlockPage } from '../../src/renderer/src/pages/UnlockPage';
import { useVaultStore } from '../../src/renderer/src/stores/vault-store';
import type { VaultMeshApi } from '../../src/shared/api';

const navigate = vi.fn();

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => navigate,
}));

const lockedStatus = {
  hasVault: true,
  unlocked: false,
  vaultPath: '/tmp/vaultmesh-test.vault',
  itemCount: 0,
};

describe('CT-TAURI-DESKTOP-001 desktop quick unlock', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'vaultMesh', {
      configurable: true,
      value: {
        vault: {
          unlockWithBiometrics: vi.fn().mockResolvedValue({ cancelled: true, status: lockedStatus }),
        },
      } as unknown as VaultMeshApi,
    });
    useVaultStore.setState({
      status: lockedStatus,
      biometric: null,
      pin: { enabled: false, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 },
      busy: false,
      error: null,
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('automatically requests Touch ID once and keeps manual retry available', async () => {
    render(<StrictMode><UnlockPage /></StrictMode>);

    expect(window.vaultMesh.vault.unlockWithBiometrics).not.toHaveBeenCalled();
    act(() => useVaultStore.setState({ biometric: { available: true, enabled: true, kind: 'touchId' } }));
    await waitFor(() => expect(window.vaultMesh.vault.unlockWithBiometrics).toHaveBeenCalledOnce());
    expect(screen.getByRole('button', { name: '使用 Touch ID' })).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: '使用 Touch ID' }));
    await waitFor(() => expect(window.vaultMesh.vault.unlockWithBiometrics).toHaveBeenCalledTimes(2));
  });
});
