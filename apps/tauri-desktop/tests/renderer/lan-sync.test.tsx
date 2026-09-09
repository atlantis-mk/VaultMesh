// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LanSyncPanel } from '../../src/renderer/src/pages/LanSyncPanel';
import type { VaultMeshApi } from '../../src/shared/api';
import type { LanTrustedPeer } from '../../src/shared/contracts';

vi.mock('sonner', () => ({ toast: { error: vi.fn() } }));
const peer: LanTrustedPeer = { pairingRef: 'lan-peer-00112233445566778899aabbccddeeff', label: 'Test peer', protocolMajor: 1 };

describe('CT-LAN-SYNC-001 desktop sync authorization and history', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'vaultMesh', { configurable: true, value: { lan: {
      syncStatus: vi.fn().mockResolvedValue({ peers: [{ peerRef: peer.pairingRef, enabled: false, state: 'disabled', lastSuccessAt: null }], conflictCount: 1 }),
      enableSync: vi.fn().mockResolvedValue({ ok: true }), disableSync: vi.fn().mockResolvedValue({ ok: true }), retrySync: vi.fn().mockResolvedValue({ ok: true }),
      syncConflicts: vi.fn().mockResolvedValue([{ id: 'conflict/00112233-4455-6677-8899-aabbccddeeff', kind: 'login', savedAt: 1000 }]),
      restoreSyncConflict: vi.fn().mockResolvedValue({ ok: true }), clearSyncConflicts: vi.fn().mockResolvedValue({ ok: true }),
    } } as unknown as VaultMeshApi });
  });
  afterEach(cleanup);
  it('requires explicit confirmation for legacy pairing and does not revoke on navigation', async () => {
    const view = render(<LanSyncPanel trusted={[peer]} />);
    await screen.findByText('自动同步已关闭');
    fireEvent.click(screen.getByRole('button', { name: '开启 Test peer 自动同步' }));
    expect(window.vaultMesh.lan.enableSync).not.toHaveBeenCalled();
    expect(screen.getByText(/旧配对设备也需要在对端确认一次/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '授权并启用' }));
    await waitFor(() => expect(window.vaultMesh.lan.enableSync).toHaveBeenCalledWith(peer.pairingRef));
    view.unmount();
    expect(window.vaultMesh.lan.disableSync).not.toHaveBeenCalled();
  });
  it('retries an authorized peer and explicitly disables future sync', async () => {
    vi.mocked(window.vaultMesh.lan.syncStatus).mockResolvedValue({ peers: [{ peerRef: peer.pairingRef, enabled: true, state: 'failed', lastSuccessAt: 1000 }], conflictCount: 0 });
    render(<LanSyncPanel trusted={[peer]} />);
    fireEvent.click(await screen.findByRole('button', { name: '立即重试' }));
    await waitFor(() => expect(window.vaultMesh.lan.retrySync).toHaveBeenCalledWith(peer.pairingRef));
    await waitFor(() => expect((screen.getByRole('button', { name: '关闭 Test peer 自动同步' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: '关闭 Test peer 自动同步' }));
    await waitFor(() => expect(window.vaultMesh.lan.disableSync).toHaveBeenCalledWith(peer.pairingRef));
  });
  it('confirms history restoration and permanent clearing without exposing protected values', async () => {
    render(<LanSyncPanel trusted={[]} />);
    fireEvent.click(await screen.findByRole('button', { name: /冲突历史（/ }));
    await waitFor(() => expect((screen.getByRole('button', { name: '恢复此版本' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: '恢复此版本' }));
    expect(window.vaultMesh.lan.restoreSyncConflict).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: '恢复并同步' }));
    await waitFor(() => expect(window.vaultMesh.lan.restoreSyncConflict).toHaveBeenCalledWith('conflict/00112233-4455-6677-8899-aabbccddeeff'));
    await waitFor(() => expect((screen.getByRole('button', { name: '清空冲突历史' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: '清空冲突历史' }));
    expect(window.vaultMesh.lan.clearSyncConflicts).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: '永久清空' }));
    await waitFor(() => expect(window.vaultMesh.lan.clearSyncConflicts).toHaveBeenCalledOnce());
  });
});
