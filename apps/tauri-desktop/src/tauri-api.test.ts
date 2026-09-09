import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.fn();
const listen = vi.fn(async (_event: string, _callback: () => void) => vi.fn());

vi.mock('@tauri-apps/api/core', () => ({ invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen }));

describe('CT-TAURI-COMMAND-001 typed adapter', () => {
  beforeEach(() => { invoke.mockReset(); listen.mockClear(); });

  it('maps renderer methods to fixed backend operations', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    invoke.mockResolvedValueOnce([]);
    await createTauriVaultMeshApi().items.list();
    expect(invoke).toHaveBeenCalledWith('desktop_invoke', {
      request: { operation: 'items.list', input: {} },
    });
  });

  it('routes desktop startup state through fixed backend operations', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    const api = createTauriVaultMeshApi();
    invoke.mockResolvedValue({ enabled: true });

    await api.desktop.startupSettings();
    await api.desktop.updateStartupSettings({ enabled: false });

    expect(invoke.mock.calls.slice(-2)).toEqual([
      ['desktop_invoke', { request: { operation: 'desktop.startup.get', input: {} } }],
      ['desktop_invoke', { request: { operation: 'desktop.startup.update', input: { enabled: false } } }],
    ]);
  });

  it('routes Agent access controls through fixed desktop operations', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    invoke.mockResolvedValue({});
    const api = createTauriVaultMeshApi();
    await api.agent.status();
    await api.agent.enablePin({ pin: '123456', failureLimit: 5 });
    await api.agent.disablePin();
    await api.agent.lockAllAccess();
    await api.agent.lockClientAccess('00000000-0000-4000-8000-000000000002');
    await api.agent.updateAccessSettings({ unlockScope: 'client', idleTimeoutMs: 900000, maxUnlockDurationMs: null });
    await api.agent.revokeClient('00000000-0000-4000-8000-000000000001');
    expect(invoke.mock.calls.slice(-7)).toEqual([
      ['desktop_invoke', { request: { operation: 'agent.status', input: {} } }],
      ['desktop_invoke', { request: { operation: 'agent.pin.enable', input: { pin: '123456', failureLimit: 5 } } }],
      ['desktop_invoke', { request: { operation: 'agent.pin.disable', input: {} } }],
      ['desktop_invoke', { request: { operation: 'agent.access.lock-all', input: {} } }],
      ['desktop_invoke', { request: { operation: 'agent.access.lock-client', input: { clientId: '00000000-0000-4000-8000-000000000002' } } }],
      ['desktop_invoke', { request: { operation: 'agent.access.settings.update', input: { unlockScope: 'client', idleTimeoutMs: 900000, maxUnlockDurationMs: null } } }],
      ['desktop_invoke', { request: { operation: 'agent.client.revoke', input: { clientId: '00000000-0000-4000-8000-000000000001' } } }],
    ]);
  });

  it('routes LAN discovery and pairing only through bounded typed operations', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    invoke.mockResolvedValue({});
    const api = createTauriVaultMeshApi();
    const pairingRef = 'lan-peer-00112233445566778899aabbccddeeff';
    await api.lan.status();
    await api.lan.startDiscovery();
    await api.lan.scan();
    await api.lan.listTrusted();
    await api.lan.begin(pairingRef, '482913');
    await api.lan.rename(pairingRef, '办公室电脑');
    await api.lan.revoke(pairingRef);
    await api.lan.stopDiscovery();
    expect(invoke.mock.calls.slice(-8)).toEqual([
      ['desktop_invoke', { request: { operation: 'lan.pairing.status', input: {} } }],
      ['desktop_invoke', { request: { operation: 'lan.discovery.start', input: {} } }],
      ['desktop_invoke', { request: { operation: 'lan.discovery.scan', input: {} } }],
      ['desktop_invoke', { request: { operation: 'lan.pairing.list', input: {} } }],
      ['desktop_invoke', { request: { operation: 'lan.pairing.begin', input: { pairingRef, pairingCode: '482913' } } }],
      ['desktop_invoke', { request: { operation: 'lan.pairing.rename', input: { pairingRef, label: '办公室电脑' } } }],
      ['desktop_invoke', { request: { operation: 'lan.pairing.revoke', input: { pairingRef } } }],
      ['desktop_invoke', { request: { operation: 'lan.discovery.stop', input: {} } }],
    ]);
  });

  it('rejects network endpoints and handshake material from LAN renderer DTOs', async () => {
    const { LanPairingStatusSchema } = await import('./shared/contracts');
    const safe = {
      discoverable: true,
      expiresAt: 1,
      pairingCode: '482913',
      nearby: [{ pairingRef: 'lan-peer-00112233445566778899aabbccddeeff', status: 'connecting' }],
      trusted: [],
    };
    expect(LanPairingStatusSchema.safeParse(safe).success).toBe(true);
    expect(LanPairingStatusSchema.safeParse({
      ...safe,
      nearby: [{ ...safe.nearby[0], status: 'code-rejected' }],
    }).success).toBe(true);
    expect(LanPairingStatusSchema.safeParse({
      ...safe,
      nearby: [{ ...safe.nearby[0], status: 'local-storage-failed' }],
    }).success).toBe(true);
    expect(LanPairingStatusSchema.safeParse({
      ...safe,
      nearby: [{ ...safe.nearby[0], status: 'peer-storage-failed' }],
    }).success).toBe(true);
    expect(LanPairingStatusSchema.safeParse({
      ...safe,
      nearby: [{ ...safe.nearby[0], address: '192.168.1.8', port: 43210, nonce: 'secret' }],
    }).success).toBe(false);
    expect(LanPairingStatusSchema.safeParse({
      ...safe,
      trusted: [{
        pairingRef: 'lan-peer-00112233445566778899aabbccddeeff',
        label: 'Peer',
        protocolMajor: 1,
        certificateFingerprint: 'ab'.repeat(32),
      }],
    }).success).toBe(false);
    expect(LanPairingStatusSchema.safeParse({ ...safe, tlsExporter: 'secret' }).success).toBe(false);
    expect(LanPairingStatusSchema.safeParse({ ...safe, pairingCode: '12345' }).success).toBe(false);
    expect(LanPairingStatusSchema.safeParse({ ...safe, pairingCode: '12345a' }).success).toBe(false);
    expect(LanPairingStatusSchema.safeParse({ ...safe, pending: [] }).success).toBe(false);
  });

  it('exposes only the pairing event to the main renderer bridge', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    const api = createTauriVaultMeshApi();
    const pairing = vi.fn();

    api.agent.onPairingRequested(pairing);
    await Promise.resolve();

    expect(listen.mock.calls.slice(-1).map(([event]) => event)).toEqual(['agent-pairing-requested']);
  });

  it('normalizes optional master passwords without exposing generic invoke', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    invoke.mockResolvedValueOnce({ clearsAt: 1 });
    await createTauriVaultMeshApi().cards.copyNumber('4f3621b7-8dc4-43c9-9a29-b111bf48e35a');
    expect(invoke).toHaveBeenCalledWith('desktop_invoke', {
      request: {
        operation: 'cards.copy-number',
        input: { id: '4f3621b7-8dc4-43c9-9a29-b111bf48e35a', masterPassword: null },
      },
    });
  });

  it('maps recovery-code reveal and copy to required-password operations', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    const id = '4f3621b7-8dc4-43c9-9a29-b111bf48e35a';
    invoke.mockResolvedValueOnce({ codes: ['ABCD-EFGH'] });
    await createTauriVaultMeshApi().items.recoveryCodes(id, 'a long master password');
    expect(invoke).toHaveBeenLastCalledWith('desktop_invoke', {
      request: { operation: 'items.recovery-codes', input: { id, masterPassword: 'a long master password' } },
    });
    invoke.mockResolvedValueOnce({ clearsAt: 1 });
    await createTauriVaultMeshApi().items.copyRecoveryCode(id, 0, 'a long master password');
    expect(invoke).toHaveBeenLastCalledWith('desktop_invoke', {
      request: { operation: 'items.copy-recovery-code', input: { id, index: 0, masterPassword: 'a long master password' } },
    });
  });

  it('routes recovery-code file selection through the fixed privileged operation', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    invoke.mockResolvedValueOnce({ codes: ['ABCD-EFGH'], fileName: 'codes.txt', sourceFileStatus: 'kept' });
    await createTauriVaultMeshApi().items.importRecoveryCodesFile();
    expect(invoke).toHaveBeenLastCalledWith('desktop_invoke', {
      request: { operation: 'items.recovery-codes.import-file', input: {} },
    });
  });

  it('preserves public Rust rejection messages as Error objects for renderer feedback', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    invoke.mockRejectedValueOnce('PIN 不正确，还可尝试 4 次。');
    await expect(createTauriVaultMeshApi().vault.unlockWithPin({ pin: '000000' }))
      .rejects.toThrow('PIN 不正确，还可尝试 4 次。');
  });

  it('routes SSH scan sessions through the bounded desktop operations', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    const api = createTauriVaultMeshApi();
    const sessionId = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
    const entryId = '3edaf140-8f87-4c5f-9294-d6ad6f153a78';
    invoke.mockResolvedValue({});
    await api.ssh.scanLocalKeys();
    await api.ssh.importScannedKeys(sessionId, [{ entryId, publicKey: 'ssh-ed25519 AAAA manual@test' }]);
    await api.ssh.cancelKeyScan(sessionId);
    expect(invoke.mock.calls.slice(-3)).toEqual([
      ['desktop_invoke', { request: { operation: 'ssh.scan', input: {} } }],
      ['desktop_invoke', { request: { operation: 'ssh.scan.commit', input: {
        sessionId,
        entryIds: [entryId],
        publicKeyOverrides: { [entryId]: 'ssh-ed25519 AAAA manual@test' },
      } } }],
      ['desktop_invoke', { request: { operation: 'ssh.scan.cancel', input: { sessionId } } }],
    ]);
  });

  it('routes SSH host inspection and public-key installation through fixed privileged operations', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    const api = createTauriVaultMeshApi();
    const accountId = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
    const keyId = '3edaf140-8f87-4c5f-9294-d6ad6f153a78';
    invoke.mockResolvedValue({});
    await api.ssh.inspectHostKey(accountId);
    await api.ssh.installPublicKey({
      accountId, keyId, authentication: 'storedPassword', authenticationKeyId: null,
      hostKeyFingerprint: 'SHA256:8oHDb5PRKSvrgACKsgtHc3CJKNWbEzwVSJYJh4QDaFs',
      masterPassword: 'correct horse battery staple',
    });
    expect(invoke.mock.calls.slice(-2)).toEqual([
      ['desktop_invoke', { request: { operation: 'ssh.inspect-host-key', input: { accountId } } }],
      ['desktop_invoke', { request: { operation: 'ssh.install-public-key', input: {
        accountId, keyId, authentication: 'storedPassword', authenticationKeyId: null,
        hostKeyFingerprint: 'SHA256:8oHDb5PRKSvrgACKsgtHc3CJKNWbEzwVSJYJh4QDaFs',
        masterPassword: 'correct horse battery staple',
      } } }],
    ]);
  });

  it('routes SSH external-client discovery and launch through fixed privileged operations', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    const api = createTauriVaultMeshApi();
    const accountId = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
    invoke.mockResolvedValue({});
    await api.ssh.externalClients();
    await api.ssh.launch({ accountId, clientId: 'systemTerminal', copyPassword: true });
    expect(invoke.mock.calls.slice(-2)).toEqual([
      ['desktop_invoke', { request: { operation: 'ssh.external-clients', input: {} } }],
      ['desktop_invoke', { request: { operation: 'ssh.launch', input: {
        accountId, clientId: 'systemTerminal', copyPassword: true,
      } } }],
    ]);
  });

  it('routes email account, scan and OAuth calls without a generic renderer API', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    const api = createTauriVaultMeshApi();
    invoke.mockResolvedValue({});
    await api.emailOtp.accounts();
    await api.emailOtp.scan();
    await api.emailOtp.connectOAuth({ provider: 'gmail', label: 'Work' });
    expect(invoke.mock.calls.slice(-3)).toEqual([
      ['desktop_invoke', { request: { operation: 'email.accounts', input: {} } }],
      ['desktop_invoke', { request: { operation: 'email.scan', input: {} } }],
      ['desktop_invoke', { request: { operation: 'email.oauth.connect', input: { provider: 'gmail', label: 'Work' } } }],
    ]);
  });

  it('routes recent email verification-code copies through the privileged desktop operation', async () => {
    const { createTauriVaultMeshApi } = await import('./tauri-api');
    invoke.mockResolvedValueOnce({ clearsAt: 1 });

    await createTauriVaultMeshApi().emailOtp.copyCode('A9b2C3');

    expect(invoke).toHaveBeenLastCalledWith('desktop_invoke', {
      request: { operation: 'email.copy-code', input: { code: 'A9b2C3' } },
    });
  });
});
