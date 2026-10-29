import { beforeEach, describe, expect, it, vi } from 'vitest';

import { rememberLoginSelection } from './autofill-preferences';
import { DesktopRpcError } from './desktop-rpc';
import {
  defaultLoginIdForPasskeyRequest,
  hasPasskeyForHost,
  installPasskeyProxy,
  isNativePasskeyBypassHost,
  isNativePasskeyBypassRequest,
  isNativePasskeyBypassUrl,
  passkeyRequestRpId,
} from './passkey-proxy';

const loginId = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';

function createRequest(origin: unknown): string {
  return JSON.stringify({
    rp: { id: 'example.test', name: 'Example' },
    extensions: { remoteDesktopClientOverride: { origin, sameOriginWithAncestors: true } },
  });
}

describe('Passkey default Login routing', () => {
  beforeEach(async () => browser.storage.local.clear());

  it('forwards only the Login remembered for the exact WebAuthn origin', async () => {
    await rememberLoginSelection('https://example.test', loginId);

    await expect(defaultLoginIdForPasskeyRequest(createRequest('https://example.test'))).resolves.toBe(loginId);
    await expect(defaultLoginIdForPasskeyRequest(createRequest('https://example.test:8443'))).resolves.toBeNull();
  });

  it('does not derive a Login hint from malformed or non-origin request data', async () => {
    await rememberLoginSelection('https://example.test', loginId);

    await expect(defaultLoginIdForPasskeyRequest('{')).resolves.toBeNull();
    await expect(defaultLoginIdForPasskeyRequest(createRequest('https://example.test/path'))).resolves.toBeNull();
    await expect(defaultLoginIdForPasskeyRequest(createRequest('file:///tmp/passkey'))).resolves.toBeNull();
  });
});

type Listener<T> = (value: T) => void;
function event<T>() {
  const listeners: Listener<T>[] = [];
  return { addListener: (listener: Listener<T>) => { listeners.push(listener); }, emit: (value: T) => listeners.forEach((listener) => listener(value)) };
}

function createFakeProxy() {
  const canceled = event<number>();
  const uvpaa = event<{ requestId: number }>();
  const create = event<{ requestId: number; requestDetailsJson: string }>();
  const get = event<{ requestId: number; requestDetailsJson: string }>();
  const completions: { requestId: number; responseJson?: string; error?: { name: string; message: string } }[] = [];
  const uvpaaResults: boolean[] = [];
  const proxy = {
    attached: false,
    onRequestCanceled: canceled,
    onIsUvpaaRequest: uvpaa,
    onCreateRequest: create,
    onGetRequest: get,
    attach: vi.fn(async () => { proxy.attached = true; return undefined; }),
    detach: vi.fn(async () => { proxy.attached = false; }),
    completeIsUvpaaRequest: vi.fn(async (details: { isUvpaa: boolean }) => { uvpaaResults.push(details.isUvpaa); }),
    completeCreateRequest: vi.fn(async (details: (typeof completions)[number]) => { completions.push(details); }),
    completeGetRequest: vi.fn(async (details: (typeof completions)[number]) => { completions.push(details); }),
  };
  return { proxy, completions, uvpaaResults, canceled, uvpaa, get, create };
}

function createHarness(initiallyUnlocked: boolean, options: { autoAttach?: boolean } = {}) {
  const fake = createFakeProxy();
  const state = { unlocked: initiallyUnlocked, reachable: true, paired: true };
  const rpc = vi.fn(async (operation: string) => {
    if (!state.paired) throw new DesktopRpcError('unpaired', 'unpaired');
    if (!state.reachable) throw new DesktopRpcError('desktop-unavailable', 'offline');
    if (operation === 'vault.status') return { unlocked: state.unlocked, hasVault: true, itemCount: 1 };
    if (!state.unlocked) throw new DesktopRpcError('unlock-required', 'locked');
    return { responseJson: '{"ok":true}' };
  });
  const openUnlockPrompt = vi.fn(async () => undefined);
  const passkeys = installPasskeyProxy({
    proxy: fake.proxy as never,
    rpc: rpc as never,
    openUnlockPrompt,
    unlockPollMs: 5,
    autoAttach: options.autoAttach ?? true,
  });
  return { ...fake, state, rpc, openUnlockPrompt, passkeys };
}

const getRequest = JSON.stringify({ rpId: 'example.test', extensions: { remoteDesktopClientOverride: { origin: 'https://example.test' } } });

describe('Passkey proxy while the extension is locked', () => {
  it('stays attached and advertises the platform authenticator while locked', async () => {
    const harness = createHarness(false);
    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(true);
    harness.uvpaa.emit({ requestId: 1 });
    await vi.waitFor(() => expect(harness.uvpaaResults).toEqual([true]));
  });

  it('attaches at start-up before any desktop status round-trip', async () => {
    const harness = createHarness(false);
    harness.state.reachable = false;
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(true));
  });

  it('keeps VaultMesh attached while the native port is unavailable and detaches only when unpaired', async () => {
    const harness = createHarness(false);
    await harness.passkeys.sync();
    harness.state.reachable = false;
    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(true);
    harness.state.paired = false;
    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(false);
  });

  it('re-attaches after a worker restart left Chromium holding the previous attachment', async () => {
    const fake = createFakeProxy();
    let chromiumAttached = true;
    fake.proxy.attach = vi.fn(async () => { if (chromiumAttached) return 'already attached'; chromiumAttached = true; fake.proxy.attached = true; return undefined; }) as never;
    fake.proxy.detach = vi.fn(async () => { chromiumAttached = false; fake.proxy.attached = false; });
    installPasskeyProxy({ proxy: fake.proxy as never, rpc: (async () => ({ unlocked: false })) as never, unlockPollMs: 5, autoAttach: true });
    await vi.waitFor(() => expect(fake.proxy.attached).toBe(true));
    fake.uvpaa.emit({ requestId: 1 });
    await vi.waitFor(() => expect(fake.uvpaaResults).toEqual([true]));
  });

  it('holds a request while the desktop is unreachable and continues once it is usable', async () => {
    const harness = createHarness(false);
    await harness.passkeys.sync();
    harness.state.reachable = false;
    harness.get.emit({ requestId: 11, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.passkeys.pendingUnlockPrompt()).not.toBeNull());
    expect(harness.openUnlockPrompt).toHaveBeenCalledTimes(1);
    harness.state.reachable = true;
    harness.state.unlocked = true;
    await vi.waitFor(() => expect(harness.completions).toEqual([{ requestId: 11, responseJson: '{"ok":true}' }]));
  });

  it('holds a locked request, prompts unlock and completes it in VaultMesh after unlocking', async () => {
    const harness = createHarness(false);
    await harness.passkeys.sync();
    harness.get.emit({ requestId: 7, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.passkeys.pendingUnlockPrompt()).toMatchObject({ operation: 'get', origin: 'https://example.test' }));
    expect(harness.openUnlockPrompt).toHaveBeenCalledTimes(1);
    expect(harness.completions).toEqual([]);

    harness.state.unlocked = true;
    await harness.passkeys.sync();
    await vi.waitFor(() => expect(harness.completions).toEqual([{ requestId: 7, responseJson: '{"ok":true}' }]));
    expect(harness.proxy.attached).toBe(true);
    expect(harness.passkeys.pendingUnlockPrompt()).toBeNull();
  });

  it('also resumes when the vault is unlocked outside the popup', async () => {
    const harness = createHarness(false);
    await harness.passkeys.sync();
    harness.create.emit({ requestId: 8, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.passkeys.pendingUnlockPrompt()).not.toBeNull());
    harness.state.unlocked = true;
    await vi.waitFor(() => expect(harness.completions).toEqual([{ requestId: 8, responseJson: '{"ok":true}' }]));
  });

  it('hands WebAuthn back to the browser only after the user explicitly declines to unlock', async () => {
    const harness = createHarness(false);
    await harness.passkeys.sync();
    harness.get.emit({ requestId: 9, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.passkeys.pendingUnlockPrompt()).not.toBeNull());
    expect(harness.proxy.attached).toBe(true);

    expect(harness.passkeys.declineUnlock(crypto.randomUUID())).toBe(false);
    const prompt = harness.passkeys.pendingUnlockPrompt()!;
    expect(harness.passkeys.declineUnlock(prompt.token)).toBe(true);
    await vi.waitFor(() => expect(harness.completions).toEqual([{ requestId: 9, error: expect.objectContaining({ name: 'NotAllowedError' }) }]));
    expect(harness.proxy.attached).toBe(false);

    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(false);
    harness.state.unlocked = true;
    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(true);
  });

  it('drops a waiting request that the page cancels', async () => {
    const harness = createHarness(false);
    await harness.passkeys.sync();
    harness.get.emit({ requestId: 10, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.passkeys.pendingUnlockPrompt()).not.toBeNull());
    harness.canceled.emit(10);
    expect(harness.passkeys.pendingUnlockPrompt()).toBeNull();
    harness.state.unlocked = true;
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(harness.completions).toEqual([]);
    expect(harness.proxy.attached).toBe(true);
  });
});

describe('Native Passkey / Touch ID bypass detection', () => {
  it('identifies browser-native and platform authenticator hosts', () => {
    expect(isNativePasskeyBypassHost('google.com')).toBe(true);
    expect(isNativePasskeyBypassHost('accounts.google.com')).toBe(true);
    expect(isNativePasskeyBypassHost('myaccount.google.com')).toBe(true);
    expect(isNativePasskeyBypassHost('apple.com')).toBe(true);
    expect(isNativePasskeyBypassHost('appleid.apple.com')).toBe(true);
    expect(isNativePasskeyBypassHost('login.microsoftonline.com')).toBe(true);

    expect(isNativePasskeyBypassHost('github.com')).toBe(false);
    expect(isNativePasskeyBypassHost('example.com')).toBe(false);
    expect(isNativePasskeyBypassHost('')).toBe(false);
  });

  it('identifies browser-native and platform authenticator URLs', () => {
    expect(isNativePasskeyBypassUrl('https://accounts.google.com/signin/v2')).toBe(true);
    expect(isNativePasskeyBypassUrl('https://appleid.apple.com/sign-in')).toBe(true);
    expect(isNativePasskeyBypassUrl('https://github.com/login')).toBe(false);
    expect(isNativePasskeyBypassUrl('chrome://settings')).toBe(false);
    expect(isNativePasskeyBypassUrl(null)).toBe(false);
  });

  it('extracts rpId correctly from create and get requests', () => {
    expect(passkeyRequestRpId(JSON.stringify({ rpId: 'google.com' }))).toBe('google.com');
    expect(passkeyRequestRpId(JSON.stringify({ rp: { id: 'accounts.google.com' } }))).toBe('accounts.google.com');
    expect(passkeyRequestRpId('{')).toBeNull();
  });

  it('detects native bypass from request details JSON', () => {
    const googleGet = JSON.stringify({ rpId: 'google.com', extensions: { remoteDesktopClientOverride: { origin: 'https://accounts.google.com' } } });
    expect(isNativePasskeyBypassRequest(googleGet)).toBe(true);

    const normalGet = JSON.stringify({ rpId: 'github.com', extensions: { remoteDesktopClientOverride: { origin: 'https://github.com' } } });
    expect(isNativePasskeyBypassRequest(normalGet)).toBe(false);
  });

  it('immediately detaches and completes with error when a native bypass request arrives', async () => {
    const harness = createHarness(true);
    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(true);

    const googleRequest = JSON.stringify({ rpId: 'google.com', extensions: { remoteDesktopClientOverride: { origin: 'https://accounts.google.com' } } });
    harness.get.emit({ requestId: 101, requestDetailsJson: googleRequest });

    await vi.waitFor(() => expect(harness.completions).toEqual([
      { requestId: 101, error: expect.objectContaining({ name: 'NotAllowedError' }) },
    ]));
    expect(harness.proxy.attached).toBe(false);
  });

  it('detaches when tab bypass is activated and re-attaches when deactivated', async () => {
    const harness = createHarness(true);
    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(true);

    harness.passkeys.setTabBypass(true);
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(false));

    harness.passkeys.setTabBypass(false);
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(true));
  });

  it('detaches when policy disables passkeys and re-attaches when enabled', async () => {
    const harness = createHarness(true);
    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(true);

    harness.passkeys.setEnabled(false);
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(false));

    harness.passkeys.setEnabled(true);
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(true));
  });

  it('starts detached when autoAttach is false', () => {
    const harness = createHarness(true, { autoAttach: false });
    expect(harness.proxy.attached).toBe(false);
  });

  it('bypasses for subsequent requests when user cancels the desktop dialog', async () => {
    const fake = createFakeProxy();
    const rpc = vi.fn(async (op: string) => {
      if (op === 'vault.status') return { unlocked: true, hasVault: true, itemCount: 1 };
      throw new DesktopRpcError('cancelled', '操作已取消。');
    });
    const passkeys = installPasskeyProxy({ proxy: fake.proxy as never, rpc: rpc as never, autoAttach: true });
    await passkeys.sync();
    expect(fake.proxy.attached).toBe(true);

    fake.get.emit({ requestId: 201, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(fake.proxy.attached).toBe(false));
  });
});

describe('hasPasskeyForHost', () => {
  const dummySnapshot = {
    status: { unlocked: true, hasVault: true, itemCount: 2 },
    items: [
      {
        id: '11111111-1111-1111-1111-111111111111',
        title: 'GitHub Login',
        username: 'alice',
        url: 'https://github.com/login',
        notes: null,
        hasPassword: true,
        hasTotpSecret: false,
        hasRecoveryCodes: false,
        autofillOnPageLoad: false,
        masterPasswordReprompt: false,
      },
    ],
    cards: [],
    identities: [],
    sshCredentials: [],
    secrets: [
      {
        id: '22222222-2222-2222-2222-222222222222',
        title: 'Alice · github.com',
        kind: 'authenticator-key' as const,
        provider: 'passkey',
        account: 'alice',
        environment: 'Passkey',
        expiresAt: null,
        website: 'https://github.com',
        notes: null,
        favorite: false,
        masterPasswordReprompt: false,
        isPasskey: true,
        loginId: '11111111-1111-1111-1111-111111111111',
      },
      {
        id: '33333333-3333-3333-3333-333333333333',
        title: 'Direct Domain Passkey',
        kind: 'authenticator-key' as const,
        provider: 'passkey',
        account: 'bob',
        environment: 'Passkey',
        expiresAt: null,
        website: 'auth.corp.internal',
        notes: null,
        favorite: false,
        masterPasswordReprompt: false,
        isPasskey: true,
        loginId: null,
      },
      {
        id: '44444444-4444-4444-4444-444444444444',
        title: 'Regular API Key',
        kind: 'api-key' as const,
        provider: 'aws',
        account: null,
        environment: null,
        expiresAt: null,
        website: 'https://aws.amazon.com',
        notes: null,
        favorite: false,
        masterPasswordReprompt: false,
        isPasskey: false,
        loginId: null,
      },
    ],
  };

  it('returns true when a passkey matches the host directly or as subdomain', () => {
    expect(hasPasskeyForHost(dummySnapshot, 'github.com')).toBe(true);
    expect(hasPasskeyForHost(dummySnapshot, 'api.github.com')).toBe(true);
    expect(hasPasskeyForHost(dummySnapshot, 'auth.corp.internal')).toBe(true);
    expect(hasPasskeyForHost(dummySnapshot, 'sub.auth.corp.internal')).toBe(true);
  });

  it('returns false for unrelated hosts', () => {
    expect(hasPasskeyForHost(dummySnapshot, 'google.com')).toBe(false);
    expect(hasPasskeyForHost(dummySnapshot, 'notgithub.com')).toBe(false);
    expect(hasPasskeyForHost(dummySnapshot, 'aws.amazon.com')).toBe(false); // isPasskey is false
  });

  it('returns false when snapshot or host is empty/null/undefined', () => {
    expect(hasPasskeyForHost(null, 'github.com')).toBe(false);
    expect(hasPasskeyForHost(undefined, 'github.com')).toBe(false);
    expect(hasPasskeyForHost(dummySnapshot, '')).toBe(false);
    expect(hasPasskeyForHost(dummySnapshot, null)).toBe(false);
    expect(hasPasskeyForHost(dummySnapshot, undefined)).toBe(false);
  });
});
