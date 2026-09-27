import { beforeEach, describe, expect, it, vi } from 'vitest';

import { rememberLoginSelection } from './autofill-preferences';
import { DesktopRpcError } from './desktop-rpc';
import { defaultLoginIdForPasskeyRequest, installPasskeyProxy } from './passkey-proxy';

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

function createHarness(initiallyUnlocked: boolean) {
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
  const passkeys = installPasskeyProxy({ proxy: fake.proxy as never, rpc: rpc as never, openUnlockPrompt, unlockPollMs: 5 });
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
    installPasskeyProxy({ proxy: fake.proxy as never, rpc: (async () => ({ unlocked: false })) as never, unlockPollMs: 5 });
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
