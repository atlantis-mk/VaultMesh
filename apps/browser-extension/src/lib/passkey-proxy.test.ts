import { beforeEach, describe, expect, it, vi } from 'vitest';

import { rememberLoginSelection } from './autofill-preferences';
import { DesktopRpcError } from './desktop-rpc';
import {
  defaultLoginIdForPasskeyRequest,
  installPasskeyProxy,
  PASSKEY_BYPASS_MS,
  passkeyRequestOrigin,
  type PasskeyProbeResult,
} from './passkey-proxy';

const loginId = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
const getRequest = JSON.stringify({
  rpId: 'example.test',
  challenge: 'Y2hhbGxlbmdl',
  allowCredentials: [],
  extensions: { remoteDesktopClientOverride: { origin: 'https://example.test', sameOriginWithAncestors: true } },
});

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

  it('extracts only an exact HTTP(S) origin for prompt and diagnostics', () => {
    expect(passkeyRequestOrigin(getRequest)).toBe('https://example.test');
    expect(passkeyRequestOrigin(createRequest('https://example.test/path'))).toBeNull();
    expect(passkeyRequestOrigin('{')).toBeNull();
  });
});

type Listener<T> = (value: T) => void;
function event<T>() {
  const listeners: Listener<T>[] = [];
  return { addListener: (listener: Listener<T>) => { listeners.push(listener); }, emit: (value: T) => listeners.forEach((listener) => listener(value)) };
}

function createFakeProxy() {
  const calls: string[] = [];
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
    attach: vi.fn(async () => {
      proxy.attached = true;
      calls.push('attach');
      return undefined;
    }),
    detach: vi.fn(async () => {
      proxy.attached = false;
      calls.push('detach');
    }),
    completeIsUvpaaRequest: vi.fn(async (details: { isUvpaa: boolean }) => { uvpaaResults.push(details.isUvpaa); }),
    completeCreateRequest: vi.fn(async (details: (typeof completions)[number]) => {
      calls.push(`complete:${details.requestId}:${details.error?.name ?? 'ok'}`);
      completions.push(details);
    }),
    completeGetRequest: vi.fn(async (details: (typeof completions)[number]) => {
      calls.push(`complete:${details.requestId}:${details.error?.name ?? 'ok'}`);
      completions.push(details);
    }),
  };
  return { proxy, completions, uvpaaResults, canceled, uvpaa, get, create, calls };
}

type HarnessState = {
  unlocked: boolean;
  reachable: boolean;
  paired: boolean;
  probe: PasskeyProbeResult;
  getError: Error | null;
};

function createHarness(initiallyUnlocked: boolean, now: () => number = Date.now) {
  const fake = createFakeProxy();
  const state: HarnessState = {
    unlocked: initiallyUnlocked,
    reachable: true,
    paired: true,
    probe: { status: 'available', rpId: 'example.test', origin: 'https://example.test', account: 'ada@example.test' },
    getError: null,
  };
  const rpc = vi.fn(async (operation: string) => {
    if (!state.paired) throw new DesktopRpcError('unpaired', 'unpaired');
    if (!state.reachable) throw new DesktopRpcError('desktop-unavailable', 'offline');
    if (operation === 'vault.status') return { unlocked: state.unlocked, hasVault: true, itemCount: 1 };
    if (operation === 'passkeys.probe') return state.probe;
    if (!state.unlocked) throw new DesktopRpcError('unlock-required', 'locked');
    if (operation === 'passkeys.get' && state.getError) throw state.getError;
    return { responseJson: '{"ok":true}' };
  });
  const openUnlockPrompt = vi.fn(async () => undefined);
  const notifyRetry = vi.fn(async () => undefined);
  const passkeys = installPasskeyProxy({
    proxy: fake.proxy as never,
    rpc: rpc as never,
    openUnlockPrompt,
    notifyRetry,
    now,
    unlockPollMs: 5,
  });
  return { ...fake, state, rpc, openUnlockPrompt, notifyRetry, passkeys };
}

describe('Passkey proxy global interception', () => {
  it('attaches at startup and advertises the platform authenticator while locked', async () => {
    const harness = createHarness(false);
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(true));
    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(true);
    harness.uvpaa.emit({ requestId: 1 });
    await vi.waitFor(() => expect(harness.uvpaaResults).toEqual([true]));
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
    fake.proxy.attach = vi.fn(async () => {
      if (chromiumAttached) return 'already attached';
      chromiumAttached = true;
      fake.proxy.attached = true;
      return undefined;
    }) as never;
    fake.proxy.detach = vi.fn(async () => {
      chromiumAttached = false;
      fake.proxy.attached = false;
    });
    installPasskeyProxy({ proxy: fake.proxy as never, rpc: (async () => ({ unlocked: false })) as never, unlockPollMs: 5 });
    await vi.waitFor(() => expect(fake.proxy.attached).toBe(true));
    fake.uvpaa.emit({ requestId: 1 });
    await vi.waitFor(() => expect(fake.uvpaaResults).toEqual([true]));
  });

  it('does not hard-code native identity providers', async () => {
    const harness = createHarness(true);
    await harness.passkeys.sync();
    const googleRequest = JSON.stringify({
      rpId: 'google.com',
      challenge: 'Y2hhbGxlbmdl',
      allowCredentials: [],
      extensions: { remoteDesktopClientOverride: { origin: 'https://accounts.google.com', sameOriginWithAncestors: true } },
    });
    harness.get.emit({ requestId: 101, requestDetailsJson: googleRequest });

    await vi.waitFor(() => expect(harness.completions).toEqual([{ requestId: 101, responseJson: '{"ok":true}' }]));
    expect(harness.rpc.mock.calls.map(([operation]) => operation)).toContain('passkeys.probe');
    expect(harness.rpc.mock.calls.map(([operation]) => operation)).toContain('passkeys.get');
    expect(harness.proxy.attached).toBe(true);
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
    await harness.passkeys.sync();
    await vi.waitFor(() => expect(harness.completions).toEqual([{ requestId: 11, responseJson: '{"ok":true}' }]));
  });

  it('prompts unlock when preflight finds a matching Passkey', async () => {
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

  it('treats an unknown locked preflight conservatively and unlocks before deciding', async () => {
    const harness = createHarness(false);
    harness.state.probe = { status: 'unknown', rpId: 'example.test', origin: 'https://example.test' };
    await harness.passkeys.sync();
    harness.get.emit({ requestId: 8, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.passkeys.pendingUnlockPrompt()).not.toBeNull());
    harness.state.unlocked = true;
    await harness.passkeys.sync();
    await vi.waitFor(() => expect(harness.completions).toEqual([{ requestId: 8, responseJson: '{"ok":true}' }]));
  });

  it('finishes the current request, detaches and prompts a browser retry when no Passkey matches', async () => {
    const harness = createHarness(false);
    harness.state.probe = { status: 'unavailable', rpId: 'example.test', origin: 'https://example.test' };
    await harness.passkeys.sync();
    harness.get.emit({ requestId: 9, requestDetailsJson: getRequest });

    await vi.waitFor(() => expect(harness.completions).toEqual([
      { requestId: 9, error: expect.objectContaining({ name: 'NotAllowedError' }) },
    ]));
    await vi.waitFor(() => expect(harness.notifyRetry).toHaveBeenCalledTimes(1));
    expect(harness.openUnlockPrompt).not.toHaveBeenCalled();
    expect(harness.proxy.attached).toBe(false);
    expect(harness.calls.indexOf('complete:9:NotAllowedError')).toBeLessThan(harness.calls.indexOf('detach'));
    expect(harness.rpc.mock.calls.map(([operation]) => operation)).not.toContain('passkeys.get');
  });

  it('also hands back after the unlocked desktop reports no matching credential', async () => {
    const harness = createHarness(true);
    harness.state.getError = new DesktopRpcError('passkey-unavailable', 'no match');
    await harness.passkeys.sync();
    harness.get.emit({ requestId: 10, requestDetailsJson: getRequest });

    await vi.waitFor(() => expect(harness.completions).toEqual([
      { requestId: 10, error: expect.objectContaining({ name: 'NotAllowedError' }) },
    ]));
    expect(harness.notifyRetry).toHaveBeenCalledTimes(1);
    expect(harness.proxy.attached).toBe(false);
  });

  it('hands the retry to the browser only after the user explicitly declines unlock', async () => {
    const harness = createHarness(false);
    await harness.passkeys.sync();
    harness.get.emit({ requestId: 12, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.passkeys.pendingUnlockPrompt()).not.toBeNull());
    expect(harness.proxy.attached).toBe(true);

    expect(harness.passkeys.declineUnlock(crypto.randomUUID())).toBe(false);
    const prompt = harness.passkeys.pendingUnlockPrompt()!;
    expect(harness.passkeys.declineUnlock(prompt.token)).toBe(true);
    await vi.waitFor(() => expect(harness.completions).toEqual([{ requestId: 12, error: expect.objectContaining({ name: 'NotAllowedError' }) }]));
    expect(harness.proxy.attached).toBe(false);
    expect(harness.notifyRetry).not.toHaveBeenCalled();
  });

  it('reattaches after the browser retry window without clearing it on an unrelated sync', async () => {
    let clock = 1_000;
    const harness = createHarness(true, () => clock);
    harness.state.probe = { status: 'unavailable', rpId: 'example.test', origin: 'https://example.test' };
    await harness.passkeys.sync();
    harness.get.emit({ requestId: 13, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(false));

    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(false);
    clock += PASSKEY_BYPASS_MS + 1;
    await harness.passkeys.sync();
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(true));
  });

  it('detaches when policy disables interception and reattaches when enabled', async () => {
    const harness = createHarness(true);
    await harness.passkeys.sync();
    expect(harness.proxy.attached).toBe(true);
    harness.passkeys.setEnabled(false);
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(false));
    harness.passkeys.setEnabled(true);
    await vi.waitFor(() => expect(harness.proxy.attached).toBe(true));
  });

  it('drops a waiting request that the page cancels', async () => {
    const harness = createHarness(false);
    await harness.passkeys.sync();
    harness.get.emit({ requestId: 14, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.passkeys.pendingUnlockPrompt()).not.toBeNull());
    harness.canceled.emit(14);
    expect(harness.passkeys.pendingUnlockPrompt()).toBeNull();
    harness.state.unlocked = true;
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(harness.completions).toEqual([]);
    expect(harness.proxy.attached).toBe(true);
  });

  it('does not run the get-only preflight for Passkey creation', async () => {
    const harness = createHarness(true);
    await harness.passkeys.sync();
    harness.create.emit({ requestId: 15, requestDetailsJson: getRequest });
    await vi.waitFor(() => expect(harness.completions).toEqual([{ requestId: 15, responseJson: '{"ok":true}' }]));
    expect(harness.rpc.mock.calls.map(([operation]) => operation)).not.toContain('passkeys.probe');
    expect(harness.rpc.mock.calls.map(([operation]) => operation)).toContain('passkeys.create');
  });
});
