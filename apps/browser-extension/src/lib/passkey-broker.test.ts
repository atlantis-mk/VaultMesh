import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DesktopRpcError } from './desktop-rpc';
import { buildRequestDetails, createPasskeyBroker, PASSKEY_PROMPT_WAIT_MS, type PasskeyPage, type PasskeyRequest } from './passkey-broker';
import { rememberPasskeyChoice, setSitePasskeyMode } from './passkey-preferences';
import { rememberLoginSelection } from './autofill-preferences';

const origin = 'https://example.test';
const partnerOrigin = 'https://auth.partner.test';
const page: PasskeyPage = { tabId: 7, frameId: 0, origin, pageUrl: `${origin}/login` };
const loginId = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
const item1 = '11111111-1111-4111-8111-111111111111';
const item2 = '22222222-2222-4222-8222-222222222222';
const getRequest: PasskeyRequest = { id: 'r1', operation: 'get', optionsJson: JSON.stringify({ challenge: 'Y2g', allowCredentials: [], extensions: {} }) };
const conditionalGetRequest: PasskeyRequest = {
  id: 'rc1',
  operation: 'get',
  optionsJson: JSON.stringify({ challenge: 'Y2g', allowCredentials: [], mediation: 'conditional', extensions: {} }),
};
const createRequest: PasskeyRequest = {
  id: 'r2', operation: 'create',
  optionsJson: JSON.stringify({ rp: { name: 'Example' }, user: { id: 'AQ', name: 'a' }, challenge: 'Y2g', pubKeyCredParams: [{ type: 'public-key', alg: -7 }], extensions: { credProps: true } }),
};
const topFrame = [{ frameId: 0, parentFrameId: -1, url: `${origin}/login` }];
const FALLBACK = { status: 'fallback' };

type Handlers = Partial<Record<string, (input?: Record<string, unknown>) => unknown>>;

function make(
  handlers: Handlers = {},
  options: {
    enabled?: boolean;
    supported?: boolean;
    frames?: typeof topFrame | (() => Promise<typeof topFrame>);
    showPrompt?: (page: PasskeyPage, prompt: unknown) => Promise<boolean>;
    defaultMode?: (operation: 'create' | 'get') => 'vaultmesh' | 'ask';
  } = {},
) {
  const hidden: string[] = [];
  const shown: unknown[] = [];
  const logs: string[] = [];
  const calls: Array<{ operation: string; input?: Record<string, unknown> }> = [];
  const rpc = vi.fn(async (operation: string, input?: Record<string, unknown>) => {
    calls.push({ operation, input });
    const handler = handlers[operation];
    if (handler) return handler(input);
    if (operation === 'vault.status') return { unlocked: true };
    if (operation === 'passkeys.probe') {
      return {
        status: 'available',
        rpId: 'example.test',
        origin,
        candidates: [{ itemId: item1, credentialId: 'c1', title: 'Example', account: 'a@example.test' }],
      };
    }
    if (operation === 'passkeys.get' || operation === 'passkeys.create') return { responseJson: '{"id":"x"}' };
    throw new Error(`unexpected ${operation}`);
  });
  const openPrompt = vi.fn(async () => undefined);
  const framesOption = options.frames;
  const broker = createPasskeyBroker({
    rpc: rpc as never,
    isEnabled: () => options.enabled !== false,
    isSupported: () => options.supported !== false,
    ...(options.defaultMode ? { defaultMode: options.defaultMode } : {}),
    frames: typeof framesOption === 'function' ? framesOption : async () => framesOption ?? topFrame,
    openPrompt,
    unlockPollMs: 10,
    log: (message) => logs.push(message),
    ...(options.showPrompt ? {
      showPrompt: async (p: PasskeyPage, prompt: unknown) => { shown.push(prompt); return options.showPrompt!(p, prompt); },
      hidePrompt: (_p: PasskeyPage, token: string) => hidden.push(token),
    } : {}),
  });
  return { broker, rpc, calls, openPrompt, logs, hidden, shown };
}

async function flush() { for (let index = 0; index < 32; index += 1) await Promise.resolve(); }

beforeEach(async () => browser.storage.local.clear());
afterEach(() => vi.useRealTimers());

describe('request details', () => {
  it('overwrites any page-supplied origin and drops unsupported extensions', () => {
    const details = buildRequestDetails({
      ...getRequest,
      optionsJson: JSON.stringify({
        challenge: 'Y2g',
        mediation: 'conditional',
        extensions: { remoteDesktopClientOverride: { origin: 'https://evil.test', sameOriginWithAncestors: false, topOrigin: 'https://evil.test' }, prf: {}, appid: 'https://example.test/app' },
      }),
    }, page);
    expect(details?.extensions).toEqual({ appid: 'https://example.test/app', remoteDesktopClientOverride: { origin, sameOriginWithAncestors: true } });
    expect(details?.rpId).toBe('example.test');
    expect(details).not.toHaveProperty('mediation');
  });

  it('writes authoritative cross-origin topOrigin and sameOriginWithAncestors=false', () => {
    const details = buildRequestDetails(getRequest, {
      origin: partnerOrigin,
      topOrigin: origin,
      sameOriginWithAncestors: false,
    });
    expect(details?.extensions).toEqual({
      remoteDesktopClientOverride: {
        origin: partnerOrigin,
        sameOriginWithAncestors: false,
        topOrigin: origin,
      },
    });
    expect(details?.rpId).toBe('auth.partner.test');
  });

  it('defaults the creation RP id from the verified origin and rejects malformed options', () => {
    expect((buildRequestDetails(createRequest, page)?.rp as { id: string }).id).toBe('example.test');
    expect(buildRequestDetails({ ...createRequest, optionsJson: '{' }, page)).toBeNull();
    expect(buildRequestDetails({ ...createRequest, optionsJson: '[]' }, page)).toBeNull();
    expect(buildRequestDetails({ ...createRequest, optionsJson: JSON.stringify({ challenge: 'x' }) }, page)).toBeNull();
  });
});

describe('fallback matrix & trusted frame ancestry', () => {
  it('falls back when browser adapter is unsupported or takeover is disabled, before contacting desktop', async () => {
    const unsupported = make({}, { supported: false });
    await expect(unsupported.broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(unsupported.rpc).not.toHaveBeenCalled();
    expect(unsupported.logs[0]).toContain('firefox-unsupported');

    const disabled = make({}, { enabled: false });
    await expect(disabled.broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(disabled.rpc).not.toHaveBeenCalled();
    expect(disabled.logs).toEqual(['[VaultMesh Passkey] get https://example.test -> browser (takeover-disabled)']);
  });

  it.each(['desktop-unavailable', 'unpaired'])('falls back when the desktop reports %s', async (code) => {
    const { broker, logs } = make({ 'vault.status': () => { throw new DesktopRpcError(code, 'x'); } });
    await expect(broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(logs[0]).toContain(`desktop-${code}`);
  });

  it('fails closed when getAllFrames fails or ancestry contains opaque/missing/cyclic frames', async () => {
    const failing = make({}, { frames: async () => { throw new Error('boom'); } });
    await expect(failing.broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(failing.rpc).not.toHaveBeenCalled();

    const opaque = make({}, {
      frames: [
        { frameId: 0, parentFrameId: -1, url: `${origin}/` },
        { frameId: 2, parentFrameId: 0, url: 'data:text/html,opaque' },
      ],
    });
    await expect(opaque.broker.handle(getRequest, { ...page, frameId: 2, origin: 'null' })).resolves.toEqual(FALLBACK);
    expect(opaque.rpc).not.toHaveBeenCalled();
  });

  it('serves verified cross-origin frames with authoritative topOrigin, composite get memory, and no create auto-remember', async () => {
    const frames = [
      { frameId: 0, parentFrameId: -1, url: `${origin}/` },
      { frameId: 2, parentFrameId: 0, url: `${partnerOrigin}/widget` },
      { frameId: 3, parentFrameId: 2, url: `${origin}/nested` },
    ];
    const crossPage: PasskeyPage = { tabId: 7, frameId: 2, origin: partnerOrigin };
    const { broker, calls } = make({}, { frames, defaultMode: () => 'ask' });

    const pendingCreate = broker.handle(createRequest, crossPage);
    await flush();
    const prompt = broker.currentPrompt()!;
    expect(prompt).toMatchObject({
      operation: 'create',
      origin: partnerOrigin,
      topOrigin: origin,
      sameOriginWithAncestors: false,
      stage: 'choose',
    });
    // Attempting to remember a cross-origin create must not auto-approve future requests.
    expect(broker.choose(prompt.token, 'vaultmesh', true)).toBe(true);
    await expect(pendingCreate).resolves.toMatchObject({ status: 'ok' });
    const createCall = calls.find((entry) => entry.operation === 'passkeys.create')!;
    expect(JSON.parse(createCall.input?.requestDetailsJson as string).extensions.remoteDesktopClientOverride).toEqual({
      origin: partnerOrigin,
      sameOriginWithAncestors: false,
      topOrigin: origin,
    });

    const secondCreate = broker.handle(createRequest, crossPage);
    await flush();
    expect(broker.currentPrompt()?.stage).toBe('choose');
    broker.choose(broker.currentPrompt()!.token, 'cancel');
    await expect(secondCreate).resolves.toMatchObject({ status: 'cancelled' });

    // Nested A -> B -> A must still set sameOriginWithAncestors=false.
    const nestedGet = broker.handle(getRequest, { ...page, frameId: 3 });
    await flush();
    expect(broker.currentPrompt()?.sameOriginWithAncestors).toBe(false);
    broker.choose(broker.currentPrompt()!.token, 'vaultmesh', true);
    await expect(nestedGet).resolves.toMatchObject({ status: 'ok' });
    const nestedCall = calls.find((entry) => entry.operation === 'passkeys.get')!;
    expect(JSON.parse(nestedCall.input?.requestDetailsJson as string).extensions.remoteDesktopClientOverride).toEqual({
      origin,
      sameOriginWithAncestors: false,
      topOrigin: origin,
    });
  });

  it('honours site mode native without probing or prompting', async () => {
    await setSitePasskeyMode(origin, 'native');
    const { broker, openPrompt, calls, logs } = make();
    await expect(broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(openPrompt).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
    expect(logs[0]).toContain('site-mode-native');
  });

  it('shows minimal no-match dialog when probe is unavailable and handles native (remember) and cancel without password-login', async () => {
    const probeUnavailable = {
      'vault.status': () => ({ unlocked: false }),
      'passkeys.probe': () => ({ status: 'unavailable', rpId: 'example.test', origin, candidates: [], hasLoginCandidates: true }),
    };

    const cancelFlow = make(probeUnavailable);
    const pendingCancel = cancelFlow.broker.handle(getRequest, page);
    await flush();
    const promptCancel = cancelFlow.broker.currentPrompt()!;
    expect(promptCancel).toMatchObject({ stage: 'no-match', origin });
    expect(promptCancel).not.toHaveProperty('hasLoginCandidates');
    expect(cancelFlow.broker.choose(promptCancel.token, 'cancel')).toBe(true);
    await expect(pendingCancel).resolves.toMatchObject({ status: 'cancelled' });

    const nativeFlow = make(probeUnavailable);
    const pendingNative = nativeFlow.broker.handle(getRequest, page);
    await flush();
    const promptNative = nativeFlow.broker.currentPrompt()!;
    nativeFlow.broker.choose(promptNative.token, 'native', true);
    await expect(pendingNative).resolves.toEqual(FALLBACK);

    // Remembered native choice skips probing on the next call.
    const next = make(probeUnavailable);
    await expect(next.broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(next.calls).toEqual([]);
  });

  it('falls back when the desktop finds no usable passkey on assertion', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker } = make({ 'passkeys.get': () => { throw new DesktopRpcError('passkey-unavailable', 'none'); } });
    await expect(broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
  });

  it('honours a remembered native choice without asking again', async () => {
    await rememberPasskeyChoice('create', origin, 'native');
    const { broker, openPrompt, calls } = make();
    await expect(broker.handle(createRequest, page)).resolves.toEqual(FALLBACK);
    expect(openPrompt).not.toHaveBeenCalled();
    expect(calls.map((call) => call.operation)).not.toContain('passkeys.create');
  });
});

describe('VaultMesh serving', () => {
  it('serves modal create even when zero login accounts exist', async () => {
    await rememberPasskeyChoice('create', origin, 'vaultmesh');
    const { broker, calls } = make();
    const outcome = await broker.handle(createRequest, page);
    expect(outcome).toEqual({ status: 'ok', responseJson: '{"id":"x"}' });
    const call = calls.find((entry) => entry.operation === 'passkeys.create')!;
    expect(call.input).not.toHaveProperty('loginId');
  });

  it('serves a remembered VaultMesh creation with the remembered Login hint and a trusted origin', async () => {
    await rememberPasskeyChoice('create', origin, 'vaultmesh');
    await rememberLoginSelection(origin, loginId);
    const { broker, calls } = make();
    const outcome = await broker.handle(createRequest, page);
    expect(outcome).toEqual({ status: 'ok', responseJson: '{"id":"x"}' });
    const call = calls.find((entry) => entry.operation === 'passkeys.create')!;
    expect(call.input?.loginId).toBe(loginId);
    expect(JSON.parse(call.input?.requestDetailsJson as string).extensions.remoteDesktopClientOverride).toEqual({ origin, sameOriginWithAncestors: true });
  });

  it('lets user choose between multiple matching passkeys and forwards itemId to passkeys.get', async () => {
    await setSitePasskeyMode(origin, 'vaultmesh');
    const { broker, calls } = make({
      'passkeys.probe': () => ({
        status: 'available',
        rpId: 'example.test',
        origin,
        candidates: [
          { itemId: item1, credentialId: 'c1', title: 'Personal', account: 'alice@example.test' },
          { itemId: item2, credentialId: 'c2', title: 'Work', account: 'bob@example.test' },
        ],
        hasLoginCandidates: false,
      }),
    });

    const pending = broker.handle(getRequest, page);
    await flush();
    const prompt = broker.currentPrompt()!;
    expect(prompt.stage).toBe('choose');
    expect(prompt.candidates).toHaveLength(2);
    expect(broker.choose(prompt.token, 'vaultmesh', false, undefined, item2)).toBe(true);
    await expect(pending).resolves.toEqual({ status: 'ok', responseJson: '{"id":"x"}' });
    const call = calls.find((entry) => entry.operation === 'passkeys.get')!;
    expect(call.input).toMatchObject({ itemId: item2, credentialId: 'c2' });
  });

  it('asks every time by default, serves VaultMesh on choice and can remember it', async () => {
    const { broker, calls } = make();
    const pending = broker.handle(createRequest, page);
    await flush();
    const prompt = broker.currentPrompt()!;
    expect(prompt).toMatchObject({ operation: 'create', origin, stage: 'choose' });
    expect(broker.choose(prompt.token, 'vaultmesh', true)).toBe(true);
    await expect(pending).resolves.toMatchObject({ status: 'ok' });
    expect(calls.map((call) => call.operation)).toContain('passkeys.create');

    const again = make();
    const second = again.broker.handle(createRequest, page);
    await flush();
    expect(again.broker.currentPrompt()).toBeNull();
    await expect(second).resolves.toMatchObject({ status: 'ok' });
  });

  it('hands the same call to the browser when the user picks it, and remembers that per operation', async () => {
    const { broker } = make({}, { defaultMode: () => 'ask' });
    const pending = broker.handle(getRequest, page);
    await flush();
    broker.choose(broker.currentPrompt()!.token, 'native', true);
    await expect(pending).resolves.toEqual(FALLBACK);

    const next = make({}, { defaultMode: () => 'ask' });
    await expect(next.broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(next.broker.currentPrompt()).toBeNull();
    // The choice for assertions does not decide creations.
    const create = next.broker.handle(createRequest, page);
    await flush();
    expect(next.broker.currentPrompt()?.stage).toBe('choose');
    next.broker.choose(next.broker.currentPrompt()!.token, 'cancel');
    await expect(create).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('keeps a user cancel as a cancel, not a fallback', async () => {
    const { broker } = make({}, { defaultMode: () => 'ask' });
    const pending = broker.handle(getRequest, page);
    await flush();
    broker.choose(broker.currentPrompt()!.token, 'cancel');
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('treats a cancelled native confirmation as a cancel', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker } = make({ 'passkeys.get': () => { throw new DesktopRpcError('cancelled', 'x'); } });
    await expect(broker.handle(getRequest, page)).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('maps other desktop failures to a typed error', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker } = make({ 'passkeys.get': () => { throw new DesktopRpcError('invalid-input', 'RP 不支持该算法'); } });
    await expect(broker.handle(getRequest, page)).resolves.toMatchObject({ status: 'error', name: 'NotSupportedError' });
  });

  it('rejects an oversized desktop response instead of forwarding it', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker } = make({ 'passkeys.get': () => ({ responseJson: 'x'.repeat(256 * 1024 + 1) }) });
    await expect(broker.handle(getRequest, page)).resolves.toMatchObject({ status: 'error' });
  });
});

describe('locked vault & one-shot desktop unlock', () => {
  it('calls passkeys.get directly while locked so desktop Touch ID/PIN one-shot unlock can handle it without extension unlock prompt', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker, calls, openPrompt } = make({
      'vault.status': () => ({ unlocked: false }),
      'passkeys.get': () => ({ responseJson: '{"id":"one-shot"}' }),
    });
    await expect(broker.handle(getRequest, page)).resolves.toEqual({ status: 'ok', responseJson: '{"id":"one-shot"}' });
    expect(calls.map((c) => c.operation)).toContain('passkeys.get');
    expect(openPrompt).not.toHaveBeenCalled();
    expect(broker.currentPrompt()).toBeNull();
  });

  it('falls back to extension unlock wait when desktop returns unlock-required, then serves the request', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    let unlocked = false;
    const { broker, openPrompt } = make({
      'vault.status': () => ({ unlocked }),
      'passkeys.get': () => {
        if (!unlocked) throw new DesktopRpcError('unlock-required', 'locked');
        return { responseJson: '{"id":"x"}' };
      },
    });
    vi.useFakeTimers();
    const pending = broker.handle(getRequest, page);
    await vi.advanceTimersByTimeAsync(5);
    expect(broker.currentPrompt()).toMatchObject({ stage: 'unlock' });
    expect(openPrompt).toHaveBeenCalledTimes(1);
    unlocked = true;
    await vi.advanceTimersByTimeAsync(30);
    await expect(pending).resolves.toMatchObject({ status: 'ok' });
    expect(broker.currentPrompt()).toBeNull();
  });

  it('opens the prompt only once when a choice is followed by an unlock-required fallback', async () => {
    let unlocked = false;
    const { broker, openPrompt } = make({
      'vault.status': () => ({ unlocked }),
      'passkeys.get': () => {
        if (!unlocked) throw new DesktopRpcError('unlock-required', 'locked');
        return { responseJson: '{"id":"x"}' };
      },
    }, { defaultMode: () => 'ask' });
    const pending = broker.handle(getRequest, page);
    await flush();
    broker.choose(broker.currentPrompt()!.token, 'vaultmesh');
    await flush();
    expect(broker.currentPrompt()?.stage).toBe('unlock');
    unlocked = true;
    await broker.syncUnlockState();
    await expect(pending).resolves.toMatchObject({ status: 'ok' });
    expect(openPrompt).toHaveBeenCalledTimes(1);
  });

  it('lets the user skip unlocking and use the browser instead', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker } = make({
      'vault.status': () => ({ unlocked: false }),
      'passkeys.get': () => { throw new DesktopRpcError('unlock-required', 'locked'); },
    });
    const pending = broker.handle(getRequest, page);
    await flush();
    expect(broker.choose(broker.currentPrompt()!.token, 'vaultmesh')).toBe(false);
    expect(broker.choose(broker.currentPrompt()!.token, 'native')).toBe(true);
    await expect(pending).resolves.toEqual(FALLBACK);
  });

  it('expires an unanswered unlock as a cancel after five minutes', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker } = make({
      'vault.status': () => ({ unlocked: false }),
      'passkeys.get': () => { throw new DesktopRpcError('unlock-required', 'locked'); },
    });
    vi.useFakeTimers();
    const pending = broker.handle(getRequest, page);
    await vi.advanceTimersByTimeAsync(PASSKEY_PROMPT_WAIT_MS + 1);
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
    expect(broker.currentPrompt()).toBeNull();
  });
});

describe('conditional mediation', () => {
  it('suspends only when enabled, allowed, non-native and probe has candidates, then resolves on inline selection', async () => {
    const { broker, openPrompt, calls, logs } = make({
      'vault.status': () => ({ unlocked: false }),
      'passkeys.probe': () => ({
        status: 'available',
        rpId: 'example.test',
        origin,
        candidates: [{ itemId: item1, credentialId: 'c1', title: 'Example', account: 'alice@example.test' }],
        hasLoginCandidates: false,
      }),
    });

    const pending = broker.handle(conditionalGetRequest, page);
    await flush();
    expect(openPrompt).not.toHaveBeenCalled();
    expect(broker.currentPrompt()).toBeNull();
    expect(logs.at(-1)).toContain('conditional-pending');

    expect(broker.conditionalCandidates(page)).toEqual([
      { requestId: 'rc1', itemId: item1, credentialId: 'c1', title: 'Example', account: 'alice@example.test' },
    ]);
    expect(broker.conditionalCandidates({ ...page, frameId: 9 })).toEqual([]);

    const outcome = await broker.resolveConditional(page, 'rc1', { action: 'vaultmesh', itemId: item1, credentialId: 'c1' });
    expect(outcome).toEqual({ status: 'ok' });
    await expect(pending).resolves.toEqual({ status: 'ok', responseJson: '{"id":"x"}' });
    expect(calls.find((c) => c.operation === 'passkeys.get')?.input).toMatchObject({ itemId: item1, credentialId: 'c1' });
    expect(broker.conditionalCandidates(page)).toEqual([]);
  });

  it('keeps conditional request suspended when desktop confirmation is cancelled so user can retry or fall back to native', async () => {
    let declinedOnce = false;
    const { broker } = make({
      'passkeys.get': () => {
        if (!declinedOnce) {
          declinedOnce = true;
          throw new DesktopRpcError('cancelled', '已取消。');
        }
        return { responseJson: '{"id":"retried"}' };
      },
    });

    const pending = broker.handle(conditionalGetRequest, page);
    await flush();
    expect(await broker.resolveConditional(page, 'rc1', { action: 'vaultmesh', itemId: item1, credentialId: 'c1' }))
      .toMatchObject({ status: 'cancelled' });
    expect(broker.conditionalCandidates(page)).toHaveLength(1);

    expect(await broker.resolveConditional(page, 'rc1', { action: 'vaultmesh', itemId: item1, credentialId: 'c1' }))
      .toEqual({ status: 'ok' });
    await expect(pending).resolves.toEqual({ status: 'ok', responseJson: '{"id":"retried"}' });
  });

  it('releases suspended conditional request to browser native when user chooses native fallback or site mode becomes native', async () => {
    const first = make();
    const pending1 = first.broker.handle(conditionalGetRequest, page);
    await flush();
    expect(await first.broker.resolveConditional(page, 'rc1', { action: 'native' })).toEqual({ status: 'fallback' });
    await expect(pending1).resolves.toEqual(FALLBACK);

    const second = make();
    const pending2 = second.broker.handle(conditionalGetRequest, page);
    await flush();
    second.broker.onSiteModeChanged(origin, 'native');
    await expect(pending2).resolves.toEqual(FALLBACK);
  });

  it('immediately falls back on conditional requests when site mode is native or probe has no candidates', async () => {
    const empty = make({
      'passkeys.probe': () => ({ status: 'unavailable', rpId: 'example.test', origin, candidates: [], hasLoginCandidates: true }),
    });
    await expect(empty.broker.handle(conditionalGetRequest, page)).resolves.toEqual(FALLBACK);
    expect(empty.broker.currentPrompt()).toBeNull();

    await setSitePasskeyMode(origin, 'native');
    const siteNative = make();
    await expect(siteNative.broker.handle(conditionalGetRequest, page)).resolves.toEqual(FALLBACK);
    expect(siteNative.calls).toEqual([]);
  });

  it('cleans up conditional requests on real history pathname navigation without killing same-path query/hash SPA updates', async () => {
    const { broker } = make();
    const pending = broker.handle(conditionalGetRequest, page);
    await flush();

    // Same path + query/hash or other frame must NOT kill the suspended request.
    broker.cancelHistoryNavigation(page.tabId, page.frameId, `${origin}/login?step=1#passkey`);
    broker.cancelHistoryNavigation(page.tabId, 2, `${origin}/dashboard`);
    expect(broker.conditionalCandidates(page)).toHaveLength(1);

    // Real pathname navigation on matching tab+frame cleans up cleanly.
    broker.cancelHistoryNavigation(page.tabId, page.frameId, `${origin}/dashboard`);
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
    expect(broker.conditionalCandidates(page)).toEqual([]);
  });
});

describe('cancellation', () => {
  it('aborts a pending choice when the page aborts', async () => {
    const { broker } = make({}, { defaultMode: () => 'ask' });
    const pending = broker.handle(getRequest, page);
    await flush();
    broker.abort(page, getRequest.id);
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
    expect(broker.currentPrompt()).toBeNull();
  });

  it('cancels every request owned by a navigated frame or closed tab, but not other tabs', async () => {
    const { broker } = make({}, { defaultMode: () => 'ask' });
    const mine = broker.handle(getRequest, page);
    const other = broker.handle({ ...getRequest, id: 'r9' }, { ...page, tabId: 8 });
    await flush();
    broker.cancelPage(7, 0);
    await expect(mine).resolves.toMatchObject({ status: 'cancelled' });
    expect(broker.currentPrompt()).not.toBeNull();
    broker.cancelPage(8);
    await expect(other).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('ignores stale or forged tokens', async () => {
    const { broker } = make();
    expect(broker.choose('00000000-0000-4000-8000-000000000000', 'vaultmesh')).toBe(false);
  });
});

describe('in-page prompt', () => {
  it('shows the prompt in the requesting tab, skips the extension window and hides it once answered', async () => {
    const { broker, openPrompt, shown, hidden } = make({}, { showPrompt: async () => true, defaultMode: () => 'ask' });
    const pending = broker.handle(getRequest, page);
    await flush();
    const prompt = broker.currentPrompt()!;
    expect(shown).toEqual([prompt]);
    expect(openPrompt).not.toHaveBeenCalled();
    broker.choose(prompt.token, 'native');
    await expect(pending).resolves.toEqual(FALLBACK);
    expect(hidden).toEqual([prompt.token]);
  });

  it('falls back to the extension window when the page cannot show the prompt', async () => {
    const { broker, openPrompt } = make({}, { showPrompt: async () => false, defaultMode: () => 'ask' });
    const pending = broker.handle(getRequest, page);
    await flush();
    await flush();
    expect(openPrompt).toHaveBeenCalledTimes(1);
    broker.choose(broker.currentPrompt()!.token, 'cancel');
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('lets a page dialog answer only prompts of its own tab', async () => {
    const { broker } = make({}, { showPrompt: async () => true, defaultMode: () => 'ask' });
    const pending = broker.handle(getRequest, page);
    await flush();
    const { token } = broker.currentPrompt()!;
    expect(broker.choose(token, 'vaultmesh', false, 99)).toBe(false);
    expect(broker.currentPrompt()).not.toBeNull();
    expect(broker.choose(token, 'cancel', false, page.tabId)).toBe(true);
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('shows the unlock stage in the page after the user chose VaultMesh when desktop falls back to unlock-required', async () => {
    let unlocked = false;
    const { broker, shown, openPrompt } = make({
      'vault.status': () => ({ unlocked }),
      'passkeys.get': () => {
        if (!unlocked) throw new DesktopRpcError('unlock-required', 'locked');
        return { responseJson: '{"id":"x"}' };
      },
    }, { showPrompt: async () => true, defaultMode: () => 'ask' });
    const pending = broker.handle(getRequest, page);
    await flush();
    broker.choose(broker.currentPrompt()!.token, 'vaultmesh');
    await flush();
    expect((shown as Array<{ stage: string }>).map((prompt) => prompt.stage)).toEqual(['choose', 'unlock']);
    unlocked = true;
    await broker.syncUnlockState();
    await expect(pending).resolves.toMatchObject({ status: 'ok' });
    expect(openPrompt).not.toHaveBeenCalled();
  });
});

describe('cancel and failure reasons are attributable', () => {
  it('logs why a request ended as a cancel', async () => {
    const choice = make();
    const pending = choice.broker.handle(createRequest, page);
    await flush();
    choice.broker.choose(choice.broker.currentPrompt()!.token, 'cancel');
    await pending;
    expect(choice.logs).toEqual([
      '[VaultMesh Passkey] create https://example.test -> prompt (choose, extension-window)',
      '[VaultMesh Passkey] create https://example.test -> cancelled (user-cancelled-choice)',
    ]);

    await rememberPasskeyChoice('create', origin, 'vaultmesh');
    const declined = make({ 'passkeys.create': () => { throw new DesktopRpcError('cancelled', 'x'); } });
    await declined.broker.handle(createRequest, page);
    expect(declined.logs.at(-1)).toContain('desktop-confirmation-declined');
  });

  it('logs the desktop error that made a creation fail', async () => {
    await rememberPasskeyChoice('create', origin, 'vaultmesh');
    const { broker, logs } = make({ 'passkeys.create': () => { throw new DesktopRpcError('invalid-input', '该账户已存在 Passkey。'); } });
    await expect(broker.handle(createRequest, page)).resolves.toMatchObject({ status: 'error', name: 'InvalidStateError' });
    expect(logs.at(-1)).toBe('[VaultMesh Passkey] create https://example.test -> error (InvalidStateError, desktop-invalid-input: 该账户已存在 Passkey。)');
  });

  it('logs an unlock timeout separately from a user cancel', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker, logs } = make({
      'vault.status': () => ({ unlocked: false }),
      'passkeys.get': () => { throw new DesktopRpcError('unlock-required', 'locked'); },
    });
    vi.useFakeTimers();
    const pending = broker.handle(getRequest, page);
    await vi.advanceTimersByTimeAsync(PASSKEY_PROMPT_WAIT_MS + 1);
    await pending;
    expect(logs).toContain('[VaultMesh Passkey] get https://example.test -> VaultMesh (remembered-vaultmesh-choice)');
    expect(logs.some((line) => line.includes('prompt (unlock'))).toBe(true);
    expect(logs.at(-1)).toContain('unlock-timed-out');
  });
});

describe('availability', () => {
  it('is available for a same-origin or verified cross-origin page with a paired desktop, even while locked', async () => {
    const same = make({ 'vault.status': () => ({ unlocked: false }) });
    await expect(same.broker.availability(page)).resolves.toBe(true);

    const cross = make(
      { 'vault.status': () => ({ unlocked: false }) },
      { frames: [{ frameId: 0, parentFrameId: -1, url: 'https://other.test/' }, { frameId: 4, parentFrameId: 0, url: `${origin}/inner` }] },
    );
    await expect(cross.broker.availability({ ...page, frameId: 4 })).resolves.toBe(true);
  });

  it.each([
    ['takeover disabled', { enabled: false }],
    ['unsupported adapter', { supported: false }],
    ['opaque/broken ancestry', { frames: [{ frameId: 0, parentFrameId: -1, url: 'data:text/html,x' }, { frameId: 4, parentFrameId: 0, url: `${origin}/inner` }] }],
  ])('is unavailable for %s without contacting the desktop', async (_name, options) => {
    const { broker, rpc } = make({}, options as never);
    await expect(broker.availability({ ...page, frameId: 4 })).resolves.toBe(false);
    expect(rpc).not.toHaveBeenCalled();
  });

  it('is unavailable, and says why, when the desktop is unpaired or unreachable', async () => {
    const { broker, logs } = make({ 'vault.status': () => { throw new DesktopRpcError('unpaired', 'x'); } });
    await expect(broker.availability(page)).resolves.toBe(false);
    expect(logs[0]).toContain('desktop-unpaired');
  });
});

describe('success and progress are recorded too', () => {
  it('records the prompt, the choice and that VaultMesh served the credential', async () => {
    const { broker, logs } = make({}, { showPrompt: async () => true });
    const pending = broker.handle(createRequest, page);
    await flush();
    broker.choose(broker.currentPrompt()!.token, 'vaultmesh');
    await expect(pending).resolves.toMatchObject({ status: 'ok' });
    expect(logs).toEqual([
      '[VaultMesh Passkey] create https://example.test -> prompt (choose, in-page)',
      '[VaultMesh Passkey] create https://example.test -> VaultMesh (chose-vaultmesh)',
      '[VaultMesh Passkey] create https://example.test -> VaultMesh (served)',
    ]);
  });

  it('records a served credential without a prompt when the choice was remembered', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker, logs } = make();
    await broker.handle(getRequest, page);
    expect(logs).toEqual([
      '[VaultMesh Passkey] get https://example.test -> VaultMesh (remembered-vaultmesh-choice)',
      '[VaultMesh Passkey] get https://example.test -> VaultMesh (served)',
    ]);
  });
});

describe('global default modes (passkeyGetDefault / passkeyCreateDefault) and probe rules', () => {
  it('defaults get to vaultmesh and skips choose prompt for a single available candidate', async () => {
    const { broker, openPrompt, logs } = make();
    const outcome = await broker.handle(getRequest, page);
    expect(outcome).toEqual({ status: 'ok', responseJson: '{"id":"x"}' });
    expect(openPrompt).not.toHaveBeenCalled();
    expect(broker.currentPrompt()).toBeNull();
    expect(logs).toEqual([
      '[VaultMesh Passkey] get https://example.test -> VaultMesh (default-vaultmesh)',
      '[VaultMesh Passkey] get https://example.test -> VaultMesh (served)',
    ]);
  });

  it('still prompts when get has multiple candidates even under default vaultmesh', async () => {
    const { broker, calls } = make({
      'passkeys.probe': () => ({
        status: 'available',
        rpId: 'example.test',
        origin,
        candidates: [
          { itemId: item1, credentialId: 'c1', title: 'Personal', account: 'alice@example.test' },
          { itemId: item2, credentialId: 'c2', title: 'Work', account: 'bob@example.test' },
        ],
      }),
    });
    const pending = broker.handle(getRequest, page);
    await flush();
    const prompt = broker.currentPrompt()!;
    expect(prompt.stage).toBe('choose');
    expect(prompt.candidates).toHaveLength(2);
    expect(broker.choose(prompt.token, 'vaultmesh', false, undefined, item2)).toBe(true);
    await expect(pending).resolves.toEqual({ status: 'ok', responseJson: '{"id":"x"}' });
    expect(calls.find((c) => c.operation === 'passkeys.get')?.input).toMatchObject({ itemId: item2, credentialId: 'c2' });
  });

  it('conservatively shows choose prompt when get probe status is unknown under default-vaultmesh', async () => {
    const { broker } = make({
      'passkeys.probe': () => ({ status: 'unknown', rpId: 'example.test', origin, candidates: [] }),
    });
    const pending = broker.handle(getRequest, page);
    await flush();
    const prompt = broker.currentPrompt()!;
    expect(prompt.stage).toBe('choose');
    broker.choose(prompt.token, 'cancel');
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('skips choose prompt when site mode is explicitly vaultmesh even if probe status is unknown', async () => {
    await setSitePasskeyMode(origin, 'vaultmesh');
    const { broker, logs } = make({
      'passkeys.probe': () => ({ status: 'unknown', rpId: 'example.test', origin, candidates: [] }),
    });
    await expect(broker.handle(getRequest, page)).resolves.toEqual({ status: 'ok', responseJson: '{"id":"x"}' });
    expect(logs).toEqual([
      '[VaultMesh Passkey] get https://example.test -> VaultMesh (site-mode-vaultmesh)',
      '[VaultMesh Passkey] get https://example.test -> VaultMesh (served)',
    ]);
  });

  it('respects site mode ask override even when global get default is vaultmesh', async () => {
    await setSitePasskeyMode(origin, 'ask');
    const { broker, logs } = make();
    const pending = broker.handle(getRequest, page);
    await flush();
    const prompt = broker.currentPrompt()!;
    expect(prompt.stage).toBe('choose');
    broker.choose(prompt.token, 'vaultmesh');
    await expect(pending).resolves.toEqual({ status: 'ok', responseJson: '{"id":"x"}' });
    expect(logs).toContain('[VaultMesh Passkey] get https://example.test -> prompt (site-mode-ask)');
  });

  it('skips choose prompt on same-origin create when create default is vaultmesh, but still prompts cross-origin create', async () => {
    const sameOrigin = make({}, { defaultMode: (op) => (op === 'create' ? 'vaultmesh' : 'vaultmesh') });
    await expect(sameOrigin.broker.handle(createRequest, page)).resolves.toEqual({ status: 'ok', responseJson: '{"id":"x"}' });
    expect(sameOrigin.logs).toEqual([
      '[VaultMesh Passkey] create https://example.test -> VaultMesh (default-vaultmesh)',
      '[VaultMesh Passkey] create https://example.test -> VaultMesh (served)',
    ]);

    const frames = [
      { frameId: 0, parentFrameId: -1, url: `${origin}/` },
      { frameId: 2, parentFrameId: 0, url: `${partnerOrigin}/widget` },
    ];
    const cross = make({}, { frames, defaultMode: () => 'vaultmesh' });
    const pending = cross.broker.handle(createRequest, { tabId: 7, frameId: 2, origin: partnerOrigin });
    await flush();
    expect(cross.broker.currentPrompt()).toMatchObject({
      stage: 'choose',
      operation: 'create',
      sameOriginWithAncestors: false,
    });
    cross.broker.choose(cross.broker.currentPrompt()!.token, 'cancel');
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
  });
});
