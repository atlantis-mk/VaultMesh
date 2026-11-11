import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DesktopRpcError } from './desktop-rpc';
import { buildRequestDetails, createPasskeyBroker, PASSKEY_PROMPT_WAIT_MS, type PasskeyPage, type PasskeyRequest } from './passkey-broker';
import { rememberPasskeyChoice } from './passkey-preferences';
import { rememberLoginSelection } from './autofill-preferences';

const origin = 'https://example.test';
const page: PasskeyPage = { tabId: 7, frameId: 0, origin };
const loginId = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
const getRequest: PasskeyRequest = { id: 'r1', operation: 'get', optionsJson: JSON.stringify({ challenge: 'Y2g', allowCredentials: [], extensions: {} }) };
const createRequest: PasskeyRequest = {
  id: 'r2', operation: 'create',
  optionsJson: JSON.stringify({ rp: { name: 'Example' }, user: { id: 'AQ', name: 'a' }, challenge: 'Y2g', pubKeyCredParams: [{ type: 'public-key', alg: -7 }], extensions: { credProps: true } }),
};
const topFrame = [{ frameId: 0, parentFrameId: -1, url: `${origin}/login` }];
const FALLBACK = { status: 'fallback' };

type Handlers = Partial<Record<string, (input?: Record<string, unknown>) => unknown>>;

function make(handlers: Handlers = {}, options: { enabled?: boolean; frames?: typeof topFrame; showPrompt?: (page: PasskeyPage, prompt: unknown) => Promise<boolean> } = {}) {
  const hidden: string[] = [];
  const shown: unknown[] = [];
  const logs: string[] = [];
  const calls: Array<{ operation: string; input?: Record<string, unknown> }> = [];
  const rpc = vi.fn(async (operation: string, input?: Record<string, unknown>) => {
    calls.push({ operation, input });
    const handler = handlers[operation];
    if (handler) return handler(input);
    if (operation === 'vault.status') return { unlocked: true };
    if (operation === 'passkeys.probe') return { status: 'available', rpId: 'example.test', origin };
    if (operation === 'passkeys.get' || operation === 'passkeys.create') return { responseJson: '{"id":"x"}' };
    throw new Error(`unexpected ${operation}`);
  });
  const openPrompt = vi.fn(async () => undefined);
  const broker = createPasskeyBroker({
    rpc: rpc as never,
    isEnabled: () => options.enabled !== false,
    frames: async () => options.frames ?? topFrame,
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

async function flush() { for (let index = 0; index < 8; index += 1) await Promise.resolve(); }

beforeEach(async () => browser.storage.local.clear());
afterEach(() => vi.useRealTimers());

describe('request details', () => {
  it('overwrites any page-supplied origin and drops unsupported extensions', () => {
    const details = buildRequestDetails({
      ...getRequest,
      optionsJson: JSON.stringify({ challenge: 'Y2g', extensions: { remoteDesktopClientOverride: { origin: 'https://evil.test', sameOriginWithAncestors: false }, prf: {}, appid: 'https://example.test/app' } }),
    }, page);
    expect(details?.extensions).toEqual({ appid: 'https://example.test/app', remoteDesktopClientOverride: { origin, sameOriginWithAncestors: true } });
    expect(details?.rpId).toBe('example.test');
  });

  it('defaults the creation RP id from the verified origin and rejects malformed options', () => {
    expect((buildRequestDetails(createRequest, page)?.rp as { id: string }).id).toBe('example.test');
    expect(buildRequestDetails({ ...createRequest, optionsJson: '{' }, page)).toBeNull();
    expect(buildRequestDetails({ ...createRequest, optionsJson: '[]' }, page)).toBeNull();
    expect(buildRequestDetails({ ...createRequest, optionsJson: JSON.stringify({ challenge: 'x' }) }, page)).toBeNull();
  });
});

describe('fallback matrix: the browser serves the same call without a retry', () => {
  it('falls back when passkey takeover is disabled, before contacting the desktop', async () => {
    const { broker, rpc, logs } = make({}, { enabled: false });
    await expect(broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(rpc).not.toHaveBeenCalled();
    expect(logs).toEqual(['[VaultMesh Passkey] get https://example.test -> browser (takeover-disabled)']);
  });

  it.each(['desktop-unavailable', 'unpaired'])('falls back when the desktop reports %s', async (code) => {
    const { broker, logs } = make({ 'vault.status': () => { throw new DesktopRpcError(code, 'x'); } });
    await expect(broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(logs[0]).toContain(`desktop-${code}`);
  });

  it('falls back from a cross-origin frame or one below a cross-origin ancestor', async () => {
    const frames = [
      { frameId: 0, parentFrameId: -1, url: `${origin}/` },
      { frameId: 2, parentFrameId: 0, url: 'https://other.test/' },
      { frameId: 3, parentFrameId: 2, url: `${origin}/inner` },
    ];
    const { broker, rpc } = make({}, { frames });
    await expect(broker.handle(getRequest, { ...page, frameId: 2, origin: 'https://other.test' })).resolves.toEqual(FALLBACK);
    await expect(broker.handle(getRequest, { ...page, frameId: 3 })).resolves.toEqual(FALLBACK);
    expect(rpc).not.toHaveBeenCalled();
  });

  it('falls back without prompting when the index proves VaultMesh has no matching passkey, even while locked', async () => {
    const { broker, openPrompt, calls, logs } = make({
      'vault.status': () => ({ unlocked: false }),
      'passkeys.probe': () => ({ status: 'unavailable', rpId: 'example.test', origin }),
    });
    await expect(broker.handle(getRequest, page)).resolves.toEqual(FALLBACK);
    expect(logs[0]).toContain('no-matching-passkey');
    expect(openPrompt).not.toHaveBeenCalled();
    expect(calls.map((call) => call.operation)).not.toContain('passkeys.get');
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
    const { broker } = make();
    const pending = broker.handle(getRequest, page);
    await flush();
    broker.choose(broker.currentPrompt()!.token, 'native', true);
    await expect(pending).resolves.toEqual(FALLBACK);

    const next = make();
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
    const { broker } = make();
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

describe('locked vault', () => {
  it('waits for unlock after the user chose VaultMesh, then serves the request', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    let unlocked = false;
    const { broker, openPrompt } = make({ 'vault.status': () => ({ unlocked }) });
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

  it('opens the prompt only once when a choice is followed by an unlock wait', async () => {
    let unlocked = false;
    const { broker, openPrompt } = make({ 'vault.status': () => ({ unlocked }) });
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
    const { broker } = make({ 'vault.status': () => ({ unlocked: false }) });
    const pending = broker.handle(getRequest, page);
    await flush();
    expect(broker.choose(broker.currentPrompt()!.token, 'vaultmesh')).toBe(false);
    expect(broker.choose(broker.currentPrompt()!.token, 'native')).toBe(true);
    await expect(pending).resolves.toEqual(FALLBACK);
  });

  it('expires an unanswered unlock as a cancel after five minutes', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker } = make({ 'vault.status': () => ({ unlocked: false }) });
    vi.useFakeTimers();
    const pending = broker.handle(getRequest, page);
    await vi.advanceTimersByTimeAsync(PASSKEY_PROMPT_WAIT_MS + 1);
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
    expect(broker.currentPrompt()).toBeNull();
  });
});

describe('cancellation', () => {
  it('aborts a pending choice when the page aborts', async () => {
    const { broker } = make();
    const pending = broker.handle(getRequest, page);
    await flush();
    broker.abort(page, getRequest.id);
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
    expect(broker.currentPrompt()).toBeNull();
  });

  it('cancels every request owned by a navigated frame or closed tab, but not other tabs', async () => {
    const { broker } = make();
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
    const { broker, openPrompt, shown, hidden } = make({}, { showPrompt: async () => true });
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
    const { broker, openPrompt } = make({}, { showPrompt: async () => false });
    const pending = broker.handle(getRequest, page);
    await flush();
    await flush();
    expect(openPrompt).toHaveBeenCalledTimes(1);
    broker.choose(broker.currentPrompt()!.token, 'cancel');
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('lets a page dialog answer only prompts of its own tab', async () => {
    const { broker } = make({}, { showPrompt: async () => true });
    const pending = broker.handle(getRequest, page);
    await flush();
    const { token } = broker.currentPrompt()!;
    expect(broker.choose(token, 'vaultmesh', false, 99)).toBe(false);
    expect(broker.currentPrompt()).not.toBeNull();
    expect(broker.choose(token, 'cancel', false, page.tabId)).toBe(true);
    await expect(pending).resolves.toMatchObject({ status: 'cancelled' });
  });

  it('shows the unlock stage in the page after the user chose VaultMesh on a locked vault', async () => {
    let unlocked = false;
    const { broker, shown, openPrompt } = make({ 'vault.status': () => ({ unlocked }) }, { showPrompt: async () => true });
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
    expect(choice.logs).toEqual(['[VaultMesh Passkey] create https://example.test -> cancelled (user-cancelled-choice)']);

    await rememberPasskeyChoice('create', origin, 'vaultmesh');
    const declined = make({ 'passkeys.create': () => { throw new DesktopRpcError('cancelled', 'x'); } });
    await declined.broker.handle(createRequest, page);
    expect(declined.logs[0]).toContain('desktop-confirmation-declined');
  });

  it('logs the desktop error that made a creation fail', async () => {
    await rememberPasskeyChoice('create', origin, 'vaultmesh');
    const { broker, logs } = make({ 'passkeys.create': () => { throw new DesktopRpcError('invalid-input', '该账户已存在 Passkey。'); } });
    await expect(broker.handle(createRequest, page)).resolves.toMatchObject({ status: 'error', name: 'InvalidStateError' });
    expect(logs[0]).toBe('[VaultMesh Passkey] create https://example.test -> error (InvalidStateError, desktop-invalid-input: 该账户已存在 Passkey。)');
  });

  it('logs an unlock timeout separately from a user cancel', async () => {
    await rememberPasskeyChoice('get', origin, 'vaultmesh');
    const { broker, logs } = make({ 'vault.status': () => ({ unlocked: false }) });
    vi.useFakeTimers();
    const pending = broker.handle(getRequest, page);
    await vi.advanceTimersByTimeAsync(PASSKEY_PROMPT_WAIT_MS + 1);
    await pending;
    expect(logs[0]).toContain('unlock-timed-out');
  });
});

describe('availability', () => {
  it('is available for a same-origin page with a paired desktop, even while the vault is locked', async () => {
    const { broker } = make({ 'vault.status': () => ({ unlocked: false }) });
    await expect(broker.availability(page)).resolves.toBe(true);
  });

  it.each([
    ['takeover disabled', { enabled: false }],
    ['a cross-origin frame', { frames: [{ frameId: 0, parentFrameId: -1, url: 'https://other.test/' }, { frameId: 4, parentFrameId: 0, url: `${origin}/inner` }] }],
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
