import { describe, expect, it, vi } from 'vitest';

import { createWindowTransport, installCapabilityShim, installPasskeyShim, PASSKEY_ACK_TIMEOUT_MS, PASSKEY_AVAILABILITY_TTL_MS, PASSKEY_CHANNEL, type PasskeyShimResult, type PasskeyShimTransport } from './passkey-shim';
import { fromBase64Url, toBase64Url } from './passkey-shim-codec';

class FakePublicKeyCredential {}
class FakeAttestation {}
class FakeAssertion {}
const constructors = {
  PublicKeyCredential: FakePublicKeyCredential,
  AuthenticatorAttestationResponse: FakeAttestation,
  AuthenticatorAssertionResponse: FakeAssertion,
};

const bytes = (...values: number[]) => new Uint8Array(values).buffer;
const NATIVE = { native: true } as unknown as Credential;

function setup(result: PasskeyShimResult | (() => Promise<PasskeyShimResult>)) {
  const nativeCreate = vi.fn(async (_options?: unknown) => NATIVE);
  const nativeGet = vi.fn(async (_options?: unknown) => NATIVE);
  const prototype = { create: nativeCreate as unknown as (o?: unknown) => Promise<Credential | null>, get: nativeGet as unknown as (o?: unknown) => Promise<Credential | null> };
  const transport: PasskeyShimTransport = {
    request: vi.fn(async () => (typeof result === 'function' ? result() : result)),
    abort: vi.fn(),
  };
  installPasskeyShim(prototype as never, transport, constructors, () => 'request-id');
  return { prototype, transport, nativeCreate, nativeGet };
}

const creation = (): PublicKeyCredentialCreationOptions => ({
  rp: { name: 'Example' },
  user: { id: bytes(1, 2, 3), name: 'a@example.test', displayName: 'A' },
  challenge: bytes(250, 251, 252),
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  excludeCredentials: [{ type: 'public-key', id: bytes(9, 9) }],
  authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
  extensions: { credProps: true },
});
const request = (): PublicKeyCredentialRequestOptions => ({ challenge: bytes(1, 2), allowCredentials: [{ type: 'public-key', id: bytes(7) }] });

const registrationJson = JSON.stringify({
  id: 'AQID', rawId: 'AQID', type: 'public-key', authenticatorAttachment: 'platform',
  response: { clientDataJSON: 'e30', attestationObject: 'oA', authenticatorData: 'AQ', publicKey: 'Ag', publicKeyAlgorithm: -7, transports: ['internal'] },
  clientExtensionResults: { credProps: { rk: true } },
});
const assertionJson = JSON.stringify({
  id: 'AQID', rawId: 'AQID', type: 'public-key', authenticatorAttachment: 'platform',
  response: { clientDataJSON: 'e30', authenticatorData: 'AQ', signature: 'Aw', userHandle: 'BA' },
  clientExtensionResults: {},
});

describe('base64url codec', () => {
  it('round-trips bytes and rejects non-canonical input', () => {
    expect(toBase64Url(bytes(250, 251, 252, 253))).toBe('-vv8_Q');
    expect([...new Uint8Array(fromBase64Url('-vv8_Q'))]).toEqual([250, 251, 252, 253]);
    expect(() => fromBase64Url('a+b/')).toThrow();
    expect(() => fromBase64Url('abcde')).toThrow();
  });
});

describe('WebAuthn page shim', () => {
  it('serialises creation options without page-controlled origin data and returns a PublicKeyCredential', async () => {
    const { prototype, transport } = setup({ status: 'ok', responseJson: registrationJson });
    const credential = await prototype.create({ publicKey: creation() }) as unknown as PublicKeyCredential;

    const [id, operation, options] = vi.mocked(transport.request).mock.calls[0];
    expect(id).toBe('request-id');
    expect(operation).toBe('create');
    expect(options).toMatchObject({
      challenge: '-vv8', user: { id: 'AQID', name: 'a@example.test' }, excludeCredentials: [{ type: 'public-key', id: 'CQk' }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' }, extensions: { credProps: true },
    });
    expect(JSON.stringify(options)).not.toContain('remoteDesktopClientOverride');
    expect(credential instanceof (FakePublicKeyCredential as never)).toBe(true);
    expect(credential.id).toBe('AQID');
    expect(credential.getClientExtensionResults()).toEqual({ credProps: { rk: true } });
    expect(new Uint8Array((credential.response as AuthenticatorAttestationResponse).attestationObject)).toEqual(new Uint8Array([160]));
    expect((credential.response as AuthenticatorAttestationResponse).getTransports()).toEqual(['internal']);
  });

  it('returns an assertion whose userHandle and signature are buffers', async () => {
    const { prototype } = setup({ status: 'ok', responseJson: assertionJson });
    const credential = await prototype.get({ publicKey: request() }) as unknown as PublicKeyCredential;
    const response = credential.response as AuthenticatorAssertionResponse;
    expect(new Uint8Array(response.signature)).toEqual(new Uint8Array([3]));
    expect(new Uint8Array(response.userHandle as ArrayBuffer)).toEqual(new Uint8Array([4]));
  });

  it('calls the browser authenticator in the same call when VaultMesh falls back', async () => {
    const { prototype, nativeCreate, nativeGet } = setup({ status: 'fallback' });
    const createOptions = { publicKey: creation() };
    await expect(prototype.create(createOptions)).resolves.toBe(NATIVE);
    await expect(prototype.get({ publicKey: request() })).resolves.toBe(NATIVE);
    expect(nativeCreate).toHaveBeenCalledWith(createOptions);
    expect(nativeGet).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['password credential requests', () => ({ password: true })],
    ['conditional mediation', () => ({ publicKey: request(), mediation: 'conditional' })],
    ['an already aborted signal', () => ({ publicKey: request(), signal: AbortSignal.abort() })],
    ['extensions VaultMesh cannot serve', () => ({ publicKey: { ...request(), extensions: { prf: { eval: { first: bytes(1) } } } } })],
  ])('never contacts VaultMesh for %s', async (_name, make) => {
    const { prototype, transport, nativeGet } = setup({ status: 'ok', responseJson: assertionJson });
    await prototype.get(make() as never);
    expect(transport.request).not.toHaveBeenCalled();
    expect(nativeGet).toHaveBeenCalledTimes(1);
  });

  it('falls back when the transport fails or the response is malformed', async () => {
    const failing = setup(async () => { throw new Error('bridge gone'); });
    await expect(failing.prototype.get({ publicKey: request() })).resolves.toBe(NATIVE);
    const malformed = setup({ status: 'ok', responseJson: '{"type":"password"}' });
    await expect(malformed.prototype.get({ publicKey: request() })).resolves.toBe(NATIVE);
  });

  it('turns a user cancel into NotAllowedError without touching the browser authenticator', async () => {
    const { prototype, nativeGet } = setup({ status: 'cancelled', message: '已取消' });
    await expect(prototype.get({ publicKey: request() })).rejects.toMatchObject({ name: 'NotAllowedError', message: '已取消' });
    expect(nativeGet).not.toHaveBeenCalled();
  });

  it('maps desktop errors to a safe DOMException name', async () => {
    const supported = setup({ status: 'error', name: 'NotSupportedError', message: '算法不支持' });
    await expect(supported.prototype.create({ publicKey: creation() })).rejects.toMatchObject({ name: 'NotSupportedError' });
    const unknown = setup({ status: 'error', name: 'TypeError', message: 'x' });
    await expect(unknown.prototype.create({ publicKey: creation() })).rejects.toMatchObject({ name: 'NotAllowedError' });
  });

  it('rejects with the abort reason and tells the bridge when the page aborts', async () => {
    const { prototype, transport } = setup(() => new Promise(() => undefined));
    const controller = new AbortController();
    const pending = prototype.get({ publicKey: request(), signal: controller.signal });
    await Promise.resolve();
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(transport.abort).toHaveBeenCalledWith('request-id');
  });
});

describe('extension handling', () => {
  it('serves requests that carry advisory extensions and forwards only the supported ones', async () => {
    const { prototype, transport, nativeGet } = setup({ status: 'ok', responseJson: assertionJson });
    await prototype.get({
      publicKey: { ...request(), extensions: { appid: 'https://example.test/app', uvm: true, credentialProtectionPolicy: 'userVerificationOptional', appidExclude: 'x' } as never },
    });
    expect(nativeGet).not.toHaveBeenCalled();
    expect(vi.mocked(transport.request).mock.calls[0][2].extensions).toEqual({ appid: 'https://example.test/app' });
  });

  it.each([
    ['prf', { prf: { eval: { first: bytes(1) } } }],
    ['largeBlob', { largeBlob: { support: 'preferred' } }],
    ['hmacCreateSecret', { hmacCreateSecret: true }],
    ['enforceCredentialProtectionPolicy', { enforceCredentialProtectionPolicy: true }],
  ])('hands requests with the result-bearing %s extension to the browser and says why', async (name, extensions) => {
    const reasons: string[] = [];
    const nativeGet = vi.fn(async (_options?: unknown) => NATIVE);
    const transport: PasskeyShimTransport = { request: vi.fn(), abort: vi.fn() };
    const target = { create: vi.fn(), get: nativeGet };
    installPasskeyShim(target as never, transport, constructors, () => 'id', (reason) => reasons.push(reason));
    await (target.get as unknown as (o: unknown) => Promise<unknown>)({ publicKey: { ...request(), extensions } });
    expect(transport.request).not.toHaveBeenCalled();
    expect(reasons).toEqual([`unsupported-extension:${name}`]);
  });
});

describe('window transport', () => {
  const options = { challenge: 'AQ' };

  it('falls back when no bridge acknowledges the request', async () => {
    vi.useFakeTimers();
    try {
      const transport = createWindowTransport(window);
      const pending = transport.request('no-bridge', 'get', options);
      await vi.advanceTimersByTimeAsync(PASSKEY_ACK_TIMEOUT_MS + 1);
      await expect(pending).resolves.toEqual({ status: 'fallback' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('waits for the response once the bridge has acknowledged and ignores foreign messages', async () => {
    vi.useFakeTimers();
    try {
      const transport = createWindowTransport(window);
      const pending = transport.request('with-bridge', 'get', options);
      const deliver = (data: unknown, source: unknown = window) => window.dispatchEvent(new MessageEvent('message', { data, source: source as Window }));
      deliver({ channel: PASSKEY_CHANNEL, direction: 'ack', id: 'with-bridge' });
      await vi.advanceTimersByTimeAsync(PASSKEY_ACK_TIMEOUT_MS * 4);
      deliver({ channel: PASSKEY_CHANNEL, direction: 'response', id: 'with-bridge', result: { status: 'cancelled' } }, {});
      deliver({ channel: 'other', direction: 'response', id: 'with-bridge', result: { status: 'cancelled' } });
      deliver({ channel: PASSKEY_CHANNEL, direction: 'response', id: 'with-bridge', result: { status: 'ok', responseJson: '{}' } });
      await expect(pending).resolves.toEqual({ status: 'ok', responseJson: '{}' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('treats an unrecognised result as a fallback', async () => {
    const transport = createWindowTransport(window);
    const pending = transport.request('odd', 'get', options);
    window.dispatchEvent(new MessageEvent('message', { data: { channel: PASSKEY_CHANNEL, direction: 'response', id: 'odd', result: { status: 'weird' } }, source: window }));
    await expect(pending).resolves.toEqual({ status: 'fallback' });
  });
});

describe('platform capability queries', () => {
  function capabilitySetup(native: { uvpaa: boolean | 'throws'; caps: Record<string, boolean> }, available: boolean | 'fails') {
    const request = vi.fn(async (): Promise<PasskeyShimResult> => {
      if (available === 'fails') throw new Error('bridge gone');
      return { status: 'ok', responseJson: JSON.stringify({ available }) };
    });
    const transport: PasskeyShimTransport = { request: request as never, abort: vi.fn() };
    const nativeUvpaa = vi.fn(async () => { if (native.uvpaa === 'throws') throw new Error('native'); return native.uvpaa; });
    const nativeCaps = vi.fn(async () => ({ ...native.caps }));
    const constructor = { isUserVerifyingPlatformAuthenticatorAvailable: nativeUvpaa, getClientCapabilities: nativeCaps };
    let clock = 1_000;
    const reasons: string[] = [];
    installCapabilityShim(constructor as never, transport, () => 'availability-id', (reason) => reasons.push(reason), () => clock);
    return { constructor: constructor as unknown as { isUserVerifyingPlatformAuthenticatorAvailable(): Promise<boolean>; getClientCapabilities(): Promise<Record<string, boolean>> }, request, reasons, advance: (ms: number) => { clock += ms; } };
  }
  const noneCaps = { userVerifyingPlatformAuthenticator: false, passkeyPlatformAuthenticator: false, hybridTransport: true };

  it('never contacts VaultMesh when the browser already reports a platform authenticator', async () => {
    const { constructor, request } = capabilitySetup({ uvpaa: true, caps: { userVerifyingPlatformAuthenticator: true, passkeyPlatformAuthenticator: true } }, true);
    await expect(constructor.isUserVerifyingPlatformAuthenticatorAvailable()).resolves.toBe(true);
    await expect(constructor.getClientCapabilities()).resolves.toMatchObject({ userVerifyingPlatformAuthenticator: true });
    expect(request).not.toHaveBeenCalled();
  });

  it('reports a platform authenticator only when the browser has none and VaultMesh is available', async () => {
    const { constructor, reasons } = capabilitySetup({ uvpaa: false, caps: noneCaps }, true);
    await expect(constructor.isUserVerifyingPlatformAuthenticatorAvailable()).resolves.toBe(true);
    await expect(constructor.getClientCapabilities()).resolves.toEqual({ userVerifyingPlatformAuthenticator: true, passkeyPlatformAuthenticator: true, hybridTransport: true });
    expect(reasons).toEqual(['platform-authenticator-reported-by-vaultmesh', 'platform-capabilities-reported-by-vaultmesh']);
  });

  it('keeps the browser answer when VaultMesh is unavailable or the bridge fails', async () => {
    const unavailable = capabilitySetup({ uvpaa: false, caps: noneCaps }, false);
    await expect(unavailable.constructor.isUserVerifyingPlatformAuthenticatorAvailable()).resolves.toBe(false);
    await expect(unavailable.constructor.getClientCapabilities()).resolves.toEqual(noneCaps);
    const failing = capabilitySetup({ uvpaa: false, caps: noneCaps }, 'fails');
    await expect(failing.constructor.isUserVerifyingPlatformAuthenticatorAvailable()).resolves.toBe(false);
  });

  it('rethrows a native failure unless VaultMesh can answer', async () => {
    const down = capabilitySetup({ uvpaa: 'throws', caps: noneCaps }, false);
    await expect(down.constructor.isUserVerifyingPlatformAuthenticatorAvailable()).rejects.toThrow('native');
    const up = capabilitySetup({ uvpaa: 'throws', caps: noneCaps }, true);
    await expect(up.constructor.isUserVerifyingPlatformAuthenticatorAvailable()).resolves.toBe(true);
  });

  it('reuses the availability answer briefly so polling pages do not hammer the desktop', async () => {
    const { constructor, request, advance } = capabilitySetup({ uvpaa: false, caps: noneCaps }, true);
    await constructor.isUserVerifyingPlatformAuthenticatorAvailable();
    await constructor.getClientCapabilities();
    expect(request).toHaveBeenCalledTimes(1);
    advance(PASSKEY_AVAILABILITY_TTL_MS + 1);
    await constructor.isUserVerifyingPlatformAuthenticatorAvailable();
    expect(request).toHaveBeenCalledTimes(2);
  });
});
