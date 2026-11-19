import {
  credentialFromCreateJson,
  credentialFromGetJson,
  encodeCreationOptions,
  blockingExtension,
  encodeRequestOptions,
  MAX_PASSKEY_JSON_CHARS,
  PASSKEY_PROMPT_WAIT_MS,
  type CredentialConstructors,
  type JsonObject,
} from '@/lib/passkey-shim-codec';

/** Runs in the page's MAIN world. It never sees secrets and never decides what
 * origin a request belongs to: it forwards sanitised options to the isolated
 * bridge and either returns VaultMesh's public response or calls the browser's
 * own WebAuthn implementation in the same call. */

export const PASSKEY_CHANNEL = 'vaultmesh.passkey.v1';
/** The bridge acknowledges immediately; without an ack the extension is absent or reloading. */
export const PASSKEY_ACK_TIMEOUT_MS = 1_500;

export type PasskeyOperation = 'create' | 'get';
/** `availability` asks whether VaultMesh could serve a platform passkey here; it never prompts. */
export type PasskeyShimOperation = PasskeyOperation | 'availability';
export type PasskeyShimResult =
  | { status: 'ok'; responseJson: string }
  | { status: 'fallback' }
  | { status: 'cancelled'; message?: string }
  | { status: 'error'; name?: string; message?: string };

export type PasskeyShimTransport = {
  request(id: string, operation: PasskeyShimOperation, options: JsonObject): Promise<PasskeyShimResult>;
  abort(id: string): void;
  /** Reports a non-secret reason code when the page-side shim handed a request to the browser. */
  note?(reason: string): void;
};

type CredentialsPrototype = {
  create: (this: unknown, options?: CredentialCreationOptions) => Promise<Credential | null>;
  get: (this: unknown, options?: CredentialRequestOptions) => Promise<Credential | null>;
};

const ERROR_NAMES = new Set(['NotAllowedError', 'NotSupportedError', 'InvalidStateError', 'SecurityError', 'AbortError', 'ConstraintError']);

export function installPasskeyShim(
  prototype: CredentialsPrototype,
  transport: PasskeyShimTransport,
  constructors: CredentialConstructors,
  newId: () => string = () => crypto.randomUUID(),
  /** Receives a non-secret reason whenever the browser serves a request without asking VaultMesh. */
  log: (reason: string) => void = () => undefined,
  now: () => number = Date.now,
): void {
  const nativeCreate = prototype.create;
  const nativeGet = prototype.get;

  async function delegate(
    operation: PasskeyOperation,
    encoded: JsonObject,
    signal: AbortSignal | undefined,
    waitTimeoutMs: number | undefined,
    native: () => Promise<Credential | null>,
    build: (responseJson: unknown) => Credential,
  ): Promise<Credential | null> {
    if (JSON.stringify(encoded).length > MAX_PASSKEY_JSON_CHARS) { log('request-too-large'); return native(); }
    if (signal?.aborted) throw signal.reason ?? new DOMException('The operation was aborted.', 'AbortError');
    const id = newId();
    let onAbort: (() => void) | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const racers: Array<Promise<PasskeyShimResult | 'aborted' | 'timed-out'>> = [
      transport.request(id, operation, encoded),
    ];
    if (signal) {
      racers.push(new Promise<'aborted'>((resolve) => {
        onAbort = () => resolve('aborted');
        signal.addEventListener('abort', onAbort, { once: true });
      }));
    }
    if (waitTimeoutMs !== undefined) {
      racers.push(new Promise<'timed-out'>((resolve) => {
        timer = setTimeout(() => resolve('timed-out'), waitTimeoutMs);
      }));
    }
    let outcome: PasskeyShimResult | 'aborted' | 'timed-out';
    try {
      outcome = await Promise.race(racers);
    } catch {
      outcome = { status: 'fallback' };
    } finally {
      if (timer) clearTimeout(timer);
      if (signal && onAbort) signal.removeEventListener('abort', onAbort);
    }
    if (outcome === 'aborted') {
      transport.abort(id);
      throw signal?.reason ?? new DOMException('The operation was aborted.', 'AbortError');
    }
    if (outcome === 'timed-out') {
      transport.abort(id);
      log('shim-timeout');
      throw new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError');
    }
    switch (outcome.status) {
      case 'fallback':
        log('background-fallback');
        return native();
      case 'cancelled':
        throw new DOMException(outcome.message ?? 'The operation either timed out or was not allowed.', 'NotAllowedError');
      case 'error':
        throw new DOMException(
          outcome.message ?? 'The operation either timed out or was not allowed.',
          outcome.name && ERROR_NAMES.has(outcome.name) ? outcome.name : 'NotAllowedError',
        );
      case 'ok':
        try {
          return build(JSON.parse(outcome.responseJson));
        } catch {
          // A malformed desktop response must not leave the site without any authenticator.
          log('malformed-response');
          return native();
        }
    }
  }

  function nativeWithRemainingTimeout<TOptions extends { publicKey?: { timeout?: number } } | undefined>(
    callNative: (nextOptions: TOptions) => Promise<Credential | null>,
    options: TOptions,
    rawTimeout: unknown,
    startedAt: number,
  ): () => Promise<Credential | null> {
    return () => {
      if (typeof rawTimeout !== 'number' || !options?.publicKey) return callNative(options);
      const elapsed = Math.max(0, now() - startedAt);
      const remaining = Math.max(1_000, rawTimeout - elapsed);
      return callNative({ ...options, publicKey: { ...options.publicKey, timeout: remaining } } as TOptions);
    };
  }

  const create = async function create(this: unknown, options?: CredentialCreationOptions) {
    const startedAt = now();
    const callNative = (nextOptions?: CredentialCreationOptions) => nativeCreate.call(this, nextOptions);
    const publicKey = options?.publicKey;
    if (!publicKey || options?.signal?.aborted) return callNative(options);
    let encoded: JsonObject | null;
    try { encoded = encodeCreationOptions(publicKey); } catch { log('unreadable-options'); return callNative(options); }
    if (!encoded) { log(`unsupported-extension:${blockingExtension(publicKey.extensions)}`); return callNative(options); }
    const waitMs = typeof encoded.timeout === 'number'
      ? Math.min(Math.max(encoded.timeout, 1_000), PASSKEY_PROMPT_WAIT_MS)
      : undefined;
    return delegate(
      'create',
      encoded,
      options.signal,
      waitMs,
      nativeWithRemainingTimeout(callNative, options, encoded.timeout, startedAt),
      (json) => credentialFromCreateJson(json, constructors),
    );
  };

  const get = async function get(this: unknown, options?: CredentialRequestOptions) {
    const startedAt = now();
    const callNative = (nextOptions?: CredentialRequestOptions) => nativeGet.call(this, nextOptions);
    const publicKey = options?.publicKey;
    if (!publicKey || options?.signal?.aborted) return callNative(options);
    let encoded: JsonObject | null;
    try { encoded = encodeRequestOptions(publicKey, options.mediation); } catch { log('unreadable-options'); return callNative(options); }
    if (!encoded) { log(`unsupported-extension:${blockingExtension(publicKey.extensions)}`); return callNative(options); }
    const waitMs = encoded.mediation !== 'conditional' && typeof encoded.timeout === 'number'
      ? Math.min(Math.max(encoded.timeout, 1_000), PASSKEY_PROMPT_WAIT_MS)
      : undefined;
    return delegate(
      'get',
      encoded,
      options.signal,
      waitMs,
      nativeWithRemainingTimeout(callNative, options, encoded.timeout, startedAt),
      (json) => credentialFromGetJson(json, constructors),
    );
  };

  for (const [name, replacement] of [['create', create], ['get', get]] as const) {
    Object.defineProperty(replacement, 'name', { value: name, configurable: true });
    Object.defineProperty(prototype, name, { value: replacement, writable: true, enumerable: true, configurable: true });
  }
}

type CapabilityConstructor = {
  isUserVerifyingPlatformAuthenticatorAvailable?: (this: unknown) => Promise<boolean>;
  getClientCapabilities?: (this: unknown) => Promise<Record<string, boolean>>;
};

/** How long a positive/negative "VaultMesh is available" answer is reused. Sites poll these queries. */
export const PASSKEY_AVAILABILITY_TTL_MS = 10_000;

/** Reports a platform authenticator to the page when the browser has none but
 * VaultMesh can serve passkeys here. The browser's own answer always wins when
 * it is already positive, so VaultMesh never masks a real authenticator. Sites
 * such as Google refuse to start a creation when these queries say "no", which
 * would leave VaultMesh without a chance to serve the request. */
export function installCapabilityShim(
  constructor: CapabilityConstructor,
  transport: PasskeyShimTransport,
  newId: () => string = () => crypto.randomUUID(),
  log: (reason: string) => void = () => undefined,
  now: () => number = Date.now,
): void {
  let cached: { at: number; available: boolean } | null = null;
  async function vaultMeshAvailable(): Promise<boolean> {
    if (cached && now() - cached.at < PASSKEY_AVAILABILITY_TTL_MS) return cached.available;
    let available = false;
    try {
      const result = await transport.request(newId(), 'availability', {});
      available = result.status === 'ok' && (JSON.parse(result.responseJson) as { available?: unknown }).available === true;
    } catch {
      available = false;
    }
    cached = { at: now(), available };
    return available;
  }

  const nativeUvpaa = constructor.isUserVerifyingPlatformAuthenticatorAvailable;
  if (typeof nativeUvpaa === 'function') {
    const replacement = async function isUserVerifyingPlatformAuthenticatorAvailable(this: unknown) {
      let native = false;
      let failure: unknown = null;
      try { native = await nativeUvpaa.call(this); } catch (error) { failure = error; }
      if (native) return true;
      if (await vaultMeshAvailable()) {
        log('platform-authenticator-reported-by-vaultmesh');
        return true;
      }
      if (failure) throw failure;
      return native;
    };
    Object.defineProperty(replacement, 'name', { value: 'isUserVerifyingPlatformAuthenticatorAvailable', configurable: true });
    Object.defineProperty(constructor, 'isUserVerifyingPlatformAuthenticatorAvailable', { value: replacement, writable: true, enumerable: true, configurable: true });
  }

  const nativeCapabilities = constructor.getClientCapabilities;
  if (typeof nativeCapabilities === 'function') {
    const replacement = async function getClientCapabilities(this: unknown) {
      const native = await nativeCapabilities.call(this);
      if (native.userVerifyingPlatformAuthenticator === true && native.passkeyPlatformAuthenticator === true) return native;
      if (!(await vaultMeshAvailable())) return native;
      log('platform-capabilities-reported-by-vaultmesh');
      return { ...native, userVerifyingPlatformAuthenticator: true, passkeyPlatformAuthenticator: true };
    };
    Object.defineProperty(replacement, 'name', { value: 'getClientCapabilities', configurable: true });
    Object.defineProperty(constructor, 'getClientCapabilities', { value: replacement, writable: true, enumerable: true, configurable: true });
  }
}

/** Page ↔ isolated-world transport over `window.postMessage`. Anything the page
 * can read here it already supplied or is entitled to receive. */
export function createWindowTransport(target: Window = window): PasskeyShimTransport {
  const pending = new Map<string, { resolve: (result: PasskeyShimResult) => void; acked: boolean; timer: ReturnType<typeof setTimeout> }>();
  const targetOrigin = target.location.origin && target.location.origin !== 'null' ? target.location.origin : '*';

  target.addEventListener('message', (event: MessageEvent) => {
    if (event.source !== target) return;
    const data = event.data as { channel?: unknown; direction?: unknown; id?: unknown; result?: unknown } | null;
    if (!data || data.channel !== PASSKEY_CHANNEL || typeof data.id !== 'string') return;
    const entry = pending.get(data.id);
    if (!entry) return;
    if (data.direction === 'ack') {
      entry.acked = true;
      clearTimeout(entry.timer);
      return;
    }
    if (data.direction !== 'response') return;
    clearTimeout(entry.timer);
    pending.delete(data.id);
    entry.resolve(parseResult(data.result));
  });

  return {
    request(id, operation, options) {
      return new Promise<PasskeyShimResult>((resolve) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          resolve({ status: 'fallback' });
        }, PASSKEY_ACK_TIMEOUT_MS);
        pending.set(id, { resolve, acked: false, timer });
        target.postMessage({ channel: PASSKEY_CHANNEL, direction: 'request', id, operation, options }, targetOrigin);
      });
    },
    note(reason) {
      target.postMessage({ channel: PASSKEY_CHANNEL, direction: 'note', id: crypto.randomUUID(), reason }, targetOrigin);
    },
    abort(id) {
      const entry = pending.get(id);
      if (entry) clearTimeout(entry.timer);
      pending.delete(id);
      target.postMessage({ channel: PASSKEY_CHANNEL, direction: 'abort', id }, targetOrigin);
    },
  };
}

function parseResult(value: unknown): PasskeyShimResult {
  if (!value || typeof value !== 'object') return { status: 'fallback' };
  const result = value as { status?: unknown; responseJson?: unknown; message?: unknown; name?: unknown };
  switch (result.status) {
    case 'ok':
      return typeof result.responseJson === 'string' ? { status: 'ok', responseJson: result.responseJson } : { status: 'fallback' };
    case 'cancelled':
      return { status: 'cancelled', message: typeof result.message === 'string' ? result.message.slice(0, 256) : undefined };
    case 'error':
      return {
        status: 'error',
        name: typeof result.name === 'string' ? result.name : undefined,
        message: typeof result.message === 'string' ? result.message.slice(0, 256) : undefined,
      };
    default:
      return { status: 'fallback' };
  }
}
