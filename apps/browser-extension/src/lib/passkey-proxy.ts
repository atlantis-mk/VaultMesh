import { backgroundDesktopRpc, DesktopRpcError } from '@/lib/desktop-rpc';
import { rememberedLoginSelection } from '@/lib/autofill-preferences';

type WebAuthenticationProxyApi = typeof browser.webAuthenticationProxy;
type FinishRequest = (details: { requestId: number; responseJson?: string; error?: { name: string; message: string } }) => Promise<void>;
type PasskeyOperation = 'passkeys.create' | 'passkeys.get';
type PasskeyProbeOperation = 'passkeys.probe';

export type PasskeyProbeResult =
  | { status: 'available'; rpId: string; origin: string; account?: string | null }
  | { status: 'unavailable' | 'unknown'; rpId: string; origin: string };

export type PasskeyUnlockPrompt = { token: string; operation: 'create' | 'get'; origin: string | null };

export type PasskeyProxyOptions = {
  proxy?: WebAuthenticationProxyApi;
  rpc?: (operation: 'vault.status' | PasskeyProbeOperation | PasskeyOperation, input?: Record<string, unknown>) => Promise<unknown>;
  /** Opens the extension unlock UI. Failures are tolerated; the toolbar popup still shows the prompt. */
  openUnlockPrompt?: () => Promise<void>;
  /** Prompts the user to retry after the current request is handed back to Chromium. */
  notifyRetry?: () => Promise<void>;
  now?: () => number;
  unlockPollMs?: number;
};

/** Upper bound for holding a WebAuthn request while the user unlocks. */
export const PASSKEY_UNLOCK_WAIT_MS = 5 * 60_000;
/** After handing a request back to Chromium the proxy stays detached this long so a retry reaches the browser. */
export const PASSKEY_BYPASS_MS = 5 * 60_000;

type PendingUnlock = PasskeyUnlockPrompt & { requestId: number; settle: (outcome: 'unlocked' | 'declined' | 'expired') => void };
type Invocation<T> =
  | { status: 'value'; value: T }
  | { status: 'declined' | 'expired' | 'cancelled' };

/** Chromium's WebAuthn proxy is process-global. VaultMesh keeps it attached
 * whenever interception is enabled and decides per request whether it can
 * serve the credential or must hand a retry back to the browser. */
export function installPasskeyProxy(options: PasskeyProxyOptions = {}) {
  const proxy = options.proxy ?? (browser as typeof browser & { webAuthenticationProxy?: WebAuthenticationProxyApi }).webAuthenticationProxy;
  const rpc = options.rpc ?? backgroundDesktopRpc;
  const openUnlockPrompt = options.openUnlockPrompt ?? (async () => undefined);
  const notifyRetry = options.notifyRetry ?? (async () => undefined);
  const now = options.now ?? Date.now;
  const unlockPollMs = options.unlockPollMs ?? 1_000;
  let attached = false;
  let bypassUntil = 0;
  let policyEnabled = true;
  let lastUnlocked: boolean | null = null;
  const cancelled = new Set<number>();
  const pendingUnlocks = new Map<string, PendingUnlock>();

  const noop = async () => undefined;
  if (!proxy) {
    return {
      sync: noop,
      detach: noop,
      pendingUnlockPrompt: () => null,
      declineUnlock: () => false,
      setEnabled: () => undefined,
    };
  }

  proxy.onRequestCanceled.addListener((requestId) => {
    cancelled.add(requestId);
    for (const pending of pendingUnlocks.values()) if (pending.requestId === requestId) pending.settle('expired');
  });
  proxy.onIsUvpaaRequest.addListener((request) => {
    void proxy.completeIsUvpaaRequest({ requestId: request.requestId, isUvpaa: attached }).catch(() => undefined);
  });
  proxy.onCreateRequest.addListener((request) => {
    void completeCreate(request.requestId, request.requestDetailsJson, proxy.completeCreateRequest.bind(proxy));
  });
  proxy.onGetRequest.addListener((request) => {
    void complete(request.requestId, 'passkeys.get', request.requestDetailsJson, proxy.completeGetRequest.bind(proxy));
  });

  async function completeCreate(requestId: number, requestDetailsJson: string, finish: FinishRequest) {
    const loginId = await defaultLoginIdForPasskeyRequest(requestDetailsJson);
    await complete(requestId, 'passkeys.create', requestDetailsJson, finish, loginId ? { loginId } : {});
  }

  async function complete(
    requestId: number,
    operation: PasskeyOperation,
    requestDetailsJson: string,
    finish: FinishRequest,
    extraInput: Record<string, unknown> = {},
  ) {
    try {
      if (operation === 'passkeys.get') {
        const probe = await invokeWithUnlock<PasskeyProbeResult>(
          'passkeys.probe',
          { requestDetailsJson },
          requestId,
          operation,
          requestDetailsJson,
        );
        if (await settleWaitingOutcome(probe, requestId, finish)) return;
        if (probe.status !== 'value') return;
        const result = parseProbeResult(probe.value);
        if (result.status === 'unavailable') {
          await finishForBrowserRetry(
            requestId,
            finish,
            'VaultMesh 没有该网站可用的通行密钥，请在网站重试；重试将由浏览器处理。',
          );
          return;
        }
      }

      const response = await invokeWithUnlock<{ responseJson?: unknown }>(
        operation,
        { requestDetailsJson, ...extraInput },
        requestId,
        operation,
        requestDetailsJson,
      );
      if (await settleWaitingOutcome(response, requestId, finish)) return;
      if (response.status !== 'value') return;
      if (cancelled.delete(requestId)) return;
      if (typeof response.value.responseJson !== 'string' || response.value.responseJson.length > 256 * 1024) {
        throw new Error('Invalid Passkey response');
      }
      await finish({ requestId, responseJson: response.value.responseJson });
    } catch (error) {
      if (cancelled.delete(requestId)) return;
      if (error instanceof DesktopRpcError && error.code === 'passkey-unavailable') {
        await finishForBrowserRetry(
          requestId,
          finish,
          'VaultMesh 没有该网站可用的通行密钥，请在网站重试；重试将由浏览器处理。',
        );
        return;
      }
      await finish({ requestId, error: domException(error) }).catch(() => undefined);
      if (error instanceof DesktopRpcError && (error.code === 'unpaired' || error.code === 'cancelled')) {
        await bypass();
      }
    }
  }

  async function invokeWithUnlock<T>(
    operation: 'vault.status' | PasskeyProbeOperation | PasskeyOperation,
    input: Record<string, unknown>,
    requestId: number,
    promptOperation: PasskeyOperation,
    requestDetailsJson: string,
  ): Promise<Invocation<T>> {
    try {
      return { status: 'value', value: await rpc(operation, input) as T };
    } catch (error) {
      if (!waitsForVaultMesh(error)) throw error;
      const outcome = await waitForUnlock(requestId, promptOperation, requestDetailsJson);
      if (cancelled.delete(requestId)) return { status: 'cancelled' };
      if (outcome === 'declined') return { status: 'declined' };
      if (outcome === 'expired') return { status: 'expired' };
      return { status: 'value', value: await rpc(operation, input) as T };
    }
  }

  async function settleWaitingOutcome<T>(
    invocation: Invocation<T>,
    requestId: number,
    finish: FinishRequest,
  ): Promise<boolean> {
    if (invocation.status === 'value') return false;
    if (invocation.status === 'cancelled') return true;
    if (invocation.status === 'expired') {
      await finish({
        requestId,
        error: { name: 'NotAllowedError', message: 'VaultMesh 未解锁，通行密钥请求已超时。' },
      }).catch(() => undefined);
      return true;
    }
    await finishForBrowserRetry(
      requestId,
      finish,
      '已选择不解锁 VaultMesh，请在网站重试；重试将由浏览器处理。',
      false,
    );
    return true;
  }

  async function finishForBrowserRetry(
    requestId: number,
    finish: FinishRequest,
    message: string,
    notify = true,
  ) {
    await finish({ requestId, error: { name: 'NotAllowedError', message } }).catch(() => undefined);
    if (cancelled.delete(requestId)) return;
    await bypass();
    if (notify) await notifyRetry().catch(() => undefined);
  }

  function waitForUnlock(requestId: number, operation: PasskeyOperation, requestDetailsJson: string): Promise<'unlocked' | 'declined' | 'expired'> {
    if (cancelled.has(requestId)) return Promise.resolve('expired');
    return new Promise((resolve) => {
      const token = crypto.randomUUID();
      const deadline = now() + PASSKEY_UNLOCK_WAIT_MS;
      let timer: ReturnType<typeof setTimeout> | null = null;
      const settle = (outcome: 'unlocked' | 'declined' | 'expired') => {
        if (!pendingUnlocks.delete(token)) return;
        if (timer) clearTimeout(timer);
        resolve(outcome);
      };
      pendingUnlocks.set(token, {
        token,
        requestId,
        operation: operation === 'passkeys.create' ? 'create' : 'get',
        origin: passkeyRequestOrigin(requestDetailsJson),
        settle,
      });
      const poll = async () => {
        timer = null;
        if (!pendingUnlocks.has(token)) return;
        if (now() >= deadline) return settle('expired');
        try {
          const status = await rpc('vault.status') as { unlocked?: unknown };
          if (status.unlocked === true) return settle('unlocked');
        } catch {
          // Desktop reconnects are retried until the request deadline.
        }
        if (pendingUnlocks.has(token)) timer = setTimeout(() => void poll(), unlockPollMs);
      };
      timer = setTimeout(() => void poll(), unlockPollMs);
      void openUnlockPrompt().catch(() => undefined);
    });
  }

  function pendingUnlockPrompt(): PasskeyUnlockPrompt | null {
    const latest = [...pendingUnlocks.values()].at(-1);
    return latest ? { token: latest.token, operation: latest.operation, origin: latest.origin } : null;
  }

  /** The user's explicit choice not to unlock declines every waiting request. */
  function declineUnlock(token: string): boolean {
    if (!pendingUnlocks.has(token)) return false;
    for (const pending of [...pendingUnlocks.values()]) pending.settle('declined');
    return true;
  }

  async function bypass() {
    bypassUntil = now() + PASSKEY_BYPASS_MS;
    await detach();
  }

  async function attach() {
    if (attached) return;
    if (!policyEnabled || bypassUntil > now()) return;
    if (await tryAttach()) return;
    // A restarted MV3 worker forgets that Chromium still holds this
    // extension's attachment; re-attach from a clean state once.
    try { await proxy!.detach(); } catch { /* not attached by this extension */ }
    await tryAttach();
  }

  async function tryAttach() {
    try {
      const error = await proxy!.attach();
      attached = !error;
    } catch {
      attached = false;
    }
    return attached;
  }

  async function detach() {
    if (!attached) return;
    attached = false;
    try { await proxy!.detach(); } catch { /* extension unload also detaches */ }
  }

  async function sync() {
    try {
      const status = await rpc('vault.status') as { unlocked?: unknown };
      if (status.unlocked === true) {
        if (lastUnlocked !== true) bypassUntil = 0;
        lastUnlocked = true;
        for (const pending of [...pendingUnlocks.values()]) pending.settle('unlocked');
      } else {
        lastUnlocked = false;
      }
    } catch (error) {
      // Only a confirmed unpaired extension cannot serve WebAuthn. Transient
      // native-port failures keep VaultMesh in front of the browser.
      if (error instanceof DesktopRpcError && error.code === 'unpaired') {
        await detach();
        return;
      }
    }
    if (!policyEnabled || bypassUntil > now()) await detach();
    else await attach();
  }

  function setEnabled(enabled: boolean) {
    if (policyEnabled === enabled) return;
    policyEnabled = enabled;
    if (!policyEnabled) {
      void detach();
    } else {
      void sync();
    }
  }

  // Attach before the first status round-trip so an early page request
  // cannot reach the browser's own authenticator.
  void attach();

  return { sync, detach, pendingUnlockPrompt, declineUnlock, setEnabled };
}

function parseProbeResult(value: unknown): PasskeyProbeResult {
  if (!value || typeof value !== 'object') throw new Error('Invalid Passkey probe response');
  const candidate = value as { status?: unknown; rpId?: unknown; origin?: unknown; account?: unknown };
  if (
    (candidate.status !== 'available' && candidate.status !== 'unavailable' && candidate.status !== 'unknown')
    || typeof candidate.rpId !== 'string'
    || typeof candidate.origin !== 'string'
  ) {
    throw new Error('Invalid Passkey probe response');
  }
  if (candidate.status === 'available') {
    return {
      status: 'available',
      rpId: candidate.rpId,
      origin: candidate.origin,
      account: typeof candidate.account === 'string' ? candidate.account : null,
    };
  }
  return {
    status: candidate.status as 'unavailable' | 'unknown',
    rpId: candidate.rpId,
    origin: candidate.origin,
  };
}

function waitsForVaultMesh(error: unknown): boolean {
  if (error instanceof DesktopRpcError) return error.code === 'unlock-required' || error.code === 'desktop-unavailable';
  return error instanceof Error && error.message === 'desktop-unavailable';
}

export function passkeyRequestOrigin(requestDetailsJson: string): string | null {
  if (requestDetailsJson.length < 2 || requestDetailsJson.length > 128 * 1024) return null;
  try {
    const request = JSON.parse(requestDetailsJson) as {
      extensions?: { remoteDesktopClientOverride?: { origin?: unknown } };
    };
    const origin = request.extensions?.remoteDesktopClientOverride?.origin;
    if (typeof origin !== 'string') return null;
    const url = new URL(origin);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== origin) return null;
    return origin;
  } catch {
    return null;
  }
}

export async function defaultLoginIdForPasskeyRequest(requestDetailsJson: string): Promise<string | null> {
  const origin = passkeyRequestOrigin(requestDetailsJson);
  return origin ? rememberedLoginSelection(origin) : null;
}

function domException(error: unknown) {
  const message = error instanceof Error ? error.message.slice(0, 256) : 'VaultMesh 无法完成 Passkey 请求。';
  if (/算法|安全密钥|largeBlob|不支持/i.test(message)) return { name: 'NotSupportedError', message };
  if (/已存在/i.test(message)) return { name: 'InvalidStateError', message };
  return { name: 'NotAllowedError', message };
}
