import { backgroundDesktopRpc, DesktopRpcError } from '@/lib/desktop-rpc';
import { rememberedLoginSelection } from '@/lib/autofill-preferences';

type WebAuthenticationProxyApi = typeof browser.webAuthenticationProxy;
type FinishRequest = (details: { requestId: number; responseJson?: string; error?: { name: string; message: string } }) => Promise<void>;
type PasskeyOperation = 'passkeys.create' | 'passkeys.get';

export type PasskeyUnlockPrompt = { token: string; operation: 'create' | 'get'; origin: string | null };

export type PasskeyProxyOptions = {
  proxy?: WebAuthenticationProxyApi;
  rpc?: (operation: 'vault.status' | PasskeyOperation, input?: Record<string, unknown>) => Promise<unknown>;
  /** Opens the extension unlock UI. Failures are tolerated; the toolbar popup still shows the prompt. */
  openUnlockPrompt?: () => Promise<void>;
  now?: () => number;
  unlockPollMs?: number;
};

/** Upper bound for holding a WebAuthn request while the user unlocks. */
export const PASSKEY_UNLOCK_WAIT_MS = 5 * 60_000;
/** After an explicit "use the browser" choice the proxy stays detached this long, so the site's retry reaches the browser. */
export const PASSKEY_BYPASS_MS = 5 * 60_000;

type PendingUnlock = PasskeyUnlockPrompt & { requestId: number; settle: (outcome: 'unlocked' | 'declined' | 'expired') => void };

/** Connect Chromium's WebAuthn proxy to the encrypted desktop vault. The
 * proxy is attached from worker start and stays attached while the extension
 * is locked or the native port is reconnecting: such a request waits for
 * VaultMesh to become usable. Only a confirmed unpaired extension or the
 * user's explicit refusal to unlock returns WebAuthn to the browser. Signing
 * still requires an unlocked vault and the desktop's native confirmation. */
export function installPasskeyProxy(options: PasskeyProxyOptions = {}) {
  const proxy = options.proxy ?? (browser as typeof browser & { webAuthenticationProxy?: WebAuthenticationProxyApi }).webAuthenticationProxy;
  const rpc = options.rpc ?? backgroundDesktopRpc;
  const openUnlockPrompt = options.openUnlockPrompt ?? (async () => undefined);
  const now = options.now ?? Date.now;
  const unlockPollMs = options.unlockPollMs ?? 1_000;
  let attached = false;
  let bypassUntil = 0;
  const cancelled = new Set<number>();
  const pendingUnlocks = new Map<string, PendingUnlock>();

  const noop = async () => undefined;
  if (!proxy) return { sync: noop, detach: noop, pendingUnlockPrompt: () => null, declineUnlock: () => false };

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
      let result: { responseJson?: unknown };
      try {
        result = await rpc(operation, { requestDetailsJson, ...extraInput }) as { responseJson?: unknown };
      } catch (error) {
        if (!waitsForVaultMesh(error)) throw error;
        const outcome = await waitForUnlock(requestId, operation, requestDetailsJson);
        if (cancelled.delete(requestId)) return;
        if (outcome === 'declined') {
          await finish({ requestId, error: { name: 'NotAllowedError', message: '已选择不解锁 VaultMesh，请重试以使用浏览器的通行密钥。' } }).catch(() => undefined);
          await bypass();
          return;
        }
        if (outcome === 'expired') {
          await finish({ requestId, error: { name: 'NotAllowedError', message: 'VaultMesh 未解锁，通行密钥请求已超时。' } }).catch(() => undefined);
          return;
        }
        result = await rpc(operation, { requestDetailsJson, ...extraInput }) as { responseJson?: unknown };
      }
      if (cancelled.delete(requestId)) return;
      if (typeof result.responseJson !== 'string' || result.responseJson.length > 256 * 1024) throw new Error('Invalid Passkey response');
      await finish({ requestId, responseJson: result.responseJson });
    } catch (error) {
      if (cancelled.delete(requestId)) return;
      await finish({ requestId, error: domException(error) }).catch(() => undefined);
      if (error instanceof DesktopRpcError && error.code === 'unpaired') await detach();
    }
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
        bypassUntil = 0;
        for (const pending of [...pendingUnlocks.values()]) pending.settle('unlocked');
      }
    } catch (error) {
      // Only a confirmed unpaired extension cannot serve WebAuthn. Transient
      // native-port failures keep VaultMesh in front of the browser.
      if (error instanceof DesktopRpcError && error.code === 'unpaired') {
        await detach();
        return;
      }
    }
    if (bypassUntil > now()) await detach();
    else await attach();
  }

  // Attach before the first status round-trip so an early page request
  // cannot reach the browser's own authenticator.
  void attach();

  return { sync, detach, pendingUnlockPrompt, declineUnlock };
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
