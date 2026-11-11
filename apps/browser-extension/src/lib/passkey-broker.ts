import { backgroundDesktopRpc, DesktopRpcError } from '@/lib/desktop-rpc';
import { rememberedLoginSelection } from '@/lib/autofill-preferences';
import { sameOriginWithAncestors, type FrameLike } from '@/lib/frame-origin';
import { MAX_PASSKEY_JSON_CHARS, MAX_PASSKEY_RESPONSE_CHARS } from '@/lib/passkey-shim-codec';
import { rememberPasskeyChoice, rememberedPasskeyChoice } from '@/lib/passkey-preferences';
import type { PasskeyOperation } from '@/lib/passkey-shim';

type BrokerOperation = 'vault.status' | 'passkeys.probe' | 'passkeys.create' | 'passkeys.get';

export type PasskeyPage = { tabId: number; frameId: number; origin: string };
export type PasskeyRequest = { id: string; operation: PasskeyOperation; optionsJson: string };
export type PasskeyOutcome =
  | { status: 'ok'; responseJson: string }
  | { status: 'fallback' }
  | { status: 'cancelled'; message: string }
  | { status: 'error'; name: string; message: string };

export type PasskeyPromptStage = 'choose' | 'unlock';
export type PasskeyPrompt = { token: string; operation: PasskeyOperation; origin: string; stage: PasskeyPromptStage };
export type PasskeyChoice = 'vaultmesh' | 'native' | 'cancel';

export type PasskeyBrokerOptions = {
  rpc?: (operation: BrokerOperation, input?: Record<string, unknown>) => Promise<unknown>;
  isEnabled: () => boolean;
  frames: (tabId: number) => Promise<FrameLike[]>;
  /** Shows the prompt inside the requesting tab. Resolves `false` when the page cannot show it. */
  showPrompt?: (page: PasskeyPage, prompt: PasskeyPrompt) => Promise<boolean>;
  /** Removes a prompt shown by `showPrompt`. */
  hidePrompt?: (page: PasskeyPage, token: string) => void;
  /** Opens the extension UI that shows the pending prompt when the page cannot. Failures are tolerated. */
  openPrompt?: () => Promise<void>;
  unlockPollMs?: number;
  /** Receives a non-secret reason (never request content) for each decision that is not a VaultMesh response. */
  log?: (message: string) => void;
};

/** Upper bound for holding a page's WebAuthn call while the user chooses or unlocks. */
export const PASSKEY_PROMPT_WAIT_MS = 5 * 60_000;

type PromptResult = 'vaultmesh' | 'native' | 'cancel' | 'expired' | 'unlocked';
type Active = { key: string; page: PasskeyPage; aborted: boolean; promptOpened: boolean; cancelPrompt: (() => void) | null };
type PendingPrompt = PasskeyPrompt & { active: Active; remember: boolean; settle: (result: PromptResult) => void };

const FALLBACK: PasskeyOutcome = { status: 'fallback' };

/** Per-request VaultMesh decision for the MAIN-world shim (ADR-0057). Every
 * path that VaultMesh cannot or should not serve resolves to `fallback`, which
 * makes the page call the browser's own authenticator in the same call. */
export function createPasskeyBroker(options: PasskeyBrokerOptions) {
  const rpc = options.rpc ?? backgroundDesktopRpc;
  const unlockPollMs = options.unlockPollMs ?? 1_000;
  const openPrompt = options.openPrompt ?? (async () => undefined);
  const log = options.log ?? ((message: string) => console.info(message));
  /** A cancel or failure is what makes sites such as Google say "cannot create", so it is always attributable. */
  const cancelled = (page: PasskeyPage, operation: PasskeyOperation, reason: string, message: string): PasskeyOutcome => {
    log(`[VaultMesh Passkey] ${operation} ${page.origin} -> cancelled (${reason})`);
    return { status: 'cancelled', message };
  };
  const fallback = (page: PasskeyPage, operation: PasskeyOperation, reason: string): PasskeyOutcome => {
    log(`[VaultMesh Passkey] ${operation} ${page.origin} -> browser (${reason})`);
    return FALLBACK;
  };
  const actives = new Map<string, Active>();
  const prompts = new Map<string, PendingPrompt>();

  async function handle(request: PasskeyRequest, page: PasskeyPage): Promise<PasskeyOutcome> {
    const active: Active = { key: `${page.tabId}:${page.frameId}:${request.id}`, page, aborted: false, promptOpened: false, cancelPrompt: null };
    actives.set(active.key, active);
    try {
      const outcome = await run(request, page, active);
      return active.aborted ? cancelled(page, request.operation, 'page-aborted-or-navigated', '通行密钥请求已取消。') : outcome;
    } catch (error) {
      if (active.aborted) return cancelled(page, request.operation, 'page-aborted-or-navigated', '通行密钥请求已取消。');
      return fallbackOrError(error, request.operation, page);
    } finally {
      actives.delete(active.key);
    }
  }

  async function run(request: PasskeyRequest, page: PasskeyPage, active: Active): Promise<PasskeyOutcome> {
    const op = request.operation;
    if (!options.isEnabled()) return fallback(page, op, 'takeover-disabled');
    if (request.optionsJson.length > MAX_PASSKEY_JSON_CHARS) return fallback(page, op, 'request-too-large');
    // Only a same-origin chain is served; cross-origin frames stay with the
    // browser, which enforces the WebAuthn permissions policy.
    const frames = await options.frames(page.tabId).catch(() => null);
    if (!frames) return fallback(page, op, 'frame-tree-unavailable');
    if (!sameOriginWithAncestors(frames, page.frameId, page.origin)) return fallback(page, op, 'cross-origin-frame');
    const details = buildRequestDetails(request, page);
    if (!details) return fallback(page, op, 'invalid-options');
    const requestDetailsJson = JSON.stringify(details);

    // Anything but a healthy, paired desktop leaves the browser in charge.
    let unlocked: boolean;
    try {
      const status = await rpc('vault.status') as { unlocked?: unknown };
      unlocked = status.unlocked === true;
    } catch (error) {
      return fallback(page, op, error instanceof DesktopRpcError ? `desktop-${error.code}` : 'desktop-unreachable');
    }

    const remembered = await rememberedPasskeyChoice(request.operation, page.origin);
    if (remembered === 'native') return fallback(page, op, 'remembered-browser-choice');

    if (request.operation === 'get') {
      try {
        const probe = await rpc('passkeys.probe', { requestDetailsJson }) as { status?: unknown };
        if (probe.status === 'unavailable') return fallback(page, op, 'no-matching-passkey');
      } catch (error) {
        return fallback(page, op, error instanceof DesktopRpcError ? `probe-${error.code}` : 'probe-failed');
      }
    }
    if (active.aborted) return cancelled(page, op, 'page-aborted-or-navigated', '通行密钥请求已取消。');

    if (remembered !== 'vaultmesh') {
      const choice = await askPrompt(active, request.operation, page.origin, 'choose');
      if (choice.result === 'native') {
        if (choice.remember) await rememberPasskeyChoice(request.operation, page.origin, 'native').catch(() => undefined);
        return fallback(page, op, 'user-chose-browser');
      }
      if (choice.result === 'expired') return cancelled(page, op, 'choice-timed-out', 'VaultMesh 通行密钥请求已超时。');
      if (choice.result !== 'vaultmesh') return cancelled(page, op, 'user-cancelled-choice', '已取消通行密钥请求。');
      if (choice.remember) await rememberPasskeyChoice(request.operation, page.origin, 'vaultmesh').catch(() => undefined);
    }

    const operation = request.operation === 'create' ? 'passkeys.create' : 'passkeys.get';
    const loginId = request.operation === 'create' ? await rememberedLoginSelection(page.origin).catch(() => null) : null;
    const input = { requestDetailsJson, ...(loginId ? { loginId } : {}) };
    if (!unlocked) {
      const unlockedNow = await waitForUnlock(active, request.operation, page.origin);
      if (unlockedNow === 'native') return fallback(page, op, 'user-skipped-unlock');
      if (unlockedNow !== 'unlocked') return cancelled(page, op, unlockedNow === 'expired' ? 'unlock-timed-out' : 'user-cancelled-unlock', 'VaultMesh 未解锁，通行密钥请求已取消。');
    }
    return invoke(operation, input, active, page);
  }

  async function invoke(
    operation: 'passkeys.create' | 'passkeys.get',
    input: Record<string, unknown>,
    active: Active,
    page: PasskeyPage,
  ): Promise<PasskeyOutcome> {
    const promptOperation: PasskeyOperation = operation === 'passkeys.create' ? 'create' : 'get';
    const origin = page.origin;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const response = await rpc(operation, input) as { responseJson?: unknown };
        if (active.aborted) return cancelled(page, promptOperation, 'page-aborted-or-navigated', '通行密钥请求已取消。');
        if (typeof response.responseJson !== 'string' || response.responseJson.length > MAX_PASSKEY_RESPONSE_CHARS) {
          throw new Error('Invalid Passkey response');
        }
        return { status: 'ok', responseJson: response.responseJson };
      } catch (error) {
        // The vault locked between the check and the call: wait once more.
        if (attempt === 0 && error instanceof DesktopRpcError && error.code === 'unlock-required') {
          const result = await waitForUnlock(active, promptOperation, origin);
          if (result === 'native') return fallback(page, promptOperation, 'user-skipped-unlock');
          if (result !== 'unlocked') return cancelled(page, promptOperation, result === 'expired' ? 'unlock-timed-out' : 'user-cancelled-unlock', 'VaultMesh 未解锁，通行密钥请求已取消。');
          continue;
        }
        throw error;
      }
    }
    return FALLBACK;
  }

  function fallbackOrError(error: unknown, operation: PasskeyOperation, page: PasskeyPage): PasskeyOutcome {
    if (error instanceof DesktopRpcError) {
      if (['passkey-unavailable', 'unpaired', 'desktop-unavailable', 'unlock-required'].includes(error.code)) return fallback(page, operation, `desktop-${error.code}`);
      if (error.code === 'cancelled') return cancelled(page, operation, 'desktop-confirmation-declined', '已取消 VaultMesh 通行密钥请求。');
    }
    const failure = domException(error);
    log(`[VaultMesh Passkey] ${operation} ${page.origin} -> error (${failure.name}${error instanceof DesktopRpcError ? `, desktop-${error.code}` : ''}: ${failure.message})`);
    return { status: 'error', ...failure };
  }

  function askPrompt(
    active: Active,
    operation: PasskeyOperation,
    origin: string,
    stage: PasskeyPromptStage,
  ): Promise<{ result: PromptResult; remember: boolean }> {
    return new Promise((resolve) => {
      const token = crypto.randomUUID();
      let timer: ReturnType<typeof setTimeout> | null = null;
      let poll: ReturnType<typeof setTimeout> | null = null;
      const pending: PendingPrompt = {
        token, operation, origin, stage, active, remember: false,
        settle: (result) => {
          if (!prompts.delete(token)) return;
          if (timer) clearTimeout(timer);
          if (poll) clearTimeout(poll);
          options.hidePrompt?.(active.page, token);
          active.cancelPrompt = null;
          resolve({ result, remember: pending.remember });
        },
      };
      prompts.set(token, pending);
      active.cancelPrompt = () => pending.settle('cancel');
      timer = setTimeout(() => pending.settle('expired'), PASSKEY_PROMPT_WAIT_MS);
      if (stage === 'unlock') {
        const tick = async () => {
          poll = null;
          if (!prompts.has(token)) return;
          try {
            const status = await rpc('vault.status') as { unlocked?: unknown };
            if (status.unlocked === true) return pending.settle('unlocked');
          } catch {
            // Reconnects are retried until the prompt deadline.
          }
          if (prompts.has(token)) poll = setTimeout(() => void tick(), unlockPollMs);
        };
        poll = setTimeout(() => void tick(), unlockPollMs);
      }
      // The in-page dialog is primary; the extension window is only the fallback.
      const view: PasskeyPrompt = { token, operation, origin, stage };
      void (async () => {
        const shown = options.showPrompt ? await options.showPrompt(active.page, view).catch(() => false) : false;
        if (shown) active.promptOpened = true;
        else if (!active.promptOpened && prompts.has(token)) {
          active.promptOpened = true;
          await openPrompt().catch(() => undefined);
        }
      })();
    });
  }

  async function waitForUnlock(active: Active, operation: PasskeyOperation, origin: string): Promise<'unlocked' | 'native' | 'cancel' | 'expired'> {
    const { result } = await askPrompt(active, operation, origin, 'unlock');
    return result === 'unlocked' || result === 'native' || result === 'expired' ? result : 'cancel';
  }

  /** Whether VaultMesh could serve a passkey for this page: takeover on, a same-origin
   * chain and a paired, reachable desktop. A locked vault still counts; the user can unlock. */
  async function availability(page: PasskeyPage): Promise<boolean> {
    if (!options.isEnabled()) return false;
    const frames = await options.frames(page.tabId).catch(() => null);
    if (!frames || !sameOriginWithAncestors(frames, page.frameId, page.origin)) return false;
    try {
      await rpc('vault.status');
      return true;
    } catch (error) {
      log(`[VaultMesh Passkey] availability ${page.origin} -> unavailable (${error instanceof DesktopRpcError ? `desktop-${error.code}` : 'desktop-unreachable'})`);
      return false;
    }
  }

  function abort(page: PasskeyPage, id: string) {
    const active = actives.get(`${page.tabId}:${page.frameId}:${id}`);
    if (!active) return;
    active.aborted = true;
    active.cancelPrompt?.();
  }

  /** Navigation, reload or tab close ends every request owned by that document. */
  function cancelPage(tabId: number, frameId?: number) {
    for (const active of actives.values()) {
      if (active.page.tabId !== tabId || (frameId !== undefined && active.page.frameId !== frameId)) continue;
      active.aborted = true;
      active.cancelPrompt?.();
    }
  }

  function currentPrompt(): PasskeyPrompt | null {
    const latest = [...prompts.values()].at(-1);
    return latest ? { token: latest.token, operation: latest.operation, origin: latest.origin, stage: latest.stage } : null;
  }

  /** `native` hands the same call to the browser; `cancel` rejects it as a user cancel. */
  function choose(token: string, choice: PasskeyChoice, remember = false, fromTabId?: number): boolean {
    const pending = prompts.get(token);
    if (!pending) return false;
    // A page-hosted dialog may only answer prompts of its own tab.
    if (fromTabId !== undefined && pending.active.page.tabId !== fromTabId) return false;
    if (pending.stage === 'unlock' && choice === 'vaultmesh') return false;
    pending.remember = remember && pending.stage === 'choose' && choice !== 'cancel';
    pending.settle(choice);
    return true;
  }

  /** Called after the unlock state may have changed so waiting calls continue promptly. */
  async function syncUnlockState() {
    if (![...prompts.values()].some((prompt) => prompt.stage === 'unlock')) return;
    try {
      const status = await rpc('vault.status') as { unlocked?: unknown };
      if (status.unlocked !== true) return;
      for (const prompt of [...prompts.values()]) if (prompt.stage === 'unlock') prompt.settle('unlocked');
    } catch {
      // The poller keeps trying until the prompt deadline.
    }
  }

  return { handle, abort, availability, cancelPage, currentPrompt, choose, syncUnlockState };
}

/** Rebuilds the desktop request from page options. The origin and ancestry
 * come from the browser-verified sender, never from the page. */
export function buildRequestDetails(request: PasskeyRequest, page: PasskeyPage): Record<string, unknown> | null {
  let parsed: unknown;
  try { parsed = JSON.parse(request.optionsJson); } catch { return null; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const options = { ...(parsed as Record<string, unknown>) };
  const hostname = new URL(page.origin).hostname;
  const supplied = options.extensions && typeof options.extensions === 'object' && !Array.isArray(options.extensions)
    ? options.extensions as Record<string, unknown>
    : {};
  const extensions: Record<string, unknown> = {};
  if (typeof supplied.appid === 'string') extensions.appid = supplied.appid;
  if (typeof supplied.credProps === 'boolean') extensions.credProps = supplied.credProps;
  extensions.remoteDesktopClientOverride = { origin: page.origin, sameOriginWithAncestors: true };
  options.extensions = extensions;
  if (request.operation === 'get') {
    if (options.rpId === undefined) options.rpId = hostname;
  } else {
    const rp = options.rp && typeof options.rp === 'object' && !Array.isArray(options.rp) ? { ...(options.rp as Record<string, unknown>) } : null;
    if (!rp) return null;
    if (rp.id === undefined) rp.id = hostname;
    options.rp = rp;
  }
  return options;
}

export function domException(error: unknown): { name: string; message: string } {
  const message = error instanceof Error ? error.message.slice(0, 256) : 'VaultMesh 无法完成 Passkey 请求。';
  if (/算法|安全密钥|largeBlob|不支持/i.test(message)) return { name: 'NotSupportedError', message };
  if (/已存在/i.test(message)) return { name: 'InvalidStateError', message };
  return { name: 'NotAllowedError', message };
}
