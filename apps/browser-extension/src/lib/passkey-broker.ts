import { backgroundDesktopRpc, DesktopRpcError } from '@/lib/desktop-rpc';
import { rememberedLoginSelection } from '@/lib/autofill-preferences';
import { resolveFrameAncestry, type FrameAncestry, type FrameLike } from '@/lib/frame-origin';
import {
  MAX_PASSKEY_JSON_CHARS,
  MAX_PASSKEY_RESPONSE_CHARS,
  PASSKEY_PROMPT_WAIT_MS,
} from '@/lib/passkey-shim-codec';
import type { PasskeyPromptCandidate, PasskeyPromptView } from '@/lib/passkey-dialog';
import {
  rememberPasskeyChoice,
  resolveEffectivePasskeyPreference,
  type SitePasskeyMode,
} from '@/lib/passkey-preferences';
import type { PasskeyOperation } from '@/lib/passkey-shim';
import type { PasskeyDefaultMode } from '@/lib/plugin-security-policy';

export { PASSKEY_PROMPT_WAIT_MS };

type BrokerOperation = 'vault.status' | 'passkeys.probe' | 'passkeys.create' | 'passkeys.get';

export type PasskeyPage = { tabId: number; frameId: number; origin: string; pageUrl?: string };
export type PasskeyRequest = { id: string; operation: PasskeyOperation; optionsJson: string };
export type PasskeyOutcome =
  | { status: 'ok'; responseJson: string }
  | { status: 'fallback' }
  | { status: 'cancelled'; message: string }
  | { status: 'error'; name: string; message: string };

export type PasskeyPromptStage = 'choose' | 'unlock' | 'no-match';
export type PasskeyPrompt = PasskeyPromptView;
export type PasskeyChoice = 'vaultmesh' | 'native' | 'cancel';
export type ConditionalPasskeyCandidate = PasskeyPromptCandidate & { requestId: string };

export type PasskeyBrokerOptions = {
  rpc?: (operation: BrokerOperation, input?: Record<string, unknown>) => Promise<unknown>;
  isEnabled: () => boolean;
  isSupported?: () => boolean;
  defaultMode?: (operation: PasskeyOperation) => PasskeyDefaultMode;
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

type PromptResult = 'vaultmesh' | 'native' | 'cancel' | 'expired' | 'unlocked';
type Active = {
  key: string;
  page: PasskeyPage;
  aborted: boolean;
  promptOpened: boolean;
  cancelPrompt: (() => void) | null;
};
type PendingPrompt = PasskeyPrompt & {
  active: Active;
  remember: boolean;
  selectedItemId?: string;
  settle: (result: PromptResult) => void;
};
type PendingConditional = {
  id: string;
  page: PasskeyPage;
  ancestry: FrameAncestry;
  requestDetailsJson: string;
  candidates: PasskeyPromptCandidate[];
  resolving: boolean;
  settle: (outcome: PasskeyOutcome) => void;
};
type ParsedProbe = {
  status: 'available' | 'unavailable' | 'unknown';
  candidates: PasskeyPromptCandidate[];
};

const FALLBACK: PasskeyOutcome = { status: 'fallback' };

/** Per-request VaultMesh decision for the MAIN-world shim (ADR-0057). Every
 * path that VaultMesh cannot or should not serve resolves to `fallback`, which
 * makes the page call the browser's own authenticator in the same call. */
export function createPasskeyBroker(options: PasskeyBrokerOptions) {
  const rpc = options.rpc ?? backgroundDesktopRpc;
  const unlockPollMs = options.unlockPollMs ?? 1_000;
  const openPrompt = options.openPrompt ?? (async () => undefined);
  const isSupported = options.isSupported ?? (() => true);
  const defaultMode = options.defaultMode ?? ((operation: PasskeyOperation) => (operation === 'create' ? 'ask' : 'vaultmesh'));
  const log = options.log ?? ((message: string) => console.info(message));
  /** A cancel or failure is what makes sites such as Google say "cannot create", so it is always attributable. */
  const cancelled = (page: Pick<PasskeyPage, 'origin'>, operation: PasskeyOperation, reason: string, message: string): PasskeyOutcome => {
    log(`[VaultMesh Passkey] ${operation} ${page.origin} -> cancelled (${reason})`);
    return { status: 'cancelled', message };
  };
  const fallback = (page: Pick<PasskeyPage, 'origin'>, operation: PasskeyOperation, reason: string): PasskeyOutcome => {
    log(`[VaultMesh Passkey] ${operation} ${page.origin} -> browser (${reason})`);
    return FALLBACK;
  };
  const actives = new Map<string, Active>();
  const prompts = new Map<string, PendingPrompt>();
  const conditionals = new Map<string, PendingConditional>();

  const conditionalKey = (tabId: number, frameId: number) => `${tabId}:${frameId}`;

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
    if (!isSupported()) return fallback(page, op, 'firefox-unsupported');
    if (!options.isEnabled()) return fallback(page, op, 'takeover-disabled');
    if (request.optionsJson.length > MAX_PASSKEY_JSON_CHARS) return fallback(page, op, 'request-too-large');
    const frames = await options.frames(page.tabId).catch(() => null);
    if (!frames) return fallback(page, op, 'frame-tree-unavailable');
    const ancestry = resolveFrameAncestry(frames, page.frameId, page.origin);
    if (!ancestry) return fallback(page, op, 'frame-ancestry-untrusted');

    const rawOptions = parseRawOptions(request.optionsJson);
    const details = rawOptions ? buildRequestDetailsFromObject(request.operation, rawOptions, ancestry) : null;
    if (!rawOptions || !details) return fallback(page, op, 'invalid-options');
    const requestDetailsJson = JSON.stringify(details);
    const isConditional = op === 'get' && rawOptions.mediation === 'conditional';
    const preference = await resolveEffectivePasskeyPreference(op, ancestry, defaultMode(op));
    if (preference.choice === 'native') return fallback(page, op, preference.reason ?? 'remembered-browser-choice');

    // Anything but a healthy, paired desktop leaves the browser in charge.
    try {
      await rpc('vault.status');
    } catch (error) {
      return fallback(page, op, error instanceof DesktopRpcError ? `desktop-${error.code}` : 'desktop-unreachable');
    }

    if (isConditional) {
      let probe: ParsedProbe;
      try {
        probe = parseProbeResult(await rpc('passkeys.probe', { requestDetailsJson }));
      } catch (error) {
        return fallback(page, op, error instanceof DesktopRpcError ? `probe-${error.code}` : 'probe-failed');
      }
      if (active.aborted) return cancelled(page, op, 'page-aborted-or-navigated', '通行密钥请求已取消。');
      if (probe.status !== 'available' || probe.candidates.length === 0) {
        return fallback(page, op, probe.status === 'unavailable' ? 'no-matching-passkey' : 'conditional-unavailable');
      }
      return suspendConditional(request.id, page, ancestry, requestDetailsJson, probe.candidates, active);
    }

    const requestWaitMs = typeof rawOptions.timeout === 'number' && Number.isSafeInteger(rawOptions.timeout) && rawOptions.timeout > 0
      ? Math.min(Math.max(rawOptions.timeout, 1_000), PASSKEY_PROMPT_WAIT_MS)
      : PASSKEY_PROMPT_WAIT_MS;
    const deadlineAt = Date.now() + requestWaitMs;

    let probe: ParsedProbe = { status: 'unknown', candidates: [] };
    if (op === 'get') {
      try {
        probe = parseProbeResult(await rpc('passkeys.probe', { requestDetailsJson }));
      } catch (error) {
        return fallback(page, op, error instanceof DesktopRpcError ? `probe-${error.code}` : 'probe-failed');
      }
      if (active.aborted) return cancelled(page, op, 'page-aborted-or-navigated', '通行密钥请求已取消。');

      if (probe.status === 'unavailable') {
        const noMatch = await askPrompt(active, ancestry, 'get', 'no-match', {}, remainingMs(deadlineAt));
        if (noMatch.result === 'native') {
          if (noMatch.remember) await rememberPasskeyChoice('get', ancestry, 'native').catch(() => undefined);
          return fallback(page, op, 'user-chose-browser');
        }
        if (noMatch.result === 'expired') return cancelled(page, op, 'choice-timed-out', 'VaultMesh 通行密钥请求已超时。');
        return cancelled(page, op, 'user-cancelled-choice', '已取消通行密钥请求。');
      }
    }

    let selectedCandidate = probe.candidates.length === 1 ? probe.candidates[0] : undefined;
    const conservativeUnknownDefault =
      op === 'get' && probe.status === 'unknown' && preference.reason === 'default-vaultmesh';
    const needsPrompt =
      preference.choice !== 'vaultmesh'
      || (op === 'get' && probe.candidates.length > 1)
      || conservativeUnknownDefault;
    if (needsPrompt) {
      if (preference.reason === 'site-mode-ask') {
        log(`[VaultMesh Passkey] ${op} ${ancestry.origin} -> prompt (site-mode-ask)`);
      }
      const choice = await askPrompt(active, ancestry, op, 'choose', {
        candidates: op === 'get' ? probe.candidates : undefined,
      }, remainingMs(deadlineAt));
      if (choice.result === 'native') {
        if (choice.remember) await rememberPasskeyChoice(op, ancestry, 'native').catch(() => undefined);
        return fallback(page, op, 'user-chose-browser');
      }
      if (choice.result === 'expired') return cancelled(page, op, 'choice-timed-out', 'VaultMesh 通行密钥请求已超时。');
      if (choice.result !== 'vaultmesh') return cancelled(page, op, 'user-cancelled-choice', '已取消通行密钥请求。');
      log(`[VaultMesh Passkey] ${op} ${ancestry.origin} -> VaultMesh (chose-vaultmesh)`);
      if (choice.remember) await rememberPasskeyChoice(op, ancestry, 'vaultmesh').catch(() => undefined);
      if (op === 'get' && probe.candidates.length > 0) {
        selectedCandidate = (choice.itemId ? probe.candidates.find((candidate) => candidate.itemId === choice.itemId) : undefined)
          ?? probe.candidates[0];
      }
    } else if (preference.reason) {
      log(`[VaultMesh Passkey] ${op} ${ancestry.origin} -> VaultMesh (${preference.reason})`);
    }

    const operation = op === 'create' ? 'passkeys.create' : 'passkeys.get';
    const loginId = op === 'create' && ancestry.sameOriginWithAncestors
      ? await rememberedLoginSelection(ancestry.origin).catch(() => null)
      : null;
    const input: Record<string, unknown> = {
      requestDetailsJson,
      ...(loginId ? { loginId } : {}),
      ...(selectedCandidate ? { itemId: selectedCandidate.itemId, credentialId: selectedCandidate.credentialId } : {}),
    };
    return invoke(operation, input, active, page, ancestry, deadlineAt);
  }

  function suspendConditional(
    id: string,
    page: PasskeyPage,
    ancestry: FrameAncestry,
    requestDetailsJson: string,
    candidates: PasskeyPromptCandidate[],
    active: Active,
  ): Promise<PasskeyOutcome> {
    const frameKey = conditionalKey(page.tabId, page.frameId);
    const previous = conditionals.get(frameKey);
    if (previous) {
      conditionals.delete(frameKey);
      previous.settle({ status: 'cancelled', message: '已被新的条件式通行密钥请求替代。' });
    }
    return new Promise((resolve) => {
      let settled = false;
      const settle = (outcome: PasskeyOutcome) => {
        if (settled) return;
        settled = true;
        if (conditionals.get(frameKey) === entry) conditionals.delete(frameKey);
        active.cancelPrompt = null;
        resolve(outcome);
      };
      const entry: PendingConditional = {
        id,
        page,
        ancestry,
        requestDetailsJson,
        candidates,
        resolving: false,
        settle,
      };
      conditionals.set(frameKey, entry);
      active.cancelPrompt = () => settle(cancelled(page, 'get', 'page-aborted-or-navigated', '通行密钥请求已取消。'));
      log(`[VaultMesh Passkey] get ${ancestry.origin} -> pending (conditional-pending)`);
    });
  }

  async function invoke(
    operation: 'passkeys.create' | 'passkeys.get',
    input: Record<string, unknown>,
    active: Active,
    page: PasskeyPage,
    ancestry: FrameAncestry,
    deadlineAt: number,
  ): Promise<PasskeyOutcome> {
    const promptOperation: PasskeyOperation = operation === 'passkeys.create' ? 'create' : 'get';
    const origin = ancestry.origin;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const response = await rpc(operation, input) as { responseJson?: unknown };
        if (active.aborted) return cancelled(page, promptOperation, 'page-aborted-or-navigated', '通行密钥请求已取消。');
        if (typeof response.responseJson !== 'string' || response.responseJson.length > MAX_PASSKEY_RESPONSE_CHARS) {
          throw new Error('Invalid Passkey response');
        }
        log(`[VaultMesh Passkey] ${promptOperation} ${origin} -> VaultMesh (served)`);
        return { status: 'ok', responseJson: response.responseJson };
      } catch (error) {
        // Fallback when desktop has no one-shot unlock waiter (returns unlock-required).
        if (attempt === 0 && error instanceof DesktopRpcError && error.code === 'unlock-required') {
          const result = await waitForUnlock(active, ancestry, promptOperation, remainingMs(deadlineAt));
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
    ancestry: FrameAncestry,
    operation: PasskeyOperation,
    stage: PasskeyPromptStage,
    extra: { candidates?: PasskeyPromptCandidate[] } = {},
    waitTimeoutMs: number = PASSKEY_PROMPT_WAIT_MS,
  ): Promise<{ result: PromptResult; remember: boolean; itemId?: string }> {
    if (waitTimeoutMs <= 0) {
      return Promise.resolve({ result: 'expired', remember: false });
    }
    return new Promise((resolve) => {
      const token = crypto.randomUUID();
      let timer: ReturnType<typeof setTimeout> | null = null;
      let poll: ReturnType<typeof setTimeout> | null = null;
      const pending: PendingPrompt = {
        token,
        operation,
        origin: ancestry.origin,
        topOrigin: ancestry.topOrigin,
        sameOriginWithAncestors: ancestry.sameOriginWithAncestors,
        stage,
        ...(extra.candidates ? { candidates: extra.candidates } : {}),
        active,
        remember: false,
        settle: (result) => {
          if (!prompts.delete(token)) return;
          if (timer) clearTimeout(timer);
          if (poll) clearTimeout(poll);
          options.hidePrompt?.(active.page, token);
          active.cancelPrompt = null;
          resolve({ result, remember: pending.remember, itemId: pending.selectedItemId });
        },
      };
      prompts.set(token, pending);
      active.cancelPrompt = () => pending.settle('cancel');
      timer = setTimeout(() => pending.settle('expired'), waitTimeoutMs);
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
      const view: PasskeyPrompt = {
        token,
        operation,
        origin: ancestry.origin,
        topOrigin: ancestry.topOrigin,
        sameOriginWithAncestors: ancestry.sameOriginWithAncestors,
        stage,
        ...(extra.candidates ? { candidates: extra.candidates } : {}),
      };
      void (async () => {
        const shown = options.showPrompt ? await options.showPrompt(active.page, view).catch(() => false) : false;
        if (prompts.has(token)) log(`[VaultMesh Passkey] ${operation} ${ancestry.origin} -> prompt (${stage}, ${shown ? 'in-page' : 'extension-window'})`);
        if (shown) active.promptOpened = true;
        else if (!active.promptOpened && prompts.has(token)) {
          active.promptOpened = true;
          await openPrompt().catch(() => undefined);
        }
      })();
    });
  }

  async function waitForUnlock(
    active: Active,
    ancestry: FrameAncestry,
    operation: PasskeyOperation,
    waitTimeoutMs: number,
  ): Promise<'unlocked' | 'native' | 'cancel' | 'expired'> {
    const { result } = await askPrompt(active, ancestry, operation, 'unlock', {}, waitTimeoutMs);
    return result === 'unlocked' || result === 'native' || result === 'expired' ? result : 'cancel';
  }

  /** Whether VaultMesh could serve a passkey for this page: takeover on, supported
   * browser adapter, trusted frame ancestry and a paired, reachable desktop. */
  async function availability(page: PasskeyPage): Promise<boolean> {
    if (!isSupported() || !options.isEnabled()) return false;
    const frames = await options.frames(page.tabId).catch(() => null);
    if (!frames || !resolveFrameAncestry(frames, page.frameId, page.origin)) return false;
    try {
      await rpc('vault.status');
      return true;
    } catch (error) {
      log(`[VaultMesh Passkey] availability ${page.origin} -> unavailable (${error instanceof DesktopRpcError ? `desktop-${error.code}` : 'desktop-unreachable'})`);
      return false;
    }
  }

  function conditionalCandidates(page: PasskeyPage): ConditionalPasskeyCandidate[] {
    const pending = conditionals.get(conditionalKey(page.tabId, page.frameId));
    if (!pending || pending.page.origin !== page.origin) return [];
    return pending.candidates.map((candidate) => ({ ...candidate, requestId: pending.id }));
  }

  async function resolveConditional(
    page: PasskeyPage,
    requestId: string,
    action: { action: 'vaultmesh'; itemId: string; credentialId: string } | { action: 'native' },
  ): Promise<{ status: 'ok' | 'fallback' | 'cancelled' | 'unlock-required' | 'error'; message?: string }> {
    const frameKey = conditionalKey(page.tabId, page.frameId);
    const pending = conditionals.get(frameKey);
    if (!pending || pending.id !== requestId || pending.page.origin !== page.origin) {
      return { status: 'cancelled', message: '条件式通行密钥请求已失效。' };
    }
    if (action.action === 'native') {
      conditionals.delete(frameKey);
      log(`[VaultMesh Passkey] get ${pending.ancestry.origin} -> browser (user-chose-browser)`);
      pending.settle(FALLBACK);
      return { status: 'fallback' };
    }
    if (pending.resolving) {
      return { status: 'cancelled', message: '正在处理通行密钥确认，请稍候。' };
    }
    const candidate = pending.candidates.find(
      (entry) => entry.itemId === action.itemId && entry.credentialId === action.credentialId,
    );
    if (!candidate) {
      return { status: 'error', message: '所选通行密钥无效。' };
    }
    pending.resolving = true;
    try {
      const response = await rpc('passkeys.get', {
        requestDetailsJson: pending.requestDetailsJson,
        itemId: candidate.itemId,
        credentialId: candidate.credentialId,
      }) as { responseJson?: unknown };
      if (conditionals.get(frameKey) !== pending) {
        return { status: 'cancelled', message: '通行密钥请求已取消。' };
      }
      if (typeof response.responseJson !== 'string' || response.responseJson.length > MAX_PASSKEY_RESPONSE_CHARS) {
        throw new Error('Invalid Passkey response');
      }
      conditionals.delete(frameKey);
      log(`[VaultMesh Passkey] get ${pending.ancestry.origin} -> VaultMesh (served)`);
      pending.settle({ status: 'ok', responseJson: response.responseJson });
      return { status: 'ok' };
    } catch (error) {
      if (conditionals.get(frameKey) !== pending) {
        return { status: 'cancelled', message: '通行密钥请求已取消。' };
      }
      if (error instanceof DesktopRpcError) {
        if (error.code === 'cancelled') {
          log(`[VaultMesh Passkey] get ${pending.ancestry.origin} -> pending (conditional-confirmation-declined)`);
          return { status: 'cancelled', message: error.message };
        }
        if (error.code === 'unlock-required') {
          void openPrompt().catch(() => undefined);
          return { status: 'unlock-required', message: error.message };
        }
        if (['passkey-unavailable', 'unpaired', 'desktop-unavailable'].includes(error.code)) {
          conditionals.delete(frameKey);
          log(`[VaultMesh Passkey] get ${pending.ancestry.origin} -> browser (desktop-${error.code})`);
          pending.settle(FALLBACK);
          return { status: 'fallback' };
        }
      }
      const failure = domException(error);
      conditionals.delete(frameKey);
      log(`[VaultMesh Passkey] get ${pending.ancestry.origin} -> error (${failure.name}: ${failure.message})`);
      pending.settle({ status: 'error', ...failure });
      return { status: 'error', message: failure.message };
    } finally {
      pending.resolving = false;
    }
  }

  function onSiteModeChanged(origin: string, mode: SitePasskeyMode) {
    if (mode !== 'native') return;
    for (const [frameKey, pending] of [...conditionals.entries()]) {
      if (pending.ancestry.origin !== origin && pending.ancestry.topOrigin !== origin) continue;
      conditionals.delete(frameKey);
      log(`[VaultMesh Passkey] get ${pending.ancestry.origin} -> browser (site-mode-native)`);
      pending.settle(FALLBACK);
    }
  }

  function abort(page: PasskeyPage, id: string) {
    const active = actives.get(`${page.tabId}:${page.frameId}:${id}`);
    if (active) {
      active.aborted = true;
      active.cancelPrompt?.();
    }
    const frameKey = conditionalKey(page.tabId, page.frameId);
    const pending = conditionals.get(frameKey);
    if (pending && pending.id === id) {
      conditionals.delete(frameKey);
      pending.settle(cancelled(page, 'get', 'page-aborted-or-navigated', '通行密钥请求已取消。'));
    }
  }

  /** Navigation, reload or tab close ends every request owned by that document. */
  function cancelPage(tabId: number, frameId?: number) {
    for (const active of actives.values()) {
      if (active.page.tabId !== tabId || (frameId !== undefined && active.page.frameId !== frameId)) continue;
      active.aborted = true;
      active.cancelPrompt?.();
    }
    for (const [frameKey, pending] of [...conditionals.entries()]) {
      if (pending.page.tabId !== tabId || (frameId !== undefined && pending.page.frameId !== frameId)) continue;
      conditionals.delete(frameKey);
      pending.settle(cancelled(pending.page, 'get', 'page-aborted-or-navigated', '通行密钥请求已取消。'));
    }
  }

  /** Cancels conditional requests only when history navigation changes route (`origin + pathname`) for that tab+frame. */
  function cancelHistoryNavigation(tabId: number, frameId: number, nextUrl: string) {
    const frameKey = conditionalKey(tabId, frameId);
    const pending = conditionals.get(frameKey);
    if (!pending) return;
    if (!shouldCancelForHistoryUrl(pending.page.pageUrl, pending.ancestry.origin, nextUrl)) return;
    conditionals.delete(frameKey);
    pending.settle(cancelled(pending.page, 'get', 'page-aborted-or-navigated', '通行密钥请求已取消。'));
  }

  function currentPrompt(): PasskeyPrompt | null {
    const latest = [...prompts.values()].at(-1);
    if (!latest) return null;
    return {
      token: latest.token,
      operation: latest.operation,
      origin: latest.origin,
      topOrigin: latest.topOrigin,
      sameOriginWithAncestors: latest.sameOriginWithAncestors,
      stage: latest.stage,
      ...(latest.candidates ? { candidates: latest.candidates } : {}),
    };
  }

  /** `native` hands the same call to the browser; `cancel` rejects it as a user cancel. */
  function choose(token: string, choice: PasskeyChoice, remember = false, fromTabId?: number, itemId?: string): boolean {
    const pending = prompts.get(token);
    if (!pending) return false;
    // A page-hosted dialog may only answer prompts of its own tab.
    if (fromTabId !== undefined && pending.active.page.tabId !== fromTabId) return false;
    if (pending.stage === 'unlock' && choice === 'vaultmesh') return false;
    if (pending.stage === 'no-match' && choice === 'vaultmesh') return false;
    const canRemember =
      pending.stage === 'no-match'
      || (pending.stage === 'choose' && !(pending.operation === 'create' && pending.sameOriginWithAncestors === false));
    pending.remember = remember && canRemember && choice !== 'cancel';
    pending.selectedItemId = choice === 'vaultmesh' ? itemId : undefined;
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

  return {
    handle,
    abort,
    availability,
    conditionalCandidates,
    resolveConditional,
    onSiteModeChanged,
    cancelPage,
    cancelHistoryNavigation,
    currentPrompt,
    choose,
    syncUnlockState,
  };
}

function parseRawOptions(optionsJson: string): Record<string, unknown> | null {
  let parsed: unknown;
  try { parsed = JSON.parse(optionsJson); } catch { return null; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
}

function buildRequestDetailsFromObject(
  operation: PasskeyOperation,
  parsed: Record<string, unknown>,
  page: Pick<PasskeyPage, 'origin'> & { topOrigin?: string; sameOriginWithAncestors?: boolean },
): Record<string, unknown> | null {
  const options = { ...parsed };
  delete options.mediation;
  const hostname = new URL(page.origin).hostname;
  const supplied = options.extensions && typeof options.extensions === 'object' && !Array.isArray(options.extensions)
    ? options.extensions as Record<string, unknown>
    : {};
  const extensions: Record<string, unknown> = {};
  if (typeof supplied.appid === 'string') extensions.appid = supplied.appid;
  if (typeof supplied.credProps === 'boolean') extensions.credProps = supplied.credProps;
  if (page.sameOriginWithAncestors === false) {
    if (!page.topOrigin) return null;
    extensions.remoteDesktopClientOverride = {
      origin: page.origin,
      sameOriginWithAncestors: false,
      topOrigin: page.topOrigin,
    };
  } else {
    extensions.remoteDesktopClientOverride = { origin: page.origin, sameOriginWithAncestors: true };
  }
  options.extensions = extensions;
  if (operation === 'get') {
    if (options.rpId === undefined) options.rpId = hostname;
  } else {
    const rp = options.rp && typeof options.rp === 'object' && !Array.isArray(options.rp)
      ? { ...(options.rp as Record<string, unknown>) }
      : null;
    if (!rp) return null;
    if (rp.id === undefined) rp.id = hostname;
    options.rp = rp;
  }
  return options;
}

/** Rebuilds the desktop request from page options. The origin and ancestry
 * come from the browser-verified sender, never from the page. */
export function buildRequestDetails(
  request: PasskeyRequest,
  page: Pick<PasskeyPage, 'origin'> & { topOrigin?: string; sameOriginWithAncestors?: boolean },
): Record<string, unknown> | null {
  const parsed = parseRawOptions(request.optionsJson);
  return parsed ? buildRequestDetailsFromObject(request.operation, parsed, page) : null;
}

function parseProbeResult(raw: unknown): ParsedProbe {
  if (!raw || typeof raw !== 'object') {
    return { status: 'unknown', candidates: [] };
  }
  const value = raw as { status?: unknown; candidates?: unknown };
  const status = value.status === 'available' || value.status === 'unavailable' ? value.status : 'unknown';
  const candidates: PasskeyPromptCandidate[] = Array.isArray(value.candidates)
    ? value.candidates.flatMap((entry): PasskeyPromptCandidate[] => {
        if (!entry || typeof entry !== 'object') return [];
        const c = entry as { itemId?: unknown; credentialId?: unknown; title?: unknown; account?: unknown };
        if (typeof c.itemId !== 'string' || typeof c.credentialId !== 'string' || typeof c.title !== 'string') return [];
        return [{
          itemId: c.itemId,
          credentialId: c.credentialId,
          title: c.title.slice(0, 256),
          account: typeof c.account === 'string' ? c.account.slice(0, 256) : null,
        }];
      })
    : [];
  return {
    status,
    candidates,
  };
}

function remainingMs(deadlineAt: number): number {
  return Math.max(0, deadlineAt - Date.now());
}

function shouldCancelForHistoryUrl(previousUrl: string | undefined, expectedOrigin: string, nextUrl: string): boolean {
  try {
    const next = new URL(nextUrl);
    if (next.protocol !== 'http:' && next.protocol !== 'https:') return true;
    if (next.origin !== expectedOrigin) return true;
    if (!previousUrl) return false;
    const prev = new URL(previousUrl);
    return `${prev.origin}${prev.pathname}` !== `${next.origin}${next.pathname}`;
  } catch {
    return false;
  }
}

export function domException(error: unknown): { name: string; message: string } {
  const message = error instanceof Error ? error.message.slice(0, 256) : 'VaultMesh 无法完成 Passkey 请求。';
  if (/算法|安全密钥|largeBlob|不支持/i.test(message)) return { name: 'NotSupportedError', message };
  if (/已存在/i.test(message)) return { name: 'InvalidStateError', message };
  return { name: 'NotAllowedError', message };
}
