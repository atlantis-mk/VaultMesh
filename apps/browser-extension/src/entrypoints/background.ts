import {
  ContentMessageSchema,
  DiscoveryFrameResponseSchema,
  type DiscoveryFrame,
  type ContentMessage,
  type FillRequest,
  AutofillCandidateSchema,
  EmailOtpCandidateSchema,
  PopupMessageSchema,
  MAX_FIELDS_PER_REQUEST,
  type SaveCaptureQueuedResponse,
} from "@/lib/protocol";
import { ApprovedFillSchema } from "@/lib/protocol";
import {
  backgroundDesktopRpc,
  DesktopRpcError,
  isDesktopRpcRuntimeMessage,
} from "@/lib/desktop-rpc";
import { persistentNativeConnection } from "@/lib/native-connection";
import { AutofillAttemptRegistry } from "@/lib/autofill-attempts";
import { presentBrowserSaveConfirmation } from "@/lib/browser-save-confirmation";
import { SAVE_CAPTURE_DECISION_TIMEOUT_MS } from "@/lib/save-capture-countdown";
import { runCaptureSaveOnce } from "@/lib/capture-save-gate";
import { SAVE_CONFIRMATION_WINDOW_HEIGHT, SAVE_CONFIRMATION_WINDOW_WIDTH, saveConfirmationWindowPosition } from "@/lib/save-confirmation-window";
import { rememberedLoginSelection, rememberLoginSelection } from "@/lib/autofill-preferences";
import { chooseAutomaticLogin, fieldsForLoginSelection, rankLoginCandidates, requiresFillConfirmation, shouldQueueFillConfirmation, shouldReplaceExistingFields, shouldWaitForLoginPair } from "@/lib/autofill-selection";
import { sameOriginFrameIds } from "@/lib/frame-origin";
import type { CapturedCard, CapturedIdentity, CapturedLogin, CapturedSaveData, CapturedSecret, CapturedSshCredential } from "@/lib/save-capture";
import { cardCaptureStatusInput } from "@/lib/save-capture-card";
import { buildIdentityUpdate, identityMatchesCapture, identityUpdateChanges, type ExistingIdentity } from "@/lib/save-capture-identity";
import { routeLoginCaptureByDefault, routeLoginCaptureByUsername } from "@/lib/save-capture-routing";
import { capturedSecretAddInput } from "@/lib/save-capture-secret";
import { pendingSavePreparationForPage, pendingSavePromptForPage } from "@/lib/pending-save-prompt";
import {
  DEFAULT_PLUGIN_SECURITY_POLICY,
  idleDetectionIntervalSeconds,
  loadPluginSecurityPolicy,
  shouldLockForIdleState,
  type BrowserIdleState,
  type PluginSecurityPolicy,
} from "@/lib/plugin-security-policy";
import { installPasskeyProxy } from "@/lib/passkey-proxy";
import { PopupWorkspaceMemoryCache } from "@/lib/popup-workspace-cache";
import {
  accountStageKey,
  currentLoginAccounts,
  fillEmailOtpForActiveTab,
  fillEmailOtpForTab,
  getAutofillAvailability,
  getAutofillCandidates,
  getEmailOtpCandidates,
  getHttpOrigin,
  isTrustedExtensionPage,
  startAutomaticFillForTab,
  startFillForActiveTab,
  startFillForTab,
  trustedPage,
} from "@/lib/background-fill";

const CONTEXT_MENU_ID = "vaultmesh-request-fill";
const NATIVE_RECONNECT_ALARM = "vaultmesh-native-reconnect";
const EMAIL_OTP_POLL_MS = 3_000;
const automaticAttempts = new AutofillAttemptRegistry();
const popupWorkspaceCache = new PopupWorkspaceMemoryCache();
type PendingPluginFill = {
  token: string;
  tabId: number;
  targetOrigin: string;
  targetPageUrl: string;
  selectedItem: NonNullable<FillRequest["selectedItem"]>;
  requiresPassword: boolean;
  expiresAt: number;
  target?: import("@/lib/protocol").AutofillTarget;
  targetFrameId?: number;
  preserveExistingAccount?: boolean;
};
let pendingPluginFill: PendingPluginFill | null = null;
let activePluginSecurityPolicy = DEFAULT_PLUGIN_SECURITY_POLICY;
let emailOtpPollTimer: ReturnType<typeof setInterval> | null = null;
const emailOtpBoostedTabs = new Map<number, string>();
type BrowserActionApi = typeof browser.action;
const extensionAction = (browser as unknown as {
  action?: BrowserActionApi;
  browserAction?: BrowserActionApi;
}).action ?? (browser as unknown as { browserAction?: BrowserActionApi }).browserAction;

export default defineBackground(() => {
  // Listener registration is deliberately synchronous: Chromium requires the
  // WebAuthn proxy handlers to exist as soon as the MV3 worker starts.
  const passkeyProxy = installPasskeyProxy();
  // The background worker, rather than the popup, owns the native
  // connection. An open native port also keeps the MV3 worker available.
  persistentNativeConnection.start();
  persistentNativeConnection.onDisconnected(() => {
    popupWorkspaceCache.clear();
    stopEmailOtpPolling();
  });
  void warmPopupWorkspaceCache();
  void syncEmailOtpPolling();
  void passkeyProxy.sync();
  void refreshPluginSecurityPolicy();
  void browser.alarms.create(NATIVE_RECONNECT_ALARM, { periodInMinutes: 1 });
  browser.runtime.onStartup.addListener(() => {
    popupWorkspaceCache.clear();
    persistentNativeConnection.ensureConnected();
    void syncEmailOtpPolling();
    void refreshPluginSecurityPolicy().then((policy) => {
      if (policy.lockOnBrowserRestart) lockExtensionWithRetry(3, () => passkeyProxy.detach());
    });
  });
  browser.idle.onStateChanged.addListener((state) => {
    if (shouldLockForIdleState(activePluginSecurityPolicy, state as BrowserIdleState)) {
      void lockExtension(() => passkeyProxy.detach());
    }
  });
  browser.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === NATIVE_RECONNECT_ALARM) {
      persistentNativeConnection.ensureConnected();
      void passkeyProxy.sync();
    }
  });
  browser.tabs.onRemoved.addListener((tabId) => {
    automaticAttempts.reset(tabId);
    for (const key of stagedAccounts.keys()) if (key.startsWith(`${tabId}:`)) stagedAccounts.delete(key);
    for (const key of currentLoginAccounts.keys()) if (key.startsWith(`${tabId}:`)) currentLoginAccounts.delete(key);
    for (const [captureId, pending] of pendingCredentialCaptures) if (pending.tabId === tabId) discardSaveCapture(captureId);
    for (const [captureId, preparing] of preparingCredentialCaptures) if (preparing.tabId === tabId) discardPreparingSaveCapture(captureId);
    void stopEmailOtpBoostForTab(tabId);
  });
  browser.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0) {
      automaticAttempts.reset(details.tabId);
      void stopEmailOtpBoostForTab(details.tabId);
    }
  });
  browser.webNavigation.onHistoryStateUpdated.addListener((details) => {
    if (details.frameId === 0) {
      automaticAttempts.reset(details.tabId);
    }
    // Same-origin iframe routes keep their content script and document id too.
    // Every affected frame must retire discovery handles before the next scan.
    void browser.tabs.sendMessage(details.tabId, { kind: "vaultmesh.autofill-rescan" }, { frameId: details.frameId }).catch(() => undefined);
  });
  browser.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId === 0) void presentPendingSavePromptForTab(details.tabId);
  });
  browser.windows.onRemoved.addListener((windowId) => {
    const captureId = saveCaptureIdsByWindow.get(windowId);
    if (!captureId) return;
    saveCaptureIdsByWindow.delete(windowId);
    saveCaptureWindows.delete(captureId);
    discardSaveCapture(captureId);
  });
  browser.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (!notificationId.startsWith(CREDENTIAL_NOTIFICATION_PREFIX)) return;
    const captureId = notificationId.slice(CREDENTIAL_NOTIFICATION_PREFIX.length);
    if (buttonIndex === 0) void saveCapture(captureId);
    else discardSaveCapture(captureId);
  });
  browser.notifications.onClicked.addListener((notificationId) => {
    if (!notificationId.startsWith(CREDENTIAL_NOTIFICATION_PREFIX)) return;
    const captureId = notificationId.slice(CREDENTIAL_NOTIFICATION_PREFIX.length);
    const pending = pendingCredentialCaptures.get(captureId);
    if (pending) void ensureSaveCaptureWindow(captureId);
  });
  browser.runtime.onInstalled.addListener(() => {
    popupWorkspaceCache.clear();
    persistentNativeConnection.ensureConnected();
    browser.contextMenus.removeAll().then(() => {
      browser.contextMenus.create({
        id: CONTEXT_MENU_ID,
        title: "使用 VaultMesh 填充当前表单",
        contexts: ["page", "editable"],
        documentUrlPatterns: ["http://*/*", "https://*/*"],
      });
    });
  });

  browser.commands.onCommand.addListener((command) => {
    if (command === "request-identity-fill") {
      void extensionAction?.openPopup();
    }
  });

  browser.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === CONTEXT_MENU_ID && tab?.id != null) {
      void extensionAction?.openPopup();
    }
  });

  browser.runtime.onMessage.addListener(async (message, sender) => {
    if (isDesktopRpcRuntimeMessage(message)) {
      if (!isTrustedExtensionPage(sender)) {
        return { kind: "vaultmesh.host-status", status: "invalid-message", requestId: message.request.requestId };
      }
      if (message.request.operation === 'vault.lock' || message.request.operation === 'browser.pairing.revoke') popupWorkspaceCache.clear();
      const response = await persistentNativeConnection.request(message.request);
      popupWorkspaceCache.observeRpcResponse(message.request.operation, response);
      if (['vault.create', 'vault.unlock', 'biometric.unlock', 'pin.unlock'].includes(message.request.operation)) void passkeyProxy.sync();
      if (['vault.create', 'vault.unlock', 'biometric.unlock', 'pin.unlock'].includes(message.request.operation)) startEmailOtpPolling();
      if (message.request.operation === 'vault.lock' || message.request.operation === 'browser.pairing.revoke') {
        stopEmailOtpPolling();
      }
      if (message.request.operation === 'vault.lock') void passkeyProxy.detach();
      return response;
    }

    const parsed = PopupMessageSchema.safeParse(message);
    if (!parsed.success) {
      return undefined;
    }
    if (parsed.data.kind === "vaultmesh.popup-workspace-cache.get") {
      if (!isTrustedExtensionPage(sender)) return { status: "empty" as const };
      const cached = popupWorkspaceCache.read();
      return cached ? { status: "ready" as const, ...cached } : { status: "empty" as const };
    }
    if (parsed.data.kind === "vaultmesh.save-capture-popup.get") {
      if (!isTrustedExtensionPage(sender)) return { status: "none" as const };
      return pendingSaveCaptureForActiveTab();
    }
    if (parsed.data.kind === "vaultmesh.save-capture-popup.decision") {
      if (!isTrustedExtensionPage(sender)) return { status: "unsupported-page" as const };
      if (parsed.data.decision === "ignore") {
        const pending = pendingCredentialCaptures.get(parsed.data.captureId);
        if (!pending || pending.expiresAt <= Date.now()) {
          discardSaveCapture(parsed.data.captureId);
          return { status: "expired" as const };
        }
        discardSaveCapture(parsed.data.captureId);
        return { status: "discarded" as const };
      }
      return saveCapture(parsed.data.captureId);
    }
    if (parsed.data.kind === "vaultmesh.save-capture-window.get") {
      const captureId = saveCaptureIdForWindow(sender);
      if (!captureId) return { status: "none" as const };
      const pending = pendingCredentialCaptures.get(captureId);
      if (!pending || pending.expiresAt <= Date.now()) {
        discardSaveCapture(captureId);
        return { status: "none" as const };
      }
      return pending.prompt;
    }
    if (parsed.data.kind === "vaultmesh.save-capture-window.decision") {
      const captureId = saveCaptureIdForWindow(sender);
      if (!captureId) return { status: "unsupported-page" as const };
      const pending = pendingCredentialCaptures.get(captureId);
      if (!pending || pending.expiresAt <= Date.now()) {
        discardSaveCapture(captureId);
        return { status: "expired" as const };
      }
      if (parsed.data.decision === "ignore") {
        discardSaveCapture(captureId);
        return { status: "discarded" as const };
      }
      return saveCapture(captureId);
    }
    if (parsed.data.kind === "vaultmesh.security-policy.updated") {
      if (!isTrustedExtensionPage(sender)) return { status: "unsupported-page" as const };
      await refreshPluginSecurityPolicy();
      return { status: "updated" as const };
    }
    if (parsed.data.kind === "vaultmesh.email-otp-fill") {
      if (!isTrustedExtensionPage(sender)) return { status: "unsupported-page" as const };
      return fillEmailOtpForActiveTab(parsed.data.candidateId);
    }
    if (parsed.data.kind === "vaultmesh.start-fill") {
      if (!isTrustedExtensionPage(sender)) return { status: "unsupported-page" as const };
      if (parsed.data.fillConfirmationToken) {
        const pending = currentPendingPluginFill(parsed.data.fillConfirmationToken);
        if (!pending) return { status: "request-expired" as const, errorMessage: "填充确认请求已过期，请重新选择。" };
        const result = await startFillForTab(pending.tabId, pending.selectedItem, {
          mode: "selection",
          targetOrigin: pending.targetOrigin,
          targetPageUrl: pending.targetPageUrl,
          masterPassword: parsed.data.masterPassword,
          target: pending.target,
          targetFrameId: pending.targetFrameId,
          preserveExistingAccount: pending.preserveExistingAccount,
        });
        if (result.status === "filled" && pending.selectedItem.kind === "login") {
          await rememberLoginSelection(pending.targetOrigin, pending.selectedItem.id).catch(() => undefined);
        }
        if (result.status === "filled" && pendingPluginFill?.token === pending.token) pendingPluginFill = null;
        return result;
      }
      return startFillForActiveTab(parsed.data.selectedItem, parsed.data.masterPassword);
    }
    if (parsed.data.kind === "vaultmesh.fill-confirmation.get") {
      if (!isTrustedExtensionPage(sender)) return null;
      const pending = currentPendingPluginFill();
      return pending ? { fillConfirmationToken: pending.token, selectedItem: pending.selectedItem, requiresPassword: pending.requiresPassword } : null;
    }
    if (parsed.data.kind === "vaultmesh.fill-confirmation.cancel") {
      if (!isTrustedExtensionPage(sender)) return { status: "unsupported-page" as const };
      if (pendingPluginFill?.token === parsed.data.fillConfirmationToken) pendingPluginFill = null;
      return { status: "cancelled" as const };
    }
    const page = trustedPage(sender);
    if (!page) return { status: "unsupported-page" as const, candidates: [] };
    if (parsed.data.kind === "vaultmesh.autofill-state") return getAutofillAvailability();
    if (parsed.data.kind === "vaultmesh.open-unlock") {
      await extensionAction?.openPopup();
      return { status: "opened" as const };
    }
    if (parsed.data.kind === "vaultmesh.autofill-candidates") {
      const result = await getAutofillCandidates(page.fillOrigin, parsed.data.fieldKind, page.framePageUrl, parsed.data.pageContext);
      if (result.status !== "ready" || parsed.data.pageContext !== "otp" || page.fillOrigin !== page.topOrigin) return result;
      const emailOtp = await getEmailOtpCandidates(page.topOrigin);
      return { ...result, emailOtpCandidates: emailOtp.status === "ready" ? emailOtp.candidates : [] };
    }
    if (parsed.data.kind === "vaultmesh.email-otp-select") {
      if (page.fillOrigin !== page.topOrigin) return { status: "unsupported-page" as const };
      return fillEmailOtpForTab(page.tabId, page.topOrigin, page.framePageUrl, parsed.data.candidateId, parsed.data.target, sender.frameId ?? 0);
    }
    if (parsed.data.kind === "vaultmesh.save-capture-pending") return pendingSaveCaptureForPage(page, sender.frameId);
    if (parsed.data.kind === "vaultmesh.otp-watch-requested") {
      try {
        await backgroundDesktopRpc("email.otp.watch", { topOrigin: page.topOrigin, active: true });
        emailOtpBoostedTabs.set(page.tabId, page.topOrigin);
        startEmailOtpPolling();
      } catch {
        // TOTP candidates remain available when Email OTP is disabled or unavailable.
      }
      const result = await getAutofillCandidates(page.fillOrigin, "login", page.framePageUrl, "otp");
      return { status: result.status === "ready" ? "watching" as const : result.status };
    }
    if (parsed.data.kind === "vaultmesh.autofill-select") {
      if (!requiresFillConfirmation(parsed.data.selectedItem)) {
        const result = await startFillForTab(page.tabId, parsed.data.selectedItem, {
          mode: "selection",
          targetOrigin: page.fillOrigin,
          targetPageUrl: page.framePageUrl,
          preserveExistingAccount: parsed.data.replaceExistingAccount !== true,
          target: parsed.data.target,
          targetFrameId: sender.frameId ?? 0,
        });
        if (result.status === "filled" && parsed.data.selectedItem.kind === "login") {
          await rememberLoginSelection(page.fillOrigin, parsed.data.selectedItem.id).catch(() => undefined);
        }
        // The desktop remains authoritative for the stored item's re-prompt
        // policy. A stale candidate summary must fall back to confirmation,
        // never turn a required re-prompt into a silent failure.
        if (!shouldQueueFillConfirmation(parsed.data.selectedItem, result.status)) return result;
      }
      pendingPluginFill = {
        token: crypto.randomUUID(),
        tabId: page.tabId,
        targetOrigin: page.fillOrigin,
        targetPageUrl: page.framePageUrl,
        selectedItem: parsed.data.selectedItem,
        requiresPassword: true,
        expiresAt: Date.now() + 60_000,
        target: parsed.data.target,
        targetFrameId: sender.frameId ?? 0,
        preserveExistingAccount: parsed.data.replaceExistingAccount !== true,
      };
      await extensionAction?.openPopup();
      return { status: "confirmation-required" as const };
    }
    if (parsed.data.kind === "vaultmesh.save-capture-confirmed") {
      const queued = await queueSaveCapture({ ...parsed.data, pageContext: "unknown" }, page, { notify: false });
      if (queued.status !== "queued") return queued;
      return saveCapture(queued.captureId, { notify: false });
    }
    if (parsed.data.kind === "vaultmesh.account-stage") return stageAccount(parsed.data, page);
    if (parsed.data.kind === "vaultmesh.save-capture-decision") return decideSaveCapture(parsed.data, page);
    if (parsed.data.kind === "vaultmesh.save-capture") return queueSaveCapture(parsed.data, page);
    if (!automaticAttempts.begin(page.tabId, page.fillOrigin, parsed.data.signature, parsed.data.documentId)) return { status: "already-attempted" as const };
    return startAutomaticFillForTab(page.tabId, page.fillOrigin, parsed.data.pageContext === "otp" ? "otp" : "login", page.framePageUrl, parsed.data.target, sender.frameId ?? 0);
  });
});

async function refreshPluginSecurityPolicy(): Promise<PluginSecurityPolicy> {
  activePluginSecurityPolicy = await loadPluginSecurityPolicy();
  browser.idle.setDetectionInterval(idleDetectionIntervalSeconds(activePluginSecurityPolicy));
  return activePluginSecurityPolicy;
}

async function warmPopupWorkspaceCache(): Promise<void> {
  try {
    const status = await backgroundDesktopRpc("vault.status") as { unlocked?: unknown };
    if (status.unlocked !== true) {
      popupWorkspaceCache.clear();
      return;
    }
    popupWorkspaceCache.storeSnapshot(await backgroundDesktopRpc("vault.workspace"));
  } catch {
    popupWorkspaceCache.clear();
  }
}

async function syncEmailOtpPolling(): Promise<void> {
  try {
    const status = await backgroundDesktopRpc("vault.status") as { unlocked?: unknown };
    if (status.unlocked === true) startEmailOtpPolling();
    else stopEmailOtpPolling();
  } catch {
    stopEmailOtpPolling();
  }
}

function startEmailOtpPolling(): void {
  if (emailOtpPollTimer) return;
  const poll = () => void backgroundDesktopRpc("email.otp.poll").catch((error) => {
    if (error instanceof DesktopRpcError && error.code === "unlock-required") stopEmailOtpPolling();
  });
  poll();
  emailOtpPollTimer = setInterval(poll, EMAIL_OTP_POLL_MS);
}

function stopEmailOtpPolling(): void {
  if (emailOtpPollTimer) clearInterval(emailOtpPollTimer);
  emailOtpPollTimer = null;
  emailOtpBoostedTabs.clear();
}

async function stopEmailOtpBoostForTab(tabId: number): Promise<void> {
  const origin = emailOtpBoostedTabs.get(tabId);
  emailOtpBoostedTabs.delete(tabId);
  if (!origin) return;
  await backgroundDesktopRpc("email.otp.watch", { topOrigin: origin, active: false }).catch(() => undefined);
}

async function lockExtension(onLocked: () => void | Promise<void> = () => {}): Promise<boolean> {
  popupWorkspaceCache.clear();
  try {
    await backgroundDesktopRpc("vault.lock");
    await onLocked();
    return true;
  } catch {
    return false;
  }
}

function lockExtensionWithRetry(attemptsRemaining = 3, onLocked: () => void | Promise<void> = () => {}): void {
  void lockExtension(onLocked).then((locked) => {
    if (locked || attemptsRemaining <= 1) return;
    persistentNativeConnection.ensureConnected();
    setTimeout(() => lockExtensionWithRetry(attemptsRemaining - 1, onLocked), 1_000);
  });
}

const CREDENTIAL_NOTIFICATION_PREFIX = "vaultmesh-credential-";
type SaveCapture = { captureId: string; pageUrl: string; pageContext: import("@/lib/protocol").PageContext; data: CapturedSaveData };
const pendingCredentialCaptures = new Map<string, { capture: SaveCapture; tabId: number; fillOrigin: string; expiresAt: number; timer: ReturnType<typeof setTimeout>; prompt: SaveCaptureQueuedResponse }>();
const saveCaptureWindows = new Map<string, number>();
const saveCaptureIdsByWindow = new Map<number, string>();
const openingSaveCaptureWindows = new Map<string, Promise<void>>();
const preparingCredentialCaptures = new Map<string, { tabId: number; fillOrigin: string; expiresAt: number; timer: ReturnType<typeof setTimeout> }>();
const stagedAccounts = new Map<string, { username: string; expiresAt: number }>();

function currentPendingPluginFill(token?: string): PendingPluginFill | null {
  if (!pendingPluginFill || pendingPluginFill.expiresAt <= Date.now() || token && pendingPluginFill.token !== token) {
    if (pendingPluginFill?.expiresAt && pendingPluginFill.expiresAt <= Date.now()) pendingPluginFill = null;
    return null;
  }
  return pendingPluginFill;
}

function stageAccount(message: { pageUrl: string; username: string }, page: { tabId: number; fillOrigin: string }) {
  if (new URL(message.pageUrl).origin !== page.fillOrigin) return { status: "unsupported-page" as const };
  const key = accountStageKey(page.tabId, page.fillOrigin);
  const account = { username: message.username, expiresAt: Date.now() + 5 * 60_000 };
  stagedAccounts.set(key, account);
  currentLoginAccounts.set(key, account);
  return { status: "staged" as const };
}

async function queueSaveCapture(
  capture: SaveCapture,
  page: { tabId: number; topOrigin: string; fillOrigin: string; pageUrl: string; framePageUrl: string },
  options: { notify?: boolean } = {},
) {
  if (new URL(capture.pageUrl).origin !== page.fillOrigin) return { status: "unsupported-page" as const };
  discardPreparingSaveCapture(capture.captureId);
  const timer = setTimeout(() => discardPreparingSaveCapture(capture.captureId), 120_000);
  preparingCredentialCaptures.set(capture.captureId, {
    tabId: page.tabId,
    fillOrigin: page.fillOrigin,
    expiresAt: Date.now() + 120_000,
    timer,
  });
  try {
    const result = await prepareSaveCapture(capture, page, options);
    if (result.status === "queued" && options.notify !== false) void presentPendingSavePromptForTab(page.tabId);
    return result;
  } finally {
    discardPreparingSaveCapture(capture.captureId);
  }
}

async function prepareSaveCapture(
  capture: SaveCapture,
  page: { tabId: number; topOrigin: string; fillOrigin: string; pageUrl: string; framePageUrl: string },
  options: { notify?: boolean },
) {
  const stagedKey = accountStageKey(page.tabId, page.fillOrigin);
  const staged = stagedAccounts.get(stagedKey);
  if (capture.data.login && !capture.data.login.username && staged && staged.expiresAt > Date.now()) {
    capture = { ...capture, data: { ...capture.data, login: { ...capture.data.login, username: staged.username } } };
  }
  stagedAccounts.delete(stagedKey);
  let submittedLogin = capture.data.login;
  let loginCandidates: Array<{ id: string; subtitle: string }> | null = null;
  if (submittedLogin && !submittedLogin.username && !submittedLogin.loginId && capture.pageContext === "password-change") {
    try {
      const defaultLoginId = await rememberedLoginSelection(page.fillOrigin);
      if (!defaultLoginId) return { status: "account-check-failed" as const, captureId: capture.captureId };
      loginCandidates = await loginCandidatesForCapture(submittedLogin, capture.pageUrl, capture.pageContext, page.fillOrigin);
      const routedLogin = routeLoginCaptureByDefault(submittedLogin, loginCandidates, defaultLoginId);
      if (!routedLogin.loginId) return { status: "account-check-failed" as const, captureId: capture.captureId };
      submittedLogin = routedLogin;
      capture = { ...capture, data: { ...capture.data, login: routedLogin } };
    } catch {
      return { status: "account-check-failed" as const, captureId: capture.captureId };
    }
  }
  if (submittedLogin?.username) currentLoginAccounts.set(stagedKey, { username: submittedLogin.username, expiresAt: Date.now() + 5 * 60_000 });
  if (submittedLogin?.username) {
    try {
      const candidates = loginCandidates
        ?? await loginCandidatesForCapture(submittedLogin, capture.pageUrl, capture.pageContext, page.fillOrigin);
      const routedLogin = routeLoginCaptureByUsername(submittedLogin, candidates);
      if (routedLogin.loginId) {
        const comparison = await backgroundDesktopRpc("browser.login.password-changed", {
          id: routedLogin.loginId,
          password: routedLogin.password,
        }) as { changed?: unknown };
        if (typeof comparison.changed !== "boolean") throw new Error("Invalid password comparison response");
        if (!comparison.changed) {
          if (!capture.data.identity && !capture.data.card && !capture.data.secrets?.length && !capture.data.sshCredentials?.length) {
            return { status: "unchanged" as const, captureId: capture.captureId };
          }
          const { login: _unchangedLogin, ...remainingData } = capture.data;
          capture = { ...capture, data: remainingData };
        } else {
          capture = { ...capture, data: { ...capture.data, login: routedLogin } };
        }
      } else {
        capture = { ...capture, data: { ...capture.data, login: routedLogin } };
      }
    } catch {
      // A failed lookup is not evidence that the account is new.  Stop here so
      // the UI can report the verification failure instead of offering a
      // misleading new-account save that could create a duplicate.
      return { status: "account-check-failed" as const, captureId: capture.captureId };
    }
  } else if (submittedLogin?.loginId) {
    const { loginId: _discardedLoginId, ...newLogin } = submittedLogin;
    capture = { ...capture, data: { ...capture.data, login: newLogin } };
  }
  if (capture.data.identity) {
    try {
      const plan = await planIdentityCapture(capture.data.identity);
      if (plan.changed) capture = { ...capture, data: { ...capture.data, identity: plan.identity } };
      else {
        const { identity: _unchangedIdentity, ...remainingData } = capture.data;
        capture = { ...capture, data: remainingData };
      }
    } catch {
      return { status: "save-check-failed" as const, captureId: capture.captureId };
    }
  }
  if (capture.data.card) {
    try {
      const plannedCard = await planCardCapture(capture.data.card);
      if (plannedCard) capture = { ...capture, data: { ...capture.data, card: plannedCard } };
      else {
        const { card: _unchangedCard, ...remainingData } = capture.data;
        capture = { ...capture, data: remainingData };
      }
    } catch {
      return { status: "save-check-failed" as const, captureId: capture.captureId };
    }
  }
  if (!capture.data.login && !capture.data.identity && !capture.data.card && !capture.data.secrets?.length && !capture.data.sshCredentials?.length) {
    return { status: "unchanged" as const, captureId: capture.captureId };
  }
  const hostname = new URL(capture.pageUrl).hostname;
  const labels = [
    capture.data.login ? "登录信息" : "",
    capture.data.identity ? "个人资料/地址" : "",
    capture.data.card ? "支付卡" : "",
    capture.data.secrets?.length ? `机密信息（${capture.data.secrets.length}）` : "",
    capture.data.sshCredentials?.length ? `SSH 凭据（${capture.data.sshCredentials.length}）` : "",
  ].filter(Boolean);
  const loginUpdate = Boolean(capture.data.login?.loginId);
  const actions = {
    ...(capture.data.login ? { login: capture.data.login.loginId ? "update" as const : "new" as const } : {}),
    ...(capture.data.identity ? { identity: capture.data.identity.identityId ? "update" as const : "new" as const } : {}),
    ...(capture.data.card ? { card: capture.data.card.cardId ? "update" as const : "new" as const } : {}),
    ...(capture.data.secrets?.length ? { secret: "new" as const } : {}),
    ...(capture.data.sshCredentials?.length ? { ssh: "new" as const } : {}),
  };
  const captureUpdate = Boolean(capture.data.login?.loginId || capture.data.identity?.identityId || capture.data.card?.cardId);
  // Keep login capture wording action-specific: an existing item means the
  // submitted secret is a password update, not another new account.
  const actionValues = Object.values(actions);
  const promptTitle = labels.length === 1 && capture.data.login
    ? loginUpdate ? "更新密码？" : "保存新账号？"
    : labels.length === 1 && capture.data.identity
      ? actions.identity === "update" ? "更新个人资料？" : "保存个人资料？"
    : labels.length === 1 && capture.data.card
        ? actions.card === "update" ? "更新支付卡？" : "保存支付卡？"
      : labels.length === 1 && capture.data.secrets?.length
        ? "保存机密信息？"
      : labels.length === 1 && capture.data.sshCredentials?.length
        ? "保存 SSH 凭据？"
        : actionValues.every((action) => action === "update")
          ? "更新这些信息？"
          : actionValues.some((action) => action === "update") ? "保存并更新这些信息？" : "保存这些信息？";
  const expiresAt = Date.now() + SAVE_CAPTURE_DECISION_TIMEOUT_MS;
  const prompt: SaveCaptureQueuedResponse = { status: "queued", captureId: capture.captureId, hostname, labels, update: captureUpdate, expiresAt, actions };
  discardSaveCapture(capture.captureId);
  const timer = setTimeout(() => discardSaveCapture(capture.captureId), SAVE_CAPTURE_DECISION_TIMEOUT_MS);
  pendingCredentialCaptures.set(capture.captureId, { capture, tabId: page.tabId, fillOrigin: page.fillOrigin, expiresAt, timer, prompt });
  void setSaveCaptureBadge(page.tabId, true);
  if (options.notify !== false) {
    // Create the independent extension window before awaiting optional OS
    // notification APIs. Its lifecycle is not tied to the submitting tab.
    void ensureSaveCaptureWindow(capture.captureId);
    const permission = await browser.notifications.getPermissionLevel().catch(() => "denied" as const);
    if (permission === "granted") {
      await browser.notifications.create(`${CREDENTIAL_NOTIFICATION_PREFIX}${capture.captureId}`, {
        type: "basic",
        iconUrl: browser.runtime.getURL("/icon.svg"),
        title: promptTitle,
        message: "请在 10 秒内确认是否保存；未确认不会写入保险库。",
        buttons: [{ title: actionValues.every((action) => action === "update") ? "更新" : actionValues.some((action) => action === "update") ? "确认" : "保存" }, { title: "忽略" }],
        priority: 2,
      }).catch(() => undefined);
    }
  }
  return prompt;
}

function pendingSaveCaptureForPage(
  page: { tabId: number; fillOrigin: string },
  frameId: number | undefined,
): SaveCaptureQueuedResponse | { status: "preparing"; captureId: string } | { status: "none" } {
  const selected = pendingSavePromptForPage(pendingCredentialCaptures, page, frameId);
  for (const captureId of selected.expiredCaptureIds) discardSaveCapture(captureId);
  if (selected.prompt) return selected.prompt;
  const preparing = pendingSavePreparationForPage(preparingCredentialCaptures, page, frameId);
  for (const captureId of preparing.expiredCaptureIds) discardPreparingSaveCapture(captureId);
  return preparing.captureId ? { status: "preparing", captureId: preparing.captureId } : { status: "none" };
}

async function presentPendingSavePromptForTab(tabId: number): Promise<void> {
  const tab = await browser.tabs.get(tabId).catch(() => null);
  const fillOrigin = getHttpOrigin(tab?.url);
  if (!tab || !fillOrigin) return;
  const selected = pendingSavePromptForPage(pendingCredentialCaptures, { tabId, fillOrigin }, 0);
  for (const captureId of selected.expiredCaptureIds) discardSaveCapture(captureId);
  if (!selected.prompt) return;
  await presentBrowserSaveConfirmation(() => ensureSaveCaptureWindow(selected.prompt!.captureId));
}

async function ensureSaveCaptureWindow(captureId: string): Promise<void> {
  const pending = pendingCredentialCaptures.get(captureId);
  if (!pending || pending.expiresAt <= Date.now()) return;
  const submittingTab = await browser.tabs.get(pending.tabId).catch(() => null);
  const anchorWindow = submittingTab?.windowId != null
    ? await browser.windows.get(submittingTab.windowId).catch(() => null)
    : await browser.windows.getLastFocused().catch(() => null);
  const position = saveConfirmationWindowPosition(anchorWindow);
  const existingWindowId = saveCaptureWindows.get(captureId);
  if (existingWindowId != null) {
    const focused = await browser.windows.update(existingWindowId, { focused: true, ...position }).then(() => true).catch(() => false);
    if (focused) return;
    saveCaptureWindows.delete(captureId);
    saveCaptureIdsByWindow.delete(existingWindowId);
  }
  const opening = openingSaveCaptureWindows.get(captureId);
  if (opening) return opening;
  const creation = (async () => {
    const created = await browser.windows.create({
      url: browser.runtime.getURL("/save-confirmation.html"),
      type: "popup",
      focused: true,
      width: SAVE_CONFIRMATION_WINDOW_WIDTH,
      height: SAVE_CONFIRMATION_WINDOW_HEIGHT,
      ...position,
    });
    const createdId = created?.id;
    if (createdId == null) return;
    const current = pendingCredentialCaptures.get(captureId);
    if (!current || current.expiresAt <= Date.now()) {
      await browser.windows.remove(createdId).catch(() => undefined);
      return;
    }
    saveCaptureWindows.set(captureId, createdId);
    saveCaptureIdsByWindow.set(createdId, captureId);
  })().finally(() => openingSaveCaptureWindows.delete(captureId));
  openingSaveCaptureWindows.set(captureId, creation);
  return creation;
}

async function pendingSaveCaptureForActiveTab(): Promise<SaveCaptureQueuedResponse | { status: "none" }> {
  const [tab] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
  const fillOrigin = getHttpOrigin(tab?.url);
  if (tab?.id == null || !fillOrigin) return { status: "none" };
  const selected = pendingSavePromptForPage(pendingCredentialCaptures, { tabId: tab.id, fillOrigin }, 0);
  for (const captureId of selected.expiredCaptureIds) discardSaveCapture(captureId);
  return selected.prompt ?? { status: "none" };
}

async function setSaveCaptureBadge(tabId: number, visible: boolean): Promise<void> {
  await Promise.allSettled([
    extensionAction?.setBadgeBackgroundColor({ tabId, color: "#b42318" }),
    extensionAction?.setBadgeText({ tabId, text: visible ? "!" : "" }),
    extensionAction?.setTitle({ tabId, title: visible ? "VaultMesh：等待确认保存" : "VaultMesh" }),
  ]);
}

async function loginCandidatesForCapture(
  login: CapturedLogin,
  pageUrl: string,
  pageContext: import("@/lib/protocol").PageContext,
  fillOrigin: string,
): Promise<Array<{ id: string; subtitle: string }>> {
  // Resolve the explicitly filled source item first.  This needs only one
  // authoritative vault query and is the normal password-change path.
  const summaries = await backgroundDesktopRpc("items.list") as Array<{ id: string; username: string; url?: string | null }>;
  if (login.loginId) {
    const source = summaries.find((summary) => summary.id === login.loginId);
    if (source) return [{ id: source.id, subtitle: source.username }];
  }

  // A manually entered account has no source id, so ask the desktop's same
  // site matcher.  It includes primary and additional URLs and is the same
  // matcher used by autofill.  Run it after items.list instead of in parallel:
  // one transient request failure must never silently mean "new account".
  const autofillResult = await backgroundDesktopRpc("browser.autofill.candidates", {
    topOrigin: fillOrigin,
    pageUrl,
    fieldKind: "login",
    pageContext,
  }) as { candidates?: Array<{ id: string; subtitle: string }> };
  return autofillResult.candidates ?? [];
}

async function planIdentityCapture(identity: CapturedIdentity): Promise<{ identity: CapturedIdentity; changed: boolean }> {
  let existing: ExistingIdentity | null = null;
  if (identity.identityId) {
    existing = await backgroundDesktopRpc("identities.detail", { id: identity.identityId }) as ExistingIdentity;
  } else {
    const summaries = await backgroundDesktopRpc("identities.list") as Array<{ id: string }>;
    const matches: ExistingIdentity[] = [];
    for (const summary of summaries.slice(0, 100)) {
      const detail = await backgroundDesktopRpc("identities.detail", { id: summary.id }) as ExistingIdentity;
      if (identityMatchesCapture(detail, identity)) matches.push(detail);
    }
    existing = matches.length === 1 ? matches[0]! : null;
  }
  if (!existing) {
    const { identityId: _staleIdentityId, ...newIdentity } = identity;
    return { identity: newIdentity, changed: true };
  }
  const routed = { ...identity, identityId: existing.id };
  return { identity: routed, changed: identityUpdateChanges(existing, buildIdentityUpdate(existing, routed)) };
}

async function planCardCapture(card: CapturedCard): Promise<CapturedCard | null> {
  const result = await backgroundDesktopRpc("browser.card.capture-status", cardCaptureStatusInput(card)) as { status?: unknown; cardId?: unknown };
  if (result.status === "unchanged" && typeof result.cardId === "string") return null;
  if (result.status === "update" && typeof result.cardId === "string") return { ...card, cardId: result.cardId };
  if (result.status === "new") {
    const { cardId: _staleCardId, ...newCard } = card;
    return newCard;
  }
  throw new Error("Invalid card capture status response");
}

async function decideSaveCapture(
  decision: { captureId: string; decision: "save" | "ignore" },
  page: { tabId: number; fillOrigin: string },
) {
  const pending = pendingCredentialCaptures.get(decision.captureId);
  if (!pending || pending.expiresAt <= Date.now()) {
    discardSaveCapture(decision.captureId);
    return { status: "expired" as const };
  }
  if (pending.tabId !== page.tabId || pending.fillOrigin !== page.fillOrigin) return { status: "unsupported-page" as const };
  if (decision.decision === "ignore") {
    discardSaveCapture(decision.captureId);
    return { status: "discarded" as const };
  }
  return saveCapture(decision.captureId);
}

const savingCaptures = new Map<string, ReturnType<typeof performSaveCapture>>();

function saveCapture(captureId: string, options: { notify?: boolean } = {}) {
  return runCaptureSaveOnce(savingCaptures, captureId, () => performSaveCapture(captureId, options));
}

async function performSaveCapture(captureId: string, options: { notify?: boolean } = {}) {
  const pending = pendingCredentialCaptures.get(captureId);
  if (!pending || pending.expiresAt <= Date.now()) {
    discardSaveCapture(captureId);
    return { status: "expired" as const };
  }
  const { capture } = pending;
  let savingLabel = "识别到的信息";
  try {
    const saved: string[] = [];
    if (capture.data.login) { savingLabel = "登录信息"; await saveLoginCapture(capture.data.login, capture.pageUrl); saved.push(capture.data.login.loginId ? "登录信息（已更新）" : "登录信息"); }
    if (capture.data.identity) {
      savingLabel = capture.data.identity.identityId ? "个人资料/地址（更新）" : "个人资料/地址（新增）";
      saved.push(await saveIdentityCapture(capture.data.identity) ? "个人资料（已更新）" : "个人资料/地址");
    }
    if (capture.data.card) { savingLabel = "支付卡"; saved.push(await saveCardCapture(capture.data.card) ? "支付卡（已更新）" : "支付卡"); }
    if (capture.data.secrets?.length) {
      for (const secret of capture.data.secrets) { savingLabel = secret.title; await saveSecretCapture(secret); }
      saved.push(`${capture.data.secrets.length} 条机密信息`);
    }
    if (capture.data.sshCredentials?.length) {
      for (const ssh of capture.data.sshCredentials) { savingLabel = ssh.title; await saveSshCapture(ssh); }
      saved.push(`${capture.data.sshCredentials.length} 条 SSH 凭据`);
    }
    if (options.notify !== false) {
      await browser.notifications.create({ type: "basic", iconUrl: browser.runtime.getURL("/icon.svg"), title: "VaultMesh 已保存", message: `${saved.join("、")}已保存，下次可自动填入。` }).catch(() => undefined);
    }
    return { status: "saved" as const };
  } catch (error) {
    if (options.notify !== false) {
      await browser.notifications.create({ type: "basic", iconUrl: browser.runtime.getURL("/icon.svg"), title: "VaultMesh 保存失败", message: "请解锁插件后重试；待保存信息已从扩展内存清除。" }).catch(() => undefined);
    }
    return {
      status: "failed" as const,
      failedItem: savingLabel.slice(0, 64),
      errorCode: error instanceof DesktopRpcError ? error.code.slice(0, 64) : "unexpected-error",
      errorMessage: error instanceof DesktopRpcError ? error.message.slice(0, 256) : undefined,
    };
  } finally {
    discardSaveCapture(captureId);
  }
}

async function saveLoginCapture(login: CapturedLogin, pageUrl: string) {
  if (login.loginId) {
    const detail = await backgroundDesktopRpc("items.detail", { id: login.loginId }) as Record<string, unknown>;
    await backgroundDesktopRpc("items.update", {
      id: login.loginId, title: login.title ?? detail.title, username: login.username || detail.username || "", password: login.password,
      url: login.url ?? detail.url ?? pageUrl, notes: detail.notes ?? null, folder: detail.folder ?? null, favorite: detail.favorite ?? false,
      totpSecret: login.totpSecret ?? null, clearTotpSecret: false,
      additionalUrls: uniqueStrings([...(detail.additionalUrls as string[] ?? []), ...(login.additionalUrls ?? [])], 20),
      autofillOnPageLoad: detail.autofillOnPageLoad ?? true, masterPasswordReprompt: detail.masterPasswordReprompt ?? false,
      customFields: uniqueCustomFields([...(detail.customFields as Array<{ label: string; value: string }> ?? []), ...(login.customFields ?? [])]),
    });
    return;
  }
  const url = new URL(pageUrl);
  await backgroundDesktopRpc("items.add", {
    title: login.title ?? url.hostname, username: login.username, password: login.password, url: login.url ?? `${url.origin}${url.pathname}`,
    notes: null, folder: null, favorite: false, totpSecret: login.totpSecret ?? null, additionalUrls: login.additionalUrls ?? [], autofillOnPageLoad: true,
    masterPasswordReprompt: false, customFields: login.customFields ?? [],
  });
}

async function saveIdentityCapture(identity: CapturedIdentity): Promise<boolean> {
  const { identityId, ...captured } = identity;
  if (!identityId) {
    await backgroundDesktopRpc("identities.add", { ...captured, notes: null, folder: null, favorite: false });
    return false;
  }
  const existing = await backgroundDesktopRpc("identities.detail", { id: identityId }) as ExistingIdentity;
  await backgroundDesktopRpc("identities.update", buildIdentityUpdate(existing, identity));
  return true;
}

async function saveCardCapture(card: CapturedCard): Promise<boolean> {
  const { cardId, ...captured } = card;
  if (!cardId) {
    await backgroundDesktopRpc("cards.add", { ...captured, pin: captured.pin ?? null, issuer: captured.issuer ?? null, network: captured.network ?? null, notes: null, folder: null, favorite: false, masterPasswordReprompt: Boolean(captured.pin) });
    return false;
  }
  const detail = await backgroundDesktopRpc("cards.detail", { id: cardId }) as Record<string, unknown>;
  await backgroundDesktopRpc("cards.update", {
    ...detail, id: cardId, title: detail.title ?? captured.title, cardholderName: captured.cardholderName, cardNumber: captured.cardNumber,
    expirationMonth: captured.expirationMonth, expirationYear: captured.expirationYear, securityCode: captured.securityCode,
    clearSecurityCode: false, pin: captured.pin ?? null, clearPin: false,
    issuer: captured.issuer ?? detail.issuer ?? null, network: captured.network ?? detail.network ?? null,
    billingAddress: captured.billingAddress ?? detail.billingAddress ?? null,
    folder: detail.folder ?? null, favorite: detail.favorite ?? false, masterPasswordReprompt: detail.masterPasswordReprompt ?? false,
  });
  return true;
}

async function saveSecretCapture(secret: CapturedSecret): Promise<void> {
  await backgroundDesktopRpc("secrets.add", capturedSecretAddInput(secret));
}

async function saveSshCapture(ssh: CapturedSshCredential): Promise<void> {
  await backgroundDesktopRpc("ssh.add", {
    ...ssh,
    notes: null,
    folder: null,
    favorite: false,
    masterPasswordReprompt: true,
  });
}

function uniqueStrings(values: string[], maximum: number): string[] {
  return Array.from(new Set(values.filter(Boolean))).slice(0, maximum);
}

function uniqueCustomFields(values: Array<{ label: string; value: string }>): Array<{ label: string; value: string }> {
  const seen = new Set<string>();
  return values.filter((field) => {
    const key = `${field.label}\u0000${field.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 50);
}

function discardSaveCapture(captureId: string) {
  const pending = pendingCredentialCaptures.get(captureId);
  if (pending) clearTimeout(pending.timer);
  pendingCredentialCaptures.delete(captureId);
  const windowId = saveCaptureWindows.get(captureId);
  if (windowId != null) {
    saveCaptureWindows.delete(captureId);
    saveCaptureIdsByWindow.delete(windowId);
    void browser.windows.remove(windowId).catch(() => undefined);
  }
  if (pending && !Array.from(pendingCredentialCaptures.values()).some((entry) => entry.tabId === pending.tabId)) {
    void setSaveCaptureBadge(pending.tabId, false);
  }
  void browser.notifications.clear(`${CREDENTIAL_NOTIFICATION_PREFIX}${captureId}`).catch(() => undefined);
}

function discardPreparingSaveCapture(captureId: string) {
  const preparing = preparingCredentialCaptures.get(captureId);
  if (preparing) clearTimeout(preparing.timer);
  preparingCredentialCaptures.delete(captureId);
}

function saveCaptureIdForWindow(sender: Browser.runtime.MessageSender): string | null {
  if (sender.id !== browser.runtime.id || sender.url !== browser.runtime.getURL("/save-confirmation.html")) return null;
  const windowId = sender.tab?.windowId;
  return windowId == null ? null : saveCaptureIdsByWindow.get(windowId) ?? null;
}
