import {
  ApprovedFillSchema,
  AutofillCandidateSchema,
  DiscoveryFrameResponseSchema,
  EmailOtpCandidateSchema,
  MAX_FIELDS_PER_REQUEST,
  type ContentMessage,
  type DiscoveryFrame,
  type FillRequest,
  type AutofillTarget,
} from "@/lib/protocol";
import { backgroundDesktopRpc, DesktopRpcError } from "@/lib/desktop-rpc";
import { rememberedLoginSelection, rememberLoginSelection } from "@/lib/autofill-preferences";
import {
  chooseAutomaticLogin,
  fieldsForLoginSelection,
  rankLoginCandidates,
  shouldReplaceExistingFields,
  shouldWaitForLoginPair,
} from "@/lib/autofill-selection";
import { sameOriginFrameIds } from "@/lib/frame-origin";

const LOGIN_DISCOVERY_TIMEOUT_MS = 3_000;
const LOGIN_DISCOVERY_POLL_MS = 100;
export const currentLoginAccounts = new Map<string, { username: string; expiresAt: number }>();
export function accountStageKey(tabId: number, origin: string) { return `${tabId}:${origin}`; }

export async function startFillForActiveTab(selectedItem?: FillRequest["selectedItem"], masterPassword?: string) {
  if (!selectedItem) return { status: "selection-required" as const };
  const [tab] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
  if (tab?.id == null) {
    return { status: "unsupported-page" as const };
  }

  const result = await startFillForTab(tab.id, selectedItem, selectedItem ? { mode: "selection", masterPassword } : {});
  if (result.status === "filled" && selectedItem?.kind === "login" && result.topOrigin) {
    await rememberLoginSelection(result.topOrigin, selectedItem.id).catch(() => undefined);
  }
  return result;
}

export async function getAutofillAvailability() {
  try {
    const status = await backgroundDesktopRpc("vault.status");
    return { status: status && typeof status === "object" && (status as { unlocked?: unknown }).unlocked === true ? "ready" as const : "locked" as const };
  } catch (error) {
    return { status: error instanceof DesktopRpcError && error.code === "unlock-required" ? "locked" as const : "unavailable" as const };
  }
}

type StartFillOptions = {
  mode?: "automatic" | "selection";
  targetOrigin?: string;
  targetPageUrl?: string;
  skipLoginPairWait?: boolean;
  preserveExistingAccount?: boolean;
  masterPassword?: string;
  target?: AutofillTarget;
  targetFrameId?: number;
};

export async function startFillForTab(tabId: number, selectedItem?: FillRequest["selectedItem"], options: StartFillOptions = {}) {
  const mode = options.mode ?? "selection";
  const tab = await browser.tabs.get(tabId);
  const topOrigin = getHttpOrigin(tab.url);
  if (!topOrigin) {
    return { status: "unsupported-page" as const };
  }
  const targetOrigin = options.targetOrigin ?? topOrigin;
  const targetPageUrl = options.targetPageUrl ?? getHttpPageUrl(tab.url) ?? targetOrigin;
  if (getHttpOrigin(targetPageUrl) !== targetOrigin) return { status: "unsupported-page" as const };

  const requestId = crypto.randomUUID();
  const sameOriginFrames = await getSameOriginFrameIds(tabId, targetOrigin);
  const frames = options.targetFrameId == null ? sameOriginFrames : sameOriginFrames.filter((id) => id === options.targetFrameId);
  if (options.target && options.targetFrameId == null) return { status: "document-changed" as const };
  const waitForLoginForm = shouldWaitForLoginPair(mode, selectedItem?.kind, options.skipLoginPairWait);
  const discoveries = await Promise.all(
    frames.map(async (frameId) => discoverFrame(tabId, frameId, requestId, waitForLoginForm, options.target)),
  );
  const discoveredFrames = discoveries.filter(
    (frame): frame is DiscoveryFrame => frame != null && frame.fields.length > 0,
  );
  let remainingFields = MAX_FIELDS_PER_REQUEST;
  const validFrames = discoveredFrames.flatMap((frame) => {
    if (remainingFields <= 0) return [];
    const fields = fieldsForLoginSelection(
      frame.fields,
      selectedItem?.kind === "login" && options.preserveExistingAccount === true,
      selectedItem?.kind === "login" && mode === "automatic",
    ).slice(0, remainingFields);
    remainingFields -= fields.length;
    return fields.length > 0 ? [{ ...frame, fields }] : [];
  });

  if (validFrames.length === 0) {
    return { status: "no-supported-fields" as const };
  }

  const request: FillRequest = {
    version: 1,
    requestId,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    tabId,
    topOrigin,
    targetOrigin,
    targetPageUrl,
    ...(selectedItem ? { selectedItem } : {}),
    frames: validFrames,
  };
  const fieldCount = validFrames.reduce((count, frame) => count + frame.fields.length, 0);
  try {
    const approval = ApprovedFillSchema.parse(await backgroundDesktopRpc("browser.autofill.execute", {
      discovery: request,
      mode,
      ...(options.masterPassword ? { masterPassword: options.masterPassword } : {}),
    }));
    const filledItem = approval.selectedItem ?? selectedItem;
    const applied = await applyApprovedFill(
      approval,
      tabId,
      topOrigin,
      filledItem,
      shouldReplaceExistingFields(mode, filledItem?.kind, options.preserveExistingAccount),
    );
    const assignmentCount = approval.frames.reduce((count, frame) => count + frame.assignments.length, 0);
    if (applied.status === "filled" && filledItem && applied.filledCount > 0) {
      await backgroundDesktopRpc("browser.fill.record", {
        itemKind: filledItem.kind,
        itemId: filledItem.id,
        itemTitle: filledItem.title,
        origin: targetOrigin,
        fieldCount: applied.filledCount,
      }).catch(() => undefined);
    }
    return { status: applied.status, fieldCount, assignmentCount, topOrigin, selectedItem };
  } catch (error) {
    if (error instanceof DesktopRpcError) {
      return { status: error.code, errorMessage: error.message, fieldCount, assignmentCount: 0, topOrigin, selectedItem };
    }
    return { status: "desktop-unavailable" as const, fieldCount, assignmentCount: 0, topOrigin, selectedItem };
  }
}

export async function fillEmailOtpForActiveTab(candidateId: string) {
  const [tab] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
  if (tab?.id == null) return { status: "unsupported-page" as const };
  const topOrigin = getHttpOrigin(tab.url);
  const targetPageUrl = getHttpPageUrl(tab.url);
  if (!topOrigin || !targetPageUrl) return { status: "unsupported-page" as const };

  return fillEmailOtpForTab(tab.id, topOrigin, targetPageUrl, candidateId);
}

export async function fillEmailOtpForTab(tabId: number, topOrigin: string, targetPageUrl: string, candidateId: string, target?: AutofillTarget, targetFrameId?: number) {
  const tab = await browser.tabs.get(tabId);
  if (getHttpOrigin(tab.url) !== topOrigin || getHttpOrigin(targetPageUrl) !== topOrigin) {
    return { status: "unsupported-page" as const };
  }

  const requestId = crypto.randomUUID();
  const sameOriginFrames = await getSameOriginFrameIds(tabId, topOrigin);
  const frames = targetFrameId == null ? sameOriginFrames : sameOriginFrames.filter((id) => id === targetFrameId);
  if (target && targetFrameId == null) return { status: "document-changed" as const };
  const discoveries = await Promise.all(frames.map((frameId) => discoverFrame(tabId, frameId, requestId, false, target)));
  let remainingFields = MAX_FIELDS_PER_REQUEST;
  const validFrames = discoveries.flatMap((frame) => {
    if (!frame || remainingFields <= 0) return [];
    const fields = frame.fields.filter(isEmptyEmailOtpField).slice(0, remainingFields);
    remainingFields -= fields.length;
    return fields.length ? [{ ...frame, fields }] : [];
  });
  if (!validFrames.length) return { status: "no-supported-fields" as const };

  const discovery: FillRequest = {
    version: 1,
    requestId,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    tabId,
    topOrigin,
    targetOrigin: topOrigin,
    targetPageUrl,
    frames: validFrames,
  };
  try {
    const approval = ApprovedFillSchema.parse(await backgroundDesktopRpc("email.otp.fill", { candidateId, discovery }));
    const applied = await applyApprovedFill(approval, tabId, topOrigin);
    return {
      status: applied.status,
      fieldCount: validFrames.reduce((count, frame) => count + frame.fields.length, 0),
      assignmentCount: approval.frames.reduce((count, frame) => count + frame.assignments.length, 0),
      topOrigin,
    };
  } catch (error) {
    return {
      status: error instanceof DesktopRpcError ? error.code : "desktop-unavailable",
      errorMessage: error instanceof Error ? error.message : "邮箱验证码填充失败。",
      fieldCount: validFrames.reduce((count, frame) => count + frame.fields.length, 0),
      assignmentCount: 0,
      topOrigin,
    };
  }
}

export async function getEmailOtpCandidates(topOrigin: string) {
  try {
    const result = await backgroundDesktopRpc("email.otp.candidates", { topOrigin });
    const parsed = EmailOtpCandidateSchema.array().max(20).safeParse((result as { candidates?: unknown })?.candidates);
    return parsed.success
      ? { status: "ready" as const, candidates: parsed.data }
      : { status: "unavailable" as const, candidates: [] };
  } catch (error) {
    return {
      status: error instanceof DesktopRpcError && error.code === "unlock-required" ? "locked" as const : "unavailable" as const,
      candidates: [],
    };
  }
}

function isEmptyEmailOtpField(field: import("@/lib/protocol").FieldDescriptor): boolean {
  if (!field.isEmpty || field.control !== "input") return false;
  const inputType = field.inputType?.toLocaleLowerCase() ?? "";
  if (!["", "text", "tel", "number"].includes(inputType)) return false;
  const metadata = [field.label, field.name, field.id, field.placeholder, ...field.autocomplete].join(" ");
  return field.context === "otp"
    || field.autocomplete.includes("one-time-code")
    || /otp|2fa|mfa|one[-_\s]*time|verification.?code|security.?code|验证码|校验码|动态码/i.test(metadata);
}

export async function startAutomaticFillForTab(tabId: number, topOrigin: string, pageContext: "login" | "otp" = "login", detectedPageUrl?: string, target?: AutofillTarget, targetFrameId?: number) {
  const tab = await browser.tabs.get(tabId);
  const pageUrl = detectedPageUrl ?? getHttpPageUrl(tab.url) ?? topOrigin;
  const response = await getAutofillCandidates(topOrigin, "login", pageUrl, pageContext);
  if (response.status !== "ready") return response;
  const rememberedId = await rememberedLoginSelection(topOrigin);
  const accountKey = accountStageKey(tabId, topOrigin);
  const currentAccount = currentLoginAccounts.get(accountKey);
  if (currentAccount && currentAccount.expiresAt <= Date.now()) currentLoginAccounts.delete(accountKey);
  const currentUsername = currentAccount && currentAccount.expiresAt > Date.now() ? currentAccount.username : null;
  const choice = chooseAutomaticLogin(response.candidates, rememberedId, currentUsername);
  if (!choice) return { status: "selection-required" as const, candidates: response.candidates };
  const candidate = choice.candidate;
  const result = await startFillForTab(tabId, { kind: "login", id: candidate.id, title: candidate.title }, {
    mode: choice.mode, targetOrigin: topOrigin, targetPageUrl: pageUrl, skipLoginPairWait: pageContext === "otp", target, targetFrameId,
  });
  if (result.status === "filled") {
    await rememberLoginSelection(topOrigin, candidate.id).catch(() => undefined);
    if (pageContext === "otp") currentLoginAccounts.delete(accountKey);
  }
  return result;
}

export async function getAutofillCandidates(topOrigin: string, fieldKind: "login" | "card" | "identity" | "secret" | "ssh", pageUrl = topOrigin, pageContext: import("@/lib/protocol").PageContext = "unknown") {
  try {
    const result = await backgroundDesktopRpc("browser.autofill.candidates", { topOrigin, pageUrl, fieldKind, pageContext });
    const parsed = AutofillCandidateSchema.array().max(200).safeParse((result as { candidates?: unknown })?.candidates);
    return parsed.success
      ? { status: "ready" as const, candidates: fieldKind === "login" ? rankLoginCandidates(parsed.data) : parsed.data }
      : { status: "unavailable" as const, candidates: [] };
  } catch (error) {
    return {
      status: error instanceof DesktopRpcError && error.code === "unlock-required" ? "locked" as const : "unavailable" as const,
      candidates: [],
    };
  }
}

export function isTrustedExtensionPage(sender: Browser.runtime.MessageSender): boolean {
  const extensionRoot = browser.runtime.getURL("");
  return sender.id === browser.runtime.id && sender.tab == null && sender.url?.startsWith(extensionRoot) === true;
}

async function applyApprovedFill(approval: import("@/lib/protocol").ApprovedFill, tabId: number, topOrigin: string, selectedItem?: FillRequest["selectedItem"], clearBeforeFill = false) {
  if (approval.tabId !== tabId || approval.topOrigin !== topOrigin || Date.parse(approval.expiresAt) <= Date.now()) {
    return { status: "approval-rejected" as const, filledCount: 0 };
  }
  const tab = await browser.tabs.get(tabId);
  if (getHttpOrigin(tab.url) !== topOrigin) return { status: "document-changed" as const, filledCount: 0 };
  const results = await Promise.all(approval.frames.map(async (frame) => {
    try {
      return await browser.tabs.sendMessage(tabId, {
        kind: "vaultmesh.apply-assignments",
        requestId: approval.requestId,
        documentId: frame.documentId,
        frameOrigin: frame.frameOrigin,
        expiresAt: approval.expiresAt,
        ...(selectedItem ? { selectedItem } : {}),
        ...(clearBeforeFill ? { clearBeforeFill: true } : {}),
        assignments: frame.assignments,
      }, { frameId: frame.frameId });
    } catch { return null; }
  }));
  const filledCount = results.reduce((count, result) => count + (result && typeof result === "object" && "results" in result && Array.isArray(result.results)
    ? result.results.filter((entry: unknown) => Boolean(entry && typeof entry === "object" && (entry as { status?: unknown }).status === "filled")).length
    : 0), 0);
  return filledCount > 0
    ? { status: "filled" as const, filledCount }
    : { status: "document-changed" as const, filledCount: 0 };
}

async function getSameOriginFrameIds(tabId: number, topOrigin: string) {
  const frames = (await browser.webNavigation.getAllFrames({ tabId })) ?? [];
  return sameOriginFrameIds(frames, topOrigin);
}

async function discoverFrame(tabId: number, frameId: number, requestId: string, waitForLoginForm = false, target?: AutofillTarget) {
  const deadline = Date.now() + (waitForLoginForm ? LOGIN_DISCOVERY_TIMEOUT_MS : 0);
  let latest: DiscoveryFrame | null = null;

  do {
    try {
      const response = await browser.tabs.sendMessage(
        tabId,
        { kind: "vaultmesh.discover-fields", requestId, ...(target ? { target } : {}) } satisfies Extract<
          ContentMessage,
          { kind: "vaultmesh.discover-fields" }
        >,
        { frameId },
      );
      const parsed = DiscoveryFrameResponseSchema.safeParse(response);
      latest = parsed.success && (!target || parsed.data.documentId === target.documentId) ? { ...parsed.data, frameId } : null;
      if (!waitForLoginForm || latest && hasVisibleLoginPair(latest.fields)) return latest;
    } catch {
      latest = null;
      if (!waitForLoginForm) return null;
    }

    if (Date.now() < deadline) await delay(LOGIN_DISCOVERY_POLL_MS);
  } while (Date.now() < deadline);

  return latest;
}

function hasVisibleLoginPair(fields: import("@/lib/protocol").FieldDescriptor[]) {
  const hasPassword = fields.some((field) =>
    field.inputType === "password" || field.autocomplete.includes("current-password"),
  );
  const hasAccount = fields.some((field) => {
    if (field.inputType === "password") return false;
    const metadata = [field.label, field.name, field.id, field.placeholder].join(" ");
    return field.autocomplete.includes("username") ||
      field.autocomplete.includes("email") ||
      field.inputType === "email" ||
      field.inputType === "tel" ||
      /user(name)?|login|account|e-?mail|phone|mobile|用户名|账号|邮箱|电话|手机/i.test(metadata);
  });
  return hasAccount && hasPassword;
}

function delay(milliseconds: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

export function getHttpOrigin(url: string | undefined) {
  if (!url) {
    return null;
  }

  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.origin : null;
  } catch {
    return null;
  }
}

function getHttpPageUrl(url: string | undefined) {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? `${parsed.origin}${parsed.pathname}` : null;
  } catch {
    return null;
  }
}

export function trustedPage(sender: Browser.runtime.MessageSender) {
  if (sender.id !== browser.runtime.id || sender.tab?.id == null) return null;
  const senderOrigin = getHttpOrigin(sender.origin) ?? getHttpOrigin(sender.url);
  const topOrigin = getHttpOrigin(sender.tab.url);
  const pageUrl = getHttpPageUrl(sender.tab.url);
  const framePageUrl = getHttpPageUrl(sender.url) ?? senderOrigin;
  return senderOrigin && topOrigin && pageUrl && framePageUrl ? { tabId: sender.tab.id, frameId: sender.frameId ?? 0, topOrigin, fillOrigin: senderOrigin, pageUrl, framePageUrl } : null;
}
