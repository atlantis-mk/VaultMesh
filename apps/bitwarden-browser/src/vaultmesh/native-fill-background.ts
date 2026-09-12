import { z } from "zod";
import { UriMatchStrategy } from "@bitwarden/common/models/domain/domain-service";
import { FieldView } from "@bitwarden/common/vault/models/view/field.view";
import { FieldType } from "@bitwarden/common/vault/enums";
import { planNativeItem, credentialCustomSources, type NativeItemKind } from "./native-item-planner";
import { NativeItemPlanSchema } from "./vendor/browser-native-item-plan";
import type { AutofillService } from "../autofill/services/abstractions/autofill.service";
import { loginSummaryView } from "./login-view";
import { AutofillPreferences, automaticCandidate } from "./autofill-preferences";
import type { FillFrame } from "./contracts";
import { createVaultMeshUuid } from "./uuid";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { EMAIL_SELECT, clearEmail } from "./email-otp";
import { EmailAssignmentSchema } from "./native-fill-contracts";
import { VaultMeshRpcClient, VaultMeshRpcError } from "./rpc";
import { AssignmentSchema, CollectedPageSchema, FILL_APPLY, FILL_CANCEL, FILL_CHECK, FILL_COLLECT,
  FILL_LIFETIME, FILL_CANDIDATES, FILL_SELECT, FILL_AUTOMATIC, NativeLoginPlanSchema, clearAssignment, nativePage, type Assignment, type CollectedPage, type NativeCandidate } from "./native-fill-contracts";

type PageTarget = { tabId: number; topUrl: string; frameId: number; url: string; targetRef: string; expires: number; candidates: NativeCandidate[]; emailIds?: string[] };
const PageRequestSchema = z.object({
  kind: z.enum([FILL_CANDIDATES, FILL_SELECT, FILL_AUTOMATIC, EMAIL_SELECT]), targetRef: z.string().uuid(),
  context: z.enum(["login", "otp", "card", "identity", "ssh", "secret"]), id: z.string().uuid().optional(),
}).strict();

const fail = (code = "operation-expired"): never => { throw new VaultMeshRpcError(code, "填充未完成。"); };
function tabMessage(tabId: number, message: unknown, frameId = 0): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new VaultMeshRpcError("execution-unknown", "页面响应未确认。")), FILL_LIFETIME);
    chrome.tabs.sendMessage(tabId, message, { frameId }, (result) => {
      clearTimeout(timer);
      if (chrome.runtime.lastError) reject(new VaultMeshRpcError("page-unavailable", "请刷新网页后重试。"));
      else resolve(result);
    });
  });
}
async function activeTab(): Promise<chrome.tabs.Tab> {
  return new Promise((resolve, reject) => chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (chrome.runtime.lastError || tabs.length !== 1 || tabs[0].id == null || !tabs[0].url) {
      reject(new VaultMeshRpcError("page-unavailable", "当前页面不可用。"));
    } else resolve(tabs[0]);
  }));
}

/** Per-frame Login plans. No account, CipherService or protected detail read. */
export class VaultMeshNativeFillBackground {
  private readonly preferences = new AutofillPreferences();
  private active?: { tabId: number; topUrl: string; frameId: number; url: string; requestId: string; expires: number; current: () => Promise<boolean>; clear?: () => void };
  private running = false;
  private generation = 0;
  private readonly menus = new Map<string, PageTarget>();
  private pendingSelection?: PageTarget & { id: string; kind: "login" | NativeItemKind };
  private menuTimer?: ReturnType<typeof setTimeout>;
  private watchMenus(): void {
    if (this.menuTimer) return;
    this.menuTimer = setTimeout(() => {
      this.menuTimer = undefined;
      if (!this.menus.size) return;
      void this.pageCurrent().then((authorized) => {
        if (!authorized || [...this.menus.values()].some((target) => target.expires <= Date.now())) this.cancel();
        else if (this.menus.size) this.watchMenus();
      }, () => this.cancel());
    }, 3000);
  }
  constructor(private readonly client: VaultMeshRpcClient, private readonly planner: () => Pick<AutofillService, "generateFillScript">,
    private readonly pageCurrent: () => Promise<boolean> = async () => false) {}

  start(): void {
    chrome.runtime.onMessage.addListener((message, sender, respond) => {
      if ([FILL_CANDIDATES, FILL_SELECT, FILL_AUTOMATIC, EMAIL_SELECT].includes(message?.kind)) {
        void this.handlePage(message, sender).then((value) => {
          try { respond(value); } finally { if (value && typeof value === "object" && "emailOtpCandidates" in value) clearEmail({ candidates: value.emailOtpCandidates }); }
        }, () => respond(null));
        return true;
      }
      if (message?.kind !== FILL_CHECK) return false;
      const active = this.active;
      if (!active || sender.id !== chrome.runtime.id || sender.tab?.id !== active.tabId || sender.frameId !== active.frameId
        || sender.url !== active.url || message.requestId !== active.requestId) { respond(false); return false; }
      void this.isCurrent(active).then(respond, () => respond(false));
      return true;
    });
    const onNavigation = (details: { tabId: number; frameId: number }) => {
      if (details.tabId === this.active?.tabId && (details.frameId === 0 || details.frameId === this.active.frameId)) this.cancel();
    };
    chrome.webNavigation.onCommitted.addListener(onNavigation);
    chrome.webNavigation.onHistoryStateUpdated.addListener(onNavigation);
    chrome.webNavigation.onReferenceFragmentUpdated.addListener(onNavigation);
    chrome.tabs.onRemoved.addListener((tabId) => { if (tabId === this.active?.tabId) this.cancel(); });
  }

  cancel(): void {
    this.generation++;
    if (this.menuTimer) clearTimeout(this.menuTimer); this.menuTimer = undefined;
    const menus = [...this.menus.values()];
    this.menus.clear();
    this.pendingSelection = undefined;
    const active = this.active;
    this.active = undefined;
    active?.clear?.();
    if (active) void tabMessage(active.tabId, { kind: FILL_CANCEL }, active.frameId).catch((): undefined => undefined);
    for (const menu of menus) void tabMessage(menu.tabId, { kind: FILL_CANCEL }, menu.frameId).catch((): undefined => undefined);
  }

  private async isCurrent(active: NonNullable<typeof this.active>): Promise<boolean> {
    if (this.active !== active || active.expires <= Date.now()) return false;
    const tab = await activeTab();
    const frame = active.frameId === 0 ? { url: tab.url } : await new Promise<chrome.webNavigation.GetFrameResultDetails | null>((resolve) => {
      chrome.webNavigation.getFrame({ tabId: active.tabId, frameId: active.frameId }, (value) => {
        resolve(chrome.runtime.lastError ? null : value);
      });
    });
    return tab.id === active.tabId && tab.url === active.topUrl && frame?.url === active.url && await active.current()
      && this.active === active && active.expires > Date.now();
  }

  async contexts(): Promise<FillFrame[]> {
    const tab = await activeTab();
    return new Promise((resolve, reject) => {
      chrome.webNavigation.getAllFrames({ tabId: tab.id! }, (frames) => {
        if (chrome.runtime.lastError || !frames) { reject(new VaultMeshRpcError("page-unavailable", "页面不可用。")); return; }
        resolve(frames.filter((frame) => /^https?:\/\//.test(frame.url)).slice(0, 16).map(({ frameId, url }) => ({ frameId, url })));
      });
    });
  }

  async insertGenerated(generated: { mode: string; value: string }, target: FillFrame, current: () => Promise<boolean>) {
    if (this.running) fail("operation-busy");
    this.running = true;
    let active: NonNullable<typeof this.active> | undefined;
    try {
      const tab = await activeTab();
      // A generator result is not a Vault assignment, but uses the same live authorization check.
      active = { tabId: tab.id!, topUrl: tab.url!, frameId: target.frameId, url: target.url,
        requestId: createVaultMeshUuid(), expires: Date.now() + FILL_LIFETIME, current };
      this.active = active;
      if (!await this.isCurrent(active)) fail();
      const message = { kind: "vaultmesh.native-fill.generated", requestId: active.requestId, url: target.url,
        expiresAt: new Date(active.expires).toISOString(), generated: { ...generated } };
      try { return z.object({ filled: z.number().int().min(0).max(3) }).strict().parse(await tabMessage(active.tabId, message, active.frameId)); }
      finally { message.generated.value = ""; }
    } finally { if (this.active === active) this.active = undefined; this.running = false; generated.value = "";
      if (active) void tabMessage(active.tabId, { kind: FILL_CANCEL }, active.frameId).catch((): undefined => undefined); }
  }

  async emailCandidates(current: () => Promise<boolean>) {
    const tab = await activeTab(); const url = new URL(tab.url!);
    if (!/^https?:$/.test(url.protocol) || !await current()) fail();
    const result = await this.client.emailCandidates(url.origin);
    try {
      const latest = await activeTab();
      if (latest.id !== tab.id || latest.url !== tab.url || !await current()) fail();
      return { tabId: tab.id!, url: tab.url!, candidates: result.candidates.map((row) => ({ ...row })) };
    } finally { clearEmail(result); }
  }

  async fillEmail(id: string, current: () => Promise<boolean>, expected: { tabId: number; url: string }, target?: PageTarget): Promise<{ filled: number }> {
    if (this.running) fail("operation-busy");
    this.running = true; const generation = this.generation; let filled = 0;
    try {
      const tab = await activeTab(); if (tab.id !== expected.tabId || tab.url !== expected.url || !await current()) fail();
      const origin = new URL(tab.url!).origin;
      const response = await this.client.emailCandidates(origin);
      let length = 0;
      try { const candidate = response.candidates.find((row) => row.id === id && row.expiresAt * 1000 > Date.now()); if (!candidate) fail(); length = candidate.code.length; }
      finally { clearEmail(response); }
      const targets = target ? [{ frameId: target.frameId, url: target.url }] : await this.contexts();
      for (const frame of targets) {
        if (new URL(frame.url).origin !== origin) continue;
        if (generation !== this.generation || !await current()) fail();
        const active: NonNullable<typeof this.active> = { tabId: tab.id!, topUrl: tab.url!, frameId: frame.frameId,
          url: frame.url, requestId: createVaultMeshUuid(), expires: Date.now() + FILL_LIFETIME, current };
        this.active = active; let assignment: z.infer<typeof EmailAssignmentSchema> | undefined;
        try {
          if (!await this.isCurrent(active)) fail();
          const page = CollectedPageSchema.parse(await tabMessage(active.tabId, { kind: FILL_COLLECT, requestId: active.requestId, topOrigin: origin,
            ...(target ? { targetRef: target.targetRef } : {}) }, active.frameId));
          if (page.url !== active.url || page.requestId !== active.requestId || Date.parse(page.expiresAt) > Date.now() + FILL_LIFETIME) fail();
          active.expires = Math.min(active.expires, Date.parse(page.expiresAt));
          const cipher = new CipherView(); cipher.login.totp = "remote-email-marker";
          const script = await this.planner().generateFillScript(nativePage(page), { cipher, tabUrl: page.url, defaultUriMatch: UriMatchStrategy.Domain,
            onlyEmptyFields: true, skipUsernameOnlyFill: false, fillNewPassword: false, autoSubmitLogin: false, allowTotpAutofill: true, canAccessTotp: true, remoteTotpPlanning: true, remoteTotpLength: length as 4 | 5 | 6 | 7 | 8 });
          const opids = new Set((script?.script ?? []).filter(([action]) => action === "fill_by_opid").map(([, opid]) => opid));
          const fields = page.fields.filter((field) => opids.has(field.opid) && field.context === "otp" && field.empty && ["text", "tel", "number"].includes(field.type));
          if (!fields.length || !script || script.untrustedIframe) continue;
          if (!await this.isCurrent(active)) fail();
          const request = discovery({ ...page, fields }, active.tabId, { id, title: "" }, active.frameId, origin);
          const { selectedItem: _notVaultItem, ...emailDiscovery } = request;
          assignment = await this.client.emailFill({ candidateId: id, discovery: emailDiscovery }); active.clear = () => clearAssignment(assignment);
          if (!await this.isCurrent(active)) fail();
          const approved = assignment.frames[0];
          if (assignment.requestId !== page.requestId || assignment.tabId !== tab.id || assignment.topOrigin !== origin || assignment.expiresAt !== page.expiresAt
            || approved.documentId !== page.documentId || approved.frameId !== frame.frameId || approved.frameOrigin !== origin
            || new Set(approved.assignments.map((item) => item.handle)).size !== approved.assignments.length
            || approved.assignments.some((item) => item.overwrite || !fields.some((field) => field.handle === item.handle))) fail("invalid-broker-response");
          const allowed = new Set(fields.filter((field) => approved.assignments.some((item) => item.handle === field.handle)).map((field) => field.opid));
          const planned = script.script.filter(([, opid]) => allowed.has(opid)).map(([action, opid]) => [action, opid, action === "fill_by_opid" ? "email-otp" : null]);
          const result = z.object({ filled: z.number().int().min(0).max(approved.assignments.length) }).strict().parse(await tabMessage(active.tabId, { kind: FILL_APPLY, assignment, script: planned, emailOtp: true }, active.frameId));
          filled += result.filled;
        } catch (error) { if (!(error instanceof VaultMeshRpcError) || error.code !== "page-unavailable") throw error; }
        finally { clearAssignment(assignment); if (this.active === active) this.active = undefined; void tabMessage(active.tabId, { kind: FILL_CANCEL }, active.frameId).catch((): undefined => undefined); }
      }
      return { filled }; // Email code never enters the fill audit or preferences.
    } finally { this.running = false; }
  }

  async fill(id: string, masterPassword: string | undefined, current: () => Promise<boolean>, selectedFrame?: FillFrame, kind: "login" | NativeItemKind = "login"): Promise<{ filled: number; auditRecorded: boolean }> {
    if (this.running) fail("operation-busy");
    if (this.pendingSelection) {
      const target = this.pendingSelection;
      this.pendingSelection = undefined;
      if (kind !== target.kind || target.id !== id || target.expires <= Date.now()
        || selectedFrame && (kind === "login" || selectedFrame.frameId !== target.frameId || selectedFrame.url !== target.url)) fail();
      return this.fillTarget(id, masterPassword, current, target, false, kind);
    }
    this.running = true;
    const generation = this.generation;
    let filled = 0;
    let completed = false;
    let auditRecorded = true;
    try {
      const tab = await activeTab();
      const frames = await new Promise<chrome.webNavigation.GetAllFrameResultDetails[]>((resolve, reject) => {
        chrome.webNavigation.getAllFrames({ tabId: tab.id! }, (frames) => {
          if (chrome.runtime.lastError || !frames) reject(new VaultMeshRpcError("page-unavailable", "页面 frame 不可用。"));
          else resolve(frames);
        });
      });
      const origin = new URL(tab.url!).origin;
      const targets = frames.filter((frame) => {
        try { return /^https?:$/.test(new URL(frame.url).protocol) && (selectedFrame
          ? selectedFrame.frameId === frame.frameId && selectedFrame.url === frame.url : new URL(frame.url).origin === origin); }
        catch { return false; }
      }).sort((a, b) => a.frameId - b.frameId).slice(0, 16);
      for (const frame of targets) {
        if (generation !== this.generation || !await current()) fail();
        try {
          const result = kind === "login" ? await this.fillFrame(id, masterPassword, current, tab, frame)
            : await this.fillItemFrame(kind, id, masterPassword, current, tab, frame);
          completed = true;
          filled += result.filled;
          if (result.filled) auditRecorded &&= result.auditRecorded;
        } catch (error) {
          if (!(error instanceof VaultMeshRpcError) || !["no-fillable-fields", "page-unavailable"].includes(error.code)) throw error;
        }
      }
      if (!completed) fail("no-fillable-fields");
      return { filled, auditRecorded: filled > 0 && auditRecorded };
    } finally { masterPassword = undefined; this.running = false; }
  }

  private async fillItemFrame(kind: NativeItemKind, id: string, masterPassword: string | undefined, current: () => Promise<boolean>, tab: chrome.tabs.Tab, target: FillFrame, targetRef?: string) {
    const url = new URL(target.url);
    if (kind !== "identity" && url.protocol !== "https:") fail("insecure-page");
    if (kind === "card" && !masterPassword) fail("re-prompt-required");
    const active: NonNullable<typeof this.active> = { tabId: tab.id!, topUrl: tab.url!, frameId: target.frameId,
      url: target.url, requestId: createVaultMeshUuid(), expires: Date.now() + FILL_LIFETIME, current };
    this.active = active;
    let assignment: Assignment | undefined;
    try {
      if (!await this.isCurrent(active)) fail();
      const rows = await this.client.managedItem({ verb: "list", kind }, () => this.active === active && active.expires > Date.now());
      const item = Array.isArray(rows) ? rows.find((row) => row.id === id) : undefined;
      if (!item) fail("invalid-request");
      if (item.masterPasswordReprompt && !masterPassword) fail("re-prompt-required");
      const page = CollectedPageSchema.parse(await tabMessage(active.tabId, { kind: FILL_COLLECT, requestId: active.requestId, topOrigin: new URL(active.topUrl).origin, ...(targetRef ? { targetRef } : {}) }, active.frameId));
      if (page.url !== active.url || page.requestId !== active.requestId || Date.parse(page.expiresAt) > Date.now() + FILL_LIFETIME) fail();
      active.expires = Math.min(active.expires, Date.parse(page.expiresAt));
      const sources = await planNativeItem(nativePage(page), kind);
      const fields = page.fields.filter((field) => field.empty && sources.has(field.opid));
      if (!fields.length) fail("no-fillable-fields");
      const plan = NativeItemPlanSchema.parse(fields.map((field) => ({ handle: field.handle, source: sources.get(field.opid) })));
      if (!await this.isCurrent(active)) fail();
      const request = discovery({ ...page, fields }, active.tabId, { id, title: item!.title }, active.frameId, new URL(active.topUrl).origin);
      assignment = await this.client.nativeLoginFill({ discovery: { ...request, selectedItem: { ...request.selectedItem, kind } },
        nativeItemPlan: plan, mode: "selection", userGestureId: createVaultMeshUuid(), ...(masterPassword ? { masterPassword } : {}),
        ...(request.topOrigin !== url.origin ? { confirmedTargetOrigin: url.origin } : {}) });
      active.clear = () => clearAssignment(assignment); masterPassword = undefined;
      if (!await this.isCurrent(active) || assignment.selectedItem.kind !== kind) fail();
      assertAssignment(assignment, page, active.tabId, id, new Set(plan.map((entry) => entry.handle)), active.frameId, request.topOrigin);
      if (assignment.frames[0].assignments.some((entry) => entry.overwrite)) fail("invalid-broker-response");
      const handles = new Set(assignment.frames[0].assignments.map((entry) => entry.handle));
      const script = fields.filter((field) => handles.has(field.handle)).map((field) => ["fill_by_opid", field.opid, sources.get(field.opid)]);
      const result = z.object({ filled: z.number().int().min(0).max(handles.size) }).strict().parse(await tabMessage(active.tabId, { kind: FILL_APPLY, assignment, script }, active.frameId));
      let auditRecorded = false;
      if (result.filled) try { await this.client.recordFill({ itemKind: kind, itemId: id, itemTitle: assignment.selectedItem.title, origin: url.origin, fieldCount: result.filled }); auditRecorded = true; } catch { /* Never replay page writes after audit failure. */ }
      return { filled: result.filled, auditRecorded };
    } finally { masterPassword = undefined; clearAssignment(assignment); if (this.active === active) this.active = undefined;
      void tabMessage(active.tabId, { kind: FILL_CANCEL }, active.frameId).catch((): undefined => undefined); }
  }

  private async handlePage(message: unknown, sender: chrome.runtime.MessageSender): Promise<unknown> {
    const parsed = PageRequestSchema.safeParse(message);
    if (!parsed.success || sender.id !== chrome.runtime.id || sender.tab?.id == null || sender.frameId == null || !sender.url) return null;
    const generation = this.generation;
    if (!await this.pageCurrent() || generation !== this.generation) return null;
    const tab = await activeTab();
    if (tab.id !== sender.tab.id || new URL(tab.url!).origin !== new URL(sender.url).origin) return null;
    const frame = await new Promise<chrome.webNavigation.GetFrameResultDetails | null>((resolve) => {
      chrome.webNavigation.getFrame({ tabId: tab.id!, frameId: sender.frameId! }, (frame) => resolve(chrome.runtime.lastError ? null : frame));
    });
    if (!frame || frame.url !== sender.url) return null;
    const request = parsed.data;
    const now = Date.now();
    for (const [key, target] of this.menus) if (target.expires <= now) this.menus.delete(key);
    const current = async () => generation === this.generation && await this.pageCurrent() && generation === this.generation;
    if (request.kind === EMAIL_SELECT) {
      const target = this.menus.get(request.targetRef); this.menus.delete(request.targetRef);
      if (request.context !== "otp" || !target || target.expires <= Date.now() || target.tabId !== tab.id || target.frameId !== sender.frameId
        || target.url !== sender.url || target.topUrl !== tab.url || !request.id || !target.emailIds?.includes(request.id) || !await current()) return null;
      return this.fillEmail(request.id, current, { tabId: target.tabId, url: target.topUrl }, target);
    }
    if (request.kind === FILL_SELECT) {
      const target = this.menus.get(request.targetRef);
      this.menus.delete(request.targetRef);
      if (!target || target.tabId !== tab.id || target.frameId !== sender.frameId || target.url !== sender.url || target.topUrl !== tab.url) return null;
      const candidate = target.candidates.find((candidate) => candidate.id === request.id);
      if (!candidate || !await current()) return null;
      if (candidate.masterPasswordReprompt || candidate.kind === "card") {
        this.pendingSelection = { ...target, id: candidate.id, kind: candidate.kind };
        return { reprompt: true };
      }
      return this.fillTarget(candidate.id, undefined, current, target, false, candidate.kind);
    }
    const result = await this.client.candidates(sender.url, request.context);
    if (!await current()) return null;
    const target: PageTarget = { tabId: tab.id!, topUrl: tab.url!, frameId: sender.frameId, url: sender.url,
      targetRef: request.targetRef, expires: now + FILL_LIFETIME, candidates: result.candidates };
    if (request.kind === FILL_AUTOMATIC) {
      if (request.context !== "login" && request.context !== "otp") return null;
      const candidate = automaticCandidate(result.candidates, await this.preferences.remembered(new URL(sender.url).origin));
      if (!candidate || !await current()) return null;
      return this.fillTarget(candidate.id, undefined, current, target, true);
    }
    if (this.menus.size >= 64) return null;
    if (request.context === "otp") {
      const email = await this.client.emailCandidates(new URL(sender.url).origin);
      try {
        if (!await current()) return null;
        target.emailIds = email.candidates.map((row) => row.id);
        this.menus.set(request.targetRef, target);
        this.watchMenus();
        return { ...result, emailOtpCandidates: email.candidates.map((row) => ({ ...row })) };
      } finally { clearEmail(email); }
    }
    this.menus.set(request.targetRef, target);
    this.watchMenus();
    return result;
  }

  private async fillTarget(id: string, masterPassword: string | undefined, current: () => Promise<boolean>, target: PageTarget, automatic: boolean, kind: "login" | NativeItemKind = "login") {
    if (this.running || target.expires <= Date.now()) fail("operation-expired");
    this.running = true;
    try {
      const tab = await activeTab();
      if (tab.id !== target.tabId || tab.url !== target.topUrl || !await current()) fail();
      return kind === "login" ? await this.fillFrame(id, masterPassword, current, tab, target, target.targetRef, automatic)
        : await this.fillItemFrame(kind, id, masterPassword, current, tab, target, target.targetRef);
    } finally { masterPassword = undefined; this.running = false; }
  }

  private async fillFrame(id: string, masterPassword: string | undefined, current: () => Promise<boolean>, tab: chrome.tabs.Tab,
    target: { frameId: number; url: string }, targetRef?: string, automatic = false): Promise<{ filled: number; auditRecorded: boolean }> {
    const url = new URL(target.url);
    if (!["http:", "https:"].includes(url.protocol)) fail("page-unavailable");
    const active: NonNullable<typeof this.active> = { tabId: tab.id!, topUrl: tab.url!, frameId: target.frameId,
      url: target.url, requestId: createVaultMeshUuid(), expires: Date.now() + FILL_LIFETIME, current };
    this.active = active;
    let assignment: Assignment | undefined;
    try {
      if (!await this.isCurrent(active)) fail();
      const item = (await this.client.logins()).find((item) => item.id === id);
      if (!item) fail("invalid-request");
      if (item.url?.startsWith("https:") && url.protocol !== "https:") fail("insecure-page");
      if (item.masterPasswordReprompt && !masterPassword) fail("re-prompt-required");
      if (automatic && (!item.autofillOnPageLoad || item.masterPasswordReprompt)) fail("confirmation-required");
      // Automatic plans never use custom fields. For explicit selection, metadata
      // and value-less DOM collection are independent; validate both before planning.
      const [profile, collected] = await Promise.all([
        automatic ? Promise.resolve({ id, customFields: [] }) : this.client.loginProfile(id),
        tabMessage(active.tabId, { kind: FILL_COLLECT, requestId: active.requestId,
          topOrigin: new URL(active.topUrl).origin, ...(automatic ? { expectedUsername: item.username } : {}),
          ...(targetRef ? { targetRef, automatic } : {}) }, active.frameId),
      ]);
      const page = CollectedPageSchema.parse(collected);
      if (page.url !== active.url || page.requestId !== active.requestId || Date.parse(page.expiresAt) > Date.now() + FILL_LIFETIME) fail();
      active.expires = Math.min(active.expires, Date.parse(page.expiresAt));
      if (!await this.isCurrent(active)) fail();
      // Markers are symbolic source names. No password/TOTP/detail is hydrated.
      const cipher = loginSummaryView(item);
      cipher.login.username = item.username ? "username" : null;
      cipher.login.password = item.hasPassword ? "password" : null;
      cipher.login.totp = item.hasTotpSecret ? "remote-totp-marker" : null;
      cipher.fields = (automatic ? [] : profile.customFields).map(({ index, name }) => {
        const field = new FieldView();
        field.name = name; field.value = `custom:${index}`; field.type = FieldType.Hidden;
        return field;
      });
      const script = await this.planner().generateFillScript(nativePage(page), {
        cipher, tabUrl: page.url, defaultUriMatch: UriMatchStrategy.Domain,
        skipUsernameOnlyFill: false, onlyEmptyFields: automatic, fillNewPassword: false,
        allowTotpAutofill: item.hasTotpSecret, canAccessTotp: item.hasTotpSecret, remoteTotpPlanning: true, autoSubmitLogin: false,
      });
      const sources = new Map<string, string>();
      for (const [action, opid, source] of script?.script ?? []) {
        if (action !== "fill_by_opid") continue;
        if (!/^(?:username|password|012345|[0-5]|custom:[0-9]{1,3})$/.test(source ?? "") || sources.has(opid)) fail("invalid-fill-plan");
        sources.set(opid, source!);
      }
      // Never disclose an OTP into a nonempty field, including explicitly selected fills.
      for (const field of nativePage(page).fields) if (credentialCustomSources(field).length && !sources.get(field.opid)?.startsWith("custom:")) sources.delete(field.opid);
      for (const field of page.fields) if (!field.empty && /^(?:012345|[0-5])$/.test(sources.get(field.opid) ?? "")) sources.delete(field.opid);
      const fields = page.fields.filter((field) => sources.has(field.opid));
      if (!script || !fields.length || fields.length !== sources.size || script.untrustedIframe) fail("no-fillable-fields");
      const plan = NativeLoginPlanSchema.parse(fields.map((field) => {
        const source = sources.get(field.opid)!;
        if (source.startsWith("custom:")) {
          const index = Number(source.slice(7));
          return { handle: field.handle, source: "custom", index, name: profile.customFields.find((f) => f.index === index)?.name };
        }
        if (/^(?:012345|[0-5])$/.test(source)) return { handle: field.handle, source: "totpCode", ...(source.length === 1 ? { index: Number(source) } : {}) };
        return { handle: field.handle, source };
      }));
      if (!await this.isCurrent(active)) fail();
      assignment = await this.client.nativeLoginFill({
        discovery: discovery({ ...page, fields }, active.tabId, item, active.frameId, new URL(active.topUrl).origin), nativeLoginPlan: plan,
        ...(new URL(active.topUrl).origin !== url.origin ? { confirmedTargetOrigin: url.origin } : {}),
        mode: automatic ? "automatic" : "selection", ...(!automatic ? { userGestureId: createVaultMeshUuid() } : {}), ...(masterPassword ? { masterPassword } : {}),
      });
      active.clear = () => clearAssignment(assignment);
      masterPassword = undefined;
      if (!await this.isCurrent(active)) fail();
      assertAssignment(assignment, page, active.tabId, id, new Set(plan.map((entry) => entry.handle)), active.frameId, new URL(active.topUrl).origin);
      // Broker can omit absent values. Never manufacture a replacement assignment.
      const handles = new Set(assignment.frames[0].assignments.map((a) => a.handle));
      const opids = new Set(fields.filter((f) => handles.has(f.handle)).map((f) => f.opid));
      const planned = script.script.filter((action) => opids.has(action[1])).map(([action, opid, source]) => [action, opid, source ?? null]);
      const result = z.object({ filled: z.number().int().min(0).max(handles.size) }).strict()
        .parse(await tabMessage(active.tabId, { kind: FILL_APPLY, assignment, script: planned }, active.frameId));
      let auditRecorded = false;
      if (result.filled > 0) {
        if (!automatic) void this.preferences.remember(url.origin, id).catch((): undefined => undefined);
        try {
          await this.client.recordFill({ itemKind: "login", itemId: id, itemTitle: assignment.selectedItem.title,
            origin: url.origin, fieldCount: result.filled });
          auditRecorded = true;
        } catch { /* A failed audit must never replay already executed page writes. */ }
      }
      return { filled: result.filled, auditRecorded };
    } finally {
      masterPassword = undefined;
      clearAssignment(assignment);
      if (this.active === active) {
        this.active = undefined;
        void tabMessage(active.tabId, { kind: FILL_CANCEL }, active.frameId).catch((): undefined => undefined);
      }
    }
  }
}

function discovery(page: CollectedPage, tabId: number, item: { id: string; title: string }, frameId = 0, topOrigin = new URL(page.url).origin) {
  const origin = new URL(page.url).origin;
  return { version: 1, requestId: page.requestId, issuedAt: new Date().toISOString(), expiresAt: page.expiresAt,
    tabId, topOrigin, targetOrigin: origin, targetPageUrl: page.url, selectedItem: { kind: "login", id: item.id, title: item.title },
    frames: [{ frameId, documentId: page.documentId, frameOrigin: origin,
      fields: page.fields.map((field) => ({ handle: field.handle, control: ["select", "textarea"].includes(field.tagName.toLowerCase()) ? field.tagName.toLowerCase() : "input", inputType: field.type,
        ...(field.selectInfo ? { options: field.selectInfo.options.map(([text, value]) => ({ text, value })) } : {}),
        isEmpty: field.empty, ...(field.maxLength && field.maxLength > 0 && field.maxLength <= 100 ? { maxLength: field.maxLength } : {}),
        autocomplete: field.autoCompleteType.split(/\s+/).filter(Boolean).slice(0, 8),
        label: [field["label-tag"], field["label-aria"], field["label-left"]].filter(Boolean).join(" ").slice(0, 240),
        name: field.htmlName.slice(0, 160), id: field.htmlID.slice(0, 160), placeholder: field.placeholder.slice(0, 160), context: field.context })),
    }],
  };
}

export function assertAssignment(assignment: Assignment, page: CollectedPage, tabId: number, itemId: string, handles: Set<string>, frameId = 0, topOrigin = new URL(page.url).origin): void {
  const origin = new URL(page.url).origin;
  const frame = assignment.frames[0];
  if (assignment.requestId !== page.requestId || assignment.tabId !== tabId || assignment.topOrigin !== topOrigin
    || assignment.expiresAt !== page.expiresAt || Date.parse(assignment.expiresAt) <= Date.now()
    || assignment.selectedItem.id !== itemId || frame.frameId !== frameId || frame.documentId !== page.documentId || frame.frameOrigin !== origin
    || new Set(frame.assignments.map((entry) => entry.handle)).size !== frame.assignments.length
    || frame.assignments.some((entry) => !handles.has(entry.handle)
      || (entry.overwrite && page.fields.find((field) => field.handle === entry.handle)?.empty))) fail("invalid-broker-response");
}
