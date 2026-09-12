import { Injectable, OnDestroy } from "@angular/core";
import { connectionMessage } from "../../vaultmesh/connection-diagnostics";
import { z } from "zod";
import { ManagedCommandSchema, parseManagedResult, managedMutation, type ManagedCommand, type ManagedResult } from "../../vaultmesh/managed-items";
import { SECURITY_TOOLS, SecurityCommandSchema, type SecurityCommand } from "../../vaultmesh/security-tools";
import { QrGrantSchema, type QrGrant } from "../../vaultmesh/qr-contracts";
import { PasskeyManagementSchema, passkeysForLogin, type PasskeyManagement, type PasskeyRows } from "../../vaultmesh/passkey-management";
import { EmailPopupSchema, type EmailPopup } from "../../vaultmesh/email-otp";
import { BehaviorSubject } from "rxjs";
import {
  LoginSummariesSchema, StatusResponseSchema, SessionResponseSchema,
  SESSION_MESSAGE, SESSION_INVALIDATED, VAULTMESH_STATUS_MESSAGE,
  type LoginSummary, type VaultMeshStatus,
} from "../../vaultmesh/contracts";
import { sendSessionMessage, requestNativePermission } from "../../vaultmesh/runtime";
import { LoginDetailSchema, clearLoginSecrets, type LoginDetail, type LoginSave } from "../../vaultmesh/login-contracts";
import { createVaultMeshUuid } from "../../vaultmesh/uuid";
import { LoginSummarySchema, FillFrameSchema, type FillFrame } from "../../vaultmesh/contracts";
import { PreparedBrowserRecoveryFileSchema, FinishedBrowserRecoveryFileSchema, type PreparedBrowserRecoveryFile } from "../../vaultmesh/vendor/browser-recovery-file";
import { LoginTrashSchema, LoginHistorySchema, RecoveryCodesSchema, type RecoveryCodes, type LoginRecoveryCommand, type LoginTrash, type LoginHistory } from "../../vaultmesh/recovery-contracts";

export type ItemActionResult<T> = { ok: true; value: T } | { ok: false; code: string };

export type VaultMeshPopupStatus = "loading" | "ready" | "locked" | "unpaired" | "unavailable";
export type SessionState = {
  status: VaultMeshPopupStatus;
  vault: VaultMeshStatus | null;
  logins: LoginSummary[];
  busy: boolean;
  error: string | null;
  revision?: number;
  sessionId?: string;
  loadingStage?: "permission" | "status" | "logins";
};
const emptyState = (): SessionState => ({ status: "loading", vault: null, logins: [], busy: false, error: null });

/** Scoped to the open VaultMesh page. No account/key/item storage is used. */
@Injectable()
export class VaultMeshBrowserRpcService implements OnDestroy {
  private readonly stateSubject = new BehaviorSubject<SessionState>(emptyState());
  readonly state$ = this.stateSubject.asObservable();
  private generation = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private running = false;
  private lifecycle = 0;
  private fillPending = false;
  private recoveryPending = false;
  private fileDialogPending = false;
  private dialogStatusPending = false;
  private managedPending = false;
  private connecting = false;
  private refreshPending?: Promise<void>;
  private readonly invalidate = (message: unknown, sender: chrome.runtime.MessageSender) => {
    if (sender.id === chrome.runtime.id && !sender.tab &&
        message && typeof message === "object" && "kind" in message && message.kind === SESSION_INVALIDATED) {
      this.clear("unavailable");
      this.stateSubject.next({ ...this.stateSubject.value, error: connectionMessage("code" in message ? message.code : undefined) });
    }
    return false;
  };

  start(): void {
    if (this.running) return;
    this.running = true;
    chrome.runtime.onMessage.addListener(this.invalidate);
    void this.poll(++this.lifecycle);
  }

  private async poll(lifecycle: number): Promise<void> {
    if (!this.running || lifecycle !== this.lifecycle) return;
    if (!this.stateSubject.value.busy) await this.refresh(false, false);
    else if (this.fileDialogPending && !this.dialogStatusPending) void this.checkDialogAuthorization(lifecycle);
    if (this.running && lifecycle === this.lifecycle) {
      this.timer = setTimeout(() => void this.poll(lifecycle), 3_000);
    }
  }

  private async checkDialogAuthorization(lifecycle: number): Promise<void> {
    this.dialogStatusPending = true;
    try {
      const response = StatusResponseSchema.parse(await sendSessionMessage({ kind: VAULTMESH_STATUS_MESSAGE }));
      if (!this.fileDialogPending || lifecycle !== this.lifecycle) return;
      if (response.status !== "ready" || response.sessionId !== this.stateSubject.value.sessionId
        || response.revision !== this.stateSubject.value.revision) this.clear(response.status === "locked" ? "locked" : "unavailable");
    } catch { if (this.fileDialogPending && lifecycle === this.lifecycle) this.clear("unavailable"); }
    finally { this.dialogStatusPending = false; }
  }

  async connect(): Promise<void> {
    if (this.connecting || this.refreshPending || this.stateSubject.value.busy) return;
    this.connecting = true;
    const lifecycle = this.lifecycle;
    this.generation++;
    this.stateSubject.next({ ...emptyState(), busy: true, loadingStage: "permission" });
    // Request immediately in the click stack: browsers require a user gesture.
    try {
      const granted = await requestNativePermission();
      if (lifecycle !== this.lifecycle) return;
      if (granted) {
        this.stateSubject.next({ ...emptyState(), loadingStage: "status" });
        await this.refresh(true);
      } else this.stateSubject.next({ ...emptyState(), status: "unavailable", error: "未获得连接权限或等待已超时，请允许连接桌面应用后重试。" });
    } catch (error) { if (lifecycle === this.lifecycle) this.fail(error); }
    finally { this.connecting = false; }
  }

  refresh(fromConnect = false, forceList = true): Promise<void> {
    if (this.refreshPending) return this.refreshPending;
    if (this.stateSubject.value.busy || this.connecting && !fromConnect) return Promise.resolve();
    const pending = this.loadSnapshot(forceList).finally(() => {
      if (this.refreshPending === pending) this.refreshPending = undefined;
    });
    this.refreshPending = pending;
    return pending;
  }

  private async loadSnapshot(forceList: boolean): Promise<void> {
    const generation = ++this.generation;
    try {
      const response = StatusResponseSchema.parse(await sendSessionMessage({ kind: VAULTMESH_STATUS_MESSAGE }));
      if (generation !== this.generation) return;
      const vault = "vault" in response ? response.vault ?? null : null;
      const revision = "revision" in response ? response.revision : undefined;
      const sessionId = "sessionId" in response ? response.sessionId : undefined;
      if (response.status !== "ready") {
        this.stateSubject.next({ status: response.status, vault, logins: [], busy: false,
          error: response.status === "unavailable" ? connectionMessage(response.code) : null, revision, sessionId });
        return;
      }
      const previous = this.stateSubject.value;
      // Reuse only the visible page's summary snapshot after a fresh authorization
      // and event check. Manual refreshes/mutations and legacy replies always read.
      if (!forceList && previous.status === "ready" && sessionId !== undefined && revision !== undefined
        && sessionId === previous.sessionId && revision === previous.revision
        && vault?.itemCount === previous.vault?.itemCount) return;
      if (this.stateSubject.value.status === "loading") {
        this.stateSubject.next({ ...this.stateSubject.value, loadingStage: "logins" });
      }
      const logins = LoginSummariesSchema.parse(await this.action({ kind: SESSION_MESSAGE, action: "logins" }));
      if (generation !== this.generation) return;
      this.stateSubject.next({ status: "ready", vault, logins, busy: false, error: null, revision, sessionId });
    } catch (error) {
      if (generation === this.generation) this.fail(error);
    }
  }

  async unlock(masterPassword: string): Promise<void> {
    const message = { kind: SESSION_MESSAGE, action: "unlock" as const, masterPassword };
    masterPassword = "";
    try { await this.mutate(message); }
    finally { message.masterPassword = ""; }
  }

  async lock(): Promise<void> {
    await this.mutate({ kind: SESSION_MESSAGE, action: "lock" });
  }

  editLogin(id: string): Promise<ItemActionResult<LoginDetail>> {
    return this.itemAction({ kind: SESSION_MESSAGE, action: "login-detail", id }, (value) => {
      const detail = LoginDetailSchema.parse(value);
      if (detail.id !== id) {
        clearLoginSecrets(detail);
        throw new Error("invalid-broker-response");
      }
      return detail;
    });
  }

  async managedItem(command: ManagedCommand): Promise<ItemActionResult<ManagedResult>> {
    if (this.managedPending) return { ok: false, code: "operation-busy" };
    const parsed = ManagedCommandSchema.safeParse(command);
    if (!parsed.success) { clearLoginSecrets(command); return { ok: false, code: "invalid-request" }; }
    this.managedPending = true;
    try {
      return await this.itemAction({ kind: SESSION_MESSAGE, action: "managed-item", command: parsed.data, ...this.mutationIdentity() },
        (value) => parseManagedResult(command, value), managedMutation(command));
    } finally { this.managedPending = false; clearLoginSecrets(parsed.data); clearLoginSecrets(command); }
  }

  cancelManaged(): void {
    if (this.managedPending || this.fillPending) {
      void sendSessionMessage({ kind: SESSION_MESSAGE, action: "cancel-fill" }).catch((): undefined => undefined);
      this.clear("unavailable");
    }
  }

  authorizeQr(): Promise<ItemActionResult<QrGrant>> {
    return this.itemAction({ kind: SESSION_MESSAGE, action: "qr-authorize", ...this.mutationIdentity() }, (value) => QrGrantSchema.parse(value));
  }

  emailCandidates(): Promise<ItemActionResult<EmailPopup>> {
    return this.itemAction({ kind: SESSION_MESSAGE, action: "email-candidates" }, (value) => EmailPopupSchema.parse(value));
  }
  async fillEmail(candidateId: string, tabId: number, url: string): Promise<ItemActionResult<{ filled: number }>> {
    if (this.managedPending) return { ok: false, code: "operation-busy" };
    this.managedPending = true;
    try { return await this.itemAction({ kind: SESSION_MESSAGE, action: "email-fill", candidateId, tabId, url, ...this.mutationIdentity() }, (value) => z.object({ filled: z.number().int().nonnegative() }).strict().parse(value)); }
    finally { this.managedPending = false; }
  }

  async managePasskeys(command: PasskeyManagement): Promise<ItemActionResult<PasskeyRows | null>> {
    if (this.managedPending) return { ok: false, code: "operation-busy" };
    const parsed = PasskeyManagementSchema.safeParse(command); if (!parsed.success) return { ok: false, code: "invalid-request" };
    this.managedPending = true;
    try {
      return await this.itemAction({ kind: SESSION_MESSAGE, action: "passkey-management", command: parsed.data, ...this.mutationIdentity() },
        (value) => command.verb === "list" ? passkeysForLogin(value, command.loginId) : null, command.verb === "delete");
    } finally { this.managedPending = false; }
  }

  async securityTool(command: SecurityCommand): Promise<ItemActionResult<unknown>> {
    if (this.managedPending) return { ok: false, code: "operation-busy" };
    const parsed = SecurityCommandSchema.safeParse(command);
    if (!parsed.success) { clearLoginSecrets(command); return { ok: false, code: "invalid-request" }; }
    const definition = SECURITY_TOOLS[command.operation];
    this.managedPending = true;
    try {
      return await this.itemAction({ kind: SESSION_MESSAGE, action: "security-tool", command: parsed.data, ...this.mutationIdentity() },
        (raw) => definition.result.parse(raw), definition.mutation, !definition.unlocked);
    } finally { this.managedPending = false; clearLoginSecrets(parsed.data); clearLoginSecrets(command); }
  }

  /** Two exact read-only operations, one busy lifecycle; no credentials or cached authorization. */
  async readUnlockMethods(): Promise<ItemActionResult<unknown>[]> {
    if (this.managedPending || this.stateSubject.value.busy || this.stateSubject.value.status !== "locked") {
      return [{ ok: false, code: "operation-busy" }, { ok: false, code: "operation-busy" }];
    }
    this.managedPending = true;
    const generation = ++this.generation;
    this.stateSubject.next({ ...this.stateSubject.value, busy: true, error: null });
    try {
      return await Promise.all((["pin.status", "biometric.status"] as const).map(async (operation): Promise<ItemActionResult<unknown>> => {
        try {
          const raw = await this.action({ kind: SESSION_MESSAGE, action: "security-tool", command: { operation, input: {} }, ...this.mutationIdentity() });
          if (generation !== this.generation) return { ok: false, code: "operation-expired" };
          return { ok: true, value: SECURITY_TOOLS[operation].result.parse(raw) };
        } catch (error) {
          const code = error instanceof Error ? error.message : "invalid-broker-response";
          if (generation === this.generation && !["operation-failed", "operation-busy", "operation-expired"].includes(code)) this.fail(error);
          return { ok: false, code: "operation-failed" };
        }
      }));
    } finally {
      this.managedPending = false;
      if (generation === this.generation) this.stateSubject.next({ ...this.stateSubject.value, busy: false });
    }
  }

  async saveLogin(input: LoginSave, cleanupId?: string): Promise<ItemActionResult<LoginSummary>> {
    try {
      return await this.itemAction({ kind: SESSION_MESSAGE, action: "login-save", input, ...(cleanupId ? { cleanupId } : {}), ...this.mutationIdentity() },
        (value) => LoginSummarySchema.parse(value), true);
    } finally {
      clearLoginSecrets(input);
    }
  }

  deleteLogin(id: string): Promise<ItemActionResult<null>> {
    return this.itemAction({ kind: SESSION_MESSAGE, action: "login-delete", id, confirmed: true, ...this.mutationIdentity() },
      (): null => null, true);
  }

  loginTrash(): Promise<ItemActionResult<LoginTrash>> {
    return this.itemAction({ kind: SESSION_MESSAGE, action: "login-trash" }, (value) => LoginTrashSchema.parse(value));
  }

  async editorContext(): Promise<boolean> {
    try { return z.object({ independent: z.boolean() }).strict().parse(await this.action({ kind: SESSION_MESSAGE, action: "editor-context" })).independent; }
    catch { return false; }
  }

  openEditorWindow(): Promise<ItemActionResult<null>> {
    return this.itemAction({ kind: SESSION_MESSAGE, action: "editor-open" }, (value) => z.null().parse(value));
  }

  async prepareRecoveryFile(): Promise<ItemActionResult<PreparedBrowserRecoveryFile>> {
    if (this.fileDialogPending) return { ok: false, code: "operation-busy" };
    this.fileDialogPending = true;
    try { return await this.itemAction({ kind: SESSION_MESSAGE, action: "recovery-file-prepare", ...this.mutationIdentity() }, (value) => PreparedBrowserRecoveryFileSchema.parse(value)); }
    finally { this.fileDialogPending = false; }
  }

  async finishRecoveryFile(cleanupId: string): Promise<ItemActionResult<{ sourceFileStatus: "deleted" | "kept" | "failed" }>> {
    if (this.fileDialogPending) return { ok: false, code: "operation-busy" };
    this.fileDialogPending = true;
    try { return await this.itemAction({ kind: SESSION_MESSAGE, action: "recovery-file-finish", cleanupId, ...this.mutationIdentity() }, (value) => FinishedBrowserRecoveryFileSchema.parse(value), true); }
    finally { this.fileDialogPending = false; }
  }

  cancelFileDialog(): void {
    if (!this.fileDialogPending) return;
    void sendSessionMessage({ kind: SESSION_MESSAGE, action: "cancel-fill" }).catch((): undefined => undefined);
    this.clear("unavailable");
  }

  discardRecoveryFile(cleanupId: string): void {
    // Cancellation drops only the adapter's permission; it never invokes file deletion.
    void sendSessionMessage({ kind: SESSION_MESSAGE, action: "recovery-file-discard", cleanupId }).catch((): undefined => undefined);
  }

  async recoveryCodes(id: string, masterPassword: string): Promise<ItemActionResult<RecoveryCodes>> {
    const message = { kind: SESSION_MESSAGE, action: "recovery-codes-view", id, masterPassword, ...this.mutationIdentity() };
    masterPassword = "";
    try { return await this.itemAction(message, (value) => RecoveryCodesSchema.parse(value)); }
    finally { message.masterPassword = ""; }
  }

  async copyRecoveryCode(id: string, index: number, masterPassword: string): Promise<ItemActionResult<{ clearsAt: number }>> {
    const message = { kind: SESSION_MESSAGE, action: "recovery-code-copy", id, index, masterPassword, ...this.mutationIdentity() };
    masterPassword = "";
    try { return await this.itemAction(message, (value) => z.object({ clearsAt: z.number().int().nonnegative() }).strict().parse(value), true); }
    finally { message.masterPassword = ""; }
  }

  loginHistory(id: string): Promise<ItemActionResult<LoginHistory>> {
    return this.itemAction({ kind: SESSION_MESSAGE, action: "login-history", id }, (value) => {
      const result = LoginHistorySchema.parse(value);
      if (result.some((entry) => entry.itemId !== id)) throw new Error("invalid-broker-response");
      return result;
    });
  }

  async recoverLogin(command: LoginRecoveryCommand): Promise<ItemActionResult<null>> {
    this.recoveryPending = true;
    try {
      return await this.itemAction({ kind: SESSION_MESSAGE, action: "login-recovery", command, confirmed: true, ...this.mutationIdentity() },
        (value) => z.null().parse(value), true);
    } finally { this.recoveryPending = false; }
  }

  fillContexts(): Promise<ItemActionResult<FillFrame[]>> {
    return this.itemAction({ kind: SESSION_MESSAGE, action: "fill-context" }, (value) => z.array(FillFrameSchema).max(16).parse(value));
  }

  async copyLogin(id: string, field: "username" | "password" | "totp", masterPassword?: string): Promise<ItemActionResult<{ clearsAt: number }>> {
    const message = { kind: SESSION_MESSAGE, action: "login-copy", id, field, ...(masterPassword ? { masterPassword } : {}), ...this.mutationIdentity() };
    masterPassword = undefined;
    try { return await this.itemAction(message, (value) => z.object({ clearsAt: z.number().int().nonnegative() }).strict().parse(value), true); }
    finally { if ("masterPassword" in message) message.masterPassword = ""; }
  }

  async fillLogin(id: string, masterPassword?: string, frame?: FillFrame): Promise<ItemActionResult<{ filled: number; auditRecorded: boolean }>> {
    const message = { kind: SESSION_MESSAGE, action: "login-fill", id, ...(masterPassword ? { masterPassword } : {}), ...(frame ? { frame } : {}), ...this.mutationIdentity() };
    masterPassword = undefined;
    this.fillPending = true;
    try {
      return await this.itemAction(message, (value) => z.object({ filled: z.number().int().min(0).max(4800), auditRecorded: z.boolean() }).strict().parse(value), true);
    } finally { this.fillPending = false; if ("masterPassword" in message) message.masterPassword = ""; }
  }

  async fillItem(itemKind: "card" | "identity" | "ssh" | "secret", id: string, frame: FillFrame, masterPassword?: string): Promise<ItemActionResult<{ filled: number; auditRecorded: boolean }>> {
    const message = { kind: SESSION_MESSAGE, action: "item-fill", itemKind, id, frame, masterPassword, ...this.mutationIdentity() };
    this.fillPending = true;
    try { return await this.itemAction(message, (value) => z.object({ filled: z.number().int().min(0).max(300), auditRecorded: z.boolean() }).strict().parse(value), true); }
    finally { this.fillPending = false; message.masterPassword = ""; }
  }

  async generatedValue(command: "copy" | "insert", generated: { mode: "password" | "passphrase" | "username" | "uuid"; value: string }, frame?: FillFrame) {
    const message = { kind: SESSION_MESSAGE, action: "generated-value", command, generated: { ...generated }, ...(frame ? { frame } : {}), ...this.mutationIdentity() };
    this.fillPending = true;
    try { return await this.itemAction(message, (value) => command === "copy" ? z.object({ clearsAt: z.number().int().nonnegative() }).strict().parse(value) : z.object({ filled: z.number().int().min(0).max(3) }).strict().parse(value), true); }
    finally { message.generated.value = ""; this.fillPending = false; }
  }

  private mutationIdentity() {
    return { mutationId: createVaultMeshUuid(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
      revision: this.stateSubject.value.revision ?? 0, sessionId: this.stateSubject.value.sessionId ?? "" };
  }

  private async itemAction<T>(message: Record<string, unknown>, parse: (value: unknown) => T,
    mutation = false, allowLocked = false): Promise<ItemActionResult<T>> {
    if (this.stateSubject.value.busy) return { ok: false, code: "operation-busy" };
    if (this.stateSubject.value.status !== "ready" && !(allowLocked && this.stateSubject.value.status === "locked")) return { ok: false, code: "unlock-required" };
    const generation = ++this.generation;
    this.stateSubject.next({ ...this.stateSubject.value, busy: true, error: null });
    let raw: unknown;
    try {
      raw = await this.action(message);
      if (generation !== this.generation) return { ok: false, code: mutation ? "execution-unknown" : "operation-expired" };
      const value = parse(raw);
      this.stateSubject.next({ ...this.stateSubject.value, busy: false });
      if (mutation) await this.refresh();
      return { ok: true, value };
    } catch (error) {
      let code = error instanceof Error ? error.message : "invalid-broker-response";
      const known = ["operation-failed", "invalid-request", "invalid-message", "operation-busy", "duplicate-operation", "operation-expired", "confirmation-required", "cancelled", "re-prompt-required", "no-fillable-fields", "page-unavailable", "insecure-page", "invalid-fill-plan"];
      if (!known.includes(code) && !["unlock-required", "unpaired"].includes(code)) {
        code = mutation ? "execution-unknown" : "desktop-unavailable";
      }
      if (generation === this.generation) {
        if (["unlock-required", "unpaired", "desktop-unavailable", "execution-unknown"].includes(code)) this.fail(new Error(code));
        else this.stateSubject.next({ ...this.stateSubject.value, busy: false });
      }
      return { ok: false, code };
    } finally {
      clearLoginSecrets(raw);
      if (generation === this.generation && this.stateSubject.value.busy) {
        this.stateSubject.next({ ...this.stateSubject.value, busy: false });
      }
    }
  }

  private async mutate(message: Record<string, unknown>): Promise<void> {
    if (this.stateSubject.value.busy) return;
    const generation = ++this.generation;
    this.stateSubject.next({ ...this.stateSubject.value, logins: [], busy: true, error: null });
    try {
      await this.action(message);
      if (generation !== this.generation) return;
      this.stateSubject.next({ ...this.stateSubject.value, busy: false });
      await this.refresh();
    } catch (error) {
      if (generation === this.generation) this.fail(error);
    }
  }

  private async action(message: Record<string, unknown>): Promise<unknown> {
    const response = SessionResponseSchema.parse(await sendSessionMessage(message));
    if (response.ok === false) throw new Error(response.code);
    return response.result;
  }

  private fail(error: unknown): void {
    const code = error instanceof Error ? error.message : "";
    // A rejected master-password attempt leaves the same known locked vault
    // available for retry, without echoing broker error text or the password.
    if (code === "operation-failed" && this.stateSubject.value.status === "locked") {
      this.stateSubject.next({ ...this.stateSubject.value, logins: [], busy: false, error: "解锁失败，请检查主密码后重试。" });
      return;
    }
    const status = code === "unlock-required" ? "locked" : code === "unpaired" ? "unpaired" : "unavailable";
    this.stateSubject.next({
      status, vault: null, logins: [], busy: false,
      error: code === "unlock-required" ? "请重新解锁插件。" : connectionMessage(code),
    });
  }

  private clear(status: VaultMeshPopupStatus): void {
    this.generation++;
    // Invalidating authorization permits a fresh read; the old read's generation
    // still prevents it from publishing a late status or login list.
    this.refreshPending = undefined;
    this.stateSubject.next({ ...emptyState(), status });
  }

  ngOnDestroy(): void {
    if (this.fillPending || this.recoveryPending || this.fileDialogPending || this.managedPending) void sendSessionMessage({ kind: SESSION_MESSAGE, action: "cancel-fill" }).catch((): undefined => undefined);
    this.running = false;
    this.lifecycle++;
    if (this.timer) clearTimeout(this.timer);
    chrome.runtime.onMessage.removeListener(this.invalidate);
    this.clear("unavailable");
  }
}
