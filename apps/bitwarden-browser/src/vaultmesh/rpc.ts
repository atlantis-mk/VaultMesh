import { z } from "zod";
import { connectionCode, type ConnectionCode } from "./connection-diagnostics";
import { ManagedCommandSchema, managedRequest, managedMutation, managedConfirmation, parseManagedResult, type ManagedCommand } from "./managed-items";
import { PasskeyProxyRequestSchema } from "./vendor/model-contracts";
import { SECURITY_TOOLS, SecurityCommandSchema, type SecurityCommand } from "./security-tools";
import { PasskeyManagementSchema, passkeysForLogin, type PasskeyManagement } from "./passkey-management";
import { EmailCandidatesSchema, clearEmail } from "./email-otp";
import { EmailAssignmentSchema } from "./native-fill-contracts";

import { PersistentNativeConnection, type NativeRpcRequest } from "./native-connection";
import { createVaultMeshUuid } from "./uuid";
import { LoginSummarySchema, LoginSummariesSchema, VaultMeshStatusSchema, type VaultMeshStatus } from "./contracts";
import { LoginDetailSchema, LoginSaveSchema, clearLoginSecrets, type LoginSave } from "./login-contracts";
export { VaultMeshStatusSchema, VAULTMESH_STATUS_MESSAGE, type VaultMeshStatus } from "./contracts";
import { VAULTMESH_STATUS_MESSAGE } from "./contracts";
import { AssignmentSchema, NativeCandidatesSchema, clearAssignment } from "./native-fill-contracts";
import { NativeLoginProfileSchema } from "./vendor/browser-native-login-profile";
import { BrowserRecoveryFileInputSchema, PreparedBrowserRecoveryFileSchema, FinishedBrowserRecoveryFileSchema } from "./vendor/browser-recovery-file";
import { LoginTrashSchema, LoginHistorySchema, LoginRecoveryCommandSchema, RecoveryCodesSchema, type LoginRecoveryCommand } from "./recovery-contracts";

export const VAULTMESH_RPC_VERSION = 2 as const;
const REQUEST_LIFETIME_MS = 60_000;

const responseSchema = z.discriminatedUnion("ok", [
  z.object({
    kind: z.literal("vaultmesh.rpc-result"),
    version: z.literal(VAULTMESH_RPC_VERSION),
    requestId: z.string().uuid(),
    ok: z.literal(true),
    result: z.unknown(),
  }),
  z.object({
    kind: z.literal("vaultmesh.rpc-result"),
    version: z.literal(VAULTMESH_RPC_VERSION),
    requestId: z.string().uuid(),
    ok: z.literal(false),
    error: z.object({ code: z.string().max(128), message: z.string().max(512) }),
  }),
]);

const hostStatusSchema = z.object({
  kind: z.literal("vaultmesh.host-status"),
  status: z.string().max(128),
  requestId: z.string().uuid().optional(),
});

export type VaultMeshDesktopState = "ready" | "locked" | "unpaired" | "unavailable";

export class VaultMeshRpcError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "VaultMeshRpcError";
  }
}

/**
 * The browser fork's only desktop entry point. It owns no Vault data and
 * returns only schema-validated renderer-safe results.
 */
export class VaultMeshRpcClient {
  constructor(private readonly connection = new PersistentNativeConnection()) {}

  start(): void {
    this.connection.start();
  }

  dispose(): void {
    this.connection.dispose();
  }

  async status(): Promise<VaultMeshStatus> {
    return VaultMeshStatusSchema.parse(await this.request("vault.status"));
  }

  async logins() {
    return LoginSummariesSchema.parse(await this.request("items.list"));
  }

  async emailCandidates(topOrigin: string) {
    const raw = await this.request("email.otp.candidates", { topOrigin });
    try { return EmailCandidatesSchema.parse(raw); } finally { clearEmail(raw); }
  }
  async emailFill(input: Record<string, unknown>) {
    const raw = await this.request("email.otp.fill", { ...input, userGestureId: createVaultMeshUuid() });
    try { return EmailAssignmentSchema.parse(raw); } finally { clearAssignment(raw); }
  }
  async emailWatch(topOrigin: string, active: boolean) {
    return z.object({ watching: z.boolean(), boostExpiresAt: z.number().nonnegative() }).parse(await this.request("email.otp.watch", { topOrigin, active, userGestureId: createVaultMeshUuid() }));
  }
  async emailPoll() { await this.request("email.otp.poll"); }

  async passkey(kind: "create" | "get", requestDetailsJson: string, loginId?: string) {
    const input = PasskeyProxyRequestSchema.parse({ requestDetailsJson, ...(loginId && kind === "create" ? { loginId } : {}) });
    let raw: unknown;
    try {
      raw = await this.request(kind === "create" ? "passkeys.create" : "passkeys.get", input);
      return z.object({ responseJson: z.string().min(2).max(256 * 1024) }).strict().parse(raw);
    } finally {
      requestDetailsJson = input.requestDetailsJson = "";
      if (raw && typeof raw === "object" && "responseJson" in raw) raw.responseJson = "";
    }
  }

  async securityTool(command: SecurityCommand, isCurrent: () => boolean) {
    const parsed = SecurityCommandSchema.parse(command);
    const definition = SECURITY_TOOLS[parsed.operation];
    const input = definition.input.parse(parsed.input) as Record<string, unknown>;
    const userGestureId = createVaultMeshUuid();
    let confirmationToken = "";
    let raw: unknown;
    try {
      if (definition.confirmation) {
        const confirmation = z.object({ confirmationToken: z.uuid(), expiresAt: z.string().datetime() })
          .parse(await this.request("confirmation.request", { operation: parsed.operation, userGestureId }));
        confirmationToken = confirmation.confirmationToken; confirmation.confirmationToken = "";
        if (Date.parse(confirmation.expiresAt) <= Date.now() || Date.parse(confirmation.expiresAt) > Date.now() + 30000) throw new VaultMeshRpcError("operation-expired", "确认已过期。");
      }
      if (!isCurrent()) throw new VaultMeshRpcError("operation-expired", "操作已取消。");
      if (parsed.operation === "vault.create" && (await this.status()).hasVault) throw new VaultMeshRpcError("invalid-request", "已有保险库，不能覆盖创建。");
      if (!isCurrent()) throw new VaultMeshRpcError("operation-expired", "操作已取消。");
      raw = await this.request(parsed.operation, { ...input, ...(definition.mutation ? { userGestureId } : {}), ...(confirmationToken ? { confirmationToken } : {}) });
      const result = definition.result.parse(raw);
      if (parsed.operation.endsWith(".unlock") && (!result || !("status" in (result as object)) || !(result as { status: { unlocked: boolean } }).status.unlocked)) throw new VaultMeshRpcError("unlock-required", "未解锁。");
      return result;
    } finally { confirmationToken = ""; clearLoginSecrets(raw); clearLoginSecrets(input); clearLoginSecrets(parsed); clearLoginSecrets(command); }
  }

  async managePasskeys(command: PasskeyManagement, isCurrent: () => boolean) {
    const parsed = PasskeyManagementSchema.parse(command);
    const raw = await this.request("secrets.list");
    let rows;
    try { rows = passkeysForLogin(raw, parsed.loginId); } finally { clearLoginSecrets(raw); }
    if (!isCurrent()) throw new VaultMeshRpcError("operation-expired", "操作已取消。");
    if (parsed.verb === "list") return rows;
    if (!rows.some((row) => row.id === parsed.id)) throw new VaultMeshRpcError("invalid-request", "Passkey 归属不匹配。");
    const userGestureId = createVaultMeshUuid();
    const confirmation = z.object({ confirmationToken: z.uuid(), expiresAt: z.iso.datetime() }).parse(await this.request("confirmation.request", { operation: "secrets.delete", userGestureId }));
    try {
      if (!isCurrent() || Date.parse(confirmation.expiresAt) <= Date.now() || Date.parse(confirmation.expiresAt) > Date.now() + 30000) throw new VaultMeshRpcError("operation-expired", "确认已过期。");
      await this.request("secrets.delete", { id: parsed.id, userGestureId, confirmationToken: confirmation.confirmationToken }); return null;
    } finally { confirmation.confirmationToken = ""; rows.length = 0; }
  }

  async managedItem(command: ManagedCommand, isCurrent: () => boolean) {
    const parsed = ManagedCommandSchema.parse(command);
    const request = managedRequest(parsed);
    let raw: unknown;
    let confirmationToken = "";
    try {
      // Passkeys are not ordinary editable Secret records. Enforce this at the
      // privileged adapter too, not only by hiding them from the Secret list.
      const id = "id" in parsed ? parsed.id : parsed.verb === "save" ? parsed.input.id : undefined;
      if (parsed.kind === "secret" && id) {
        const detail = await this.request("secrets.detail", { id });
        try { parseManagedResult({ kind: "secret", verb: "detail", id: String(id) }, detail); }
        finally { clearLoginSecrets(detail); }
      }
      const userGestureId = createVaultMeshUuid();
      if (managedConfirmation(parsed)) {
        const confirmation = z.object({ confirmationToken: z.uuid(), expiresAt: z.string().datetime() })
          .parse(await this.request("confirmation.request", { operation: request.operation, userGestureId }));
        confirmationToken = confirmation.confirmationToken;
        confirmation.confirmationToken = "";
        if (Date.parse(confirmation.expiresAt) <= Date.now() || Date.parse(confirmation.expiresAt) > Date.now() + 30000) {
          throw new VaultMeshRpcError("operation-expired", "确认已过期。");
        }
      }
      if (!isCurrent()) throw new VaultMeshRpcError("operation-expired", "操作会话已失效。");
      raw = await this.request(request.operation, { ...request.input,
        ...(managedMutation(parsed) ? { userGestureId } : {}), ...(confirmationToken ? { confirmationToken } : {}) });
      try { return parseManagedResult(parsed, raw); }
      catch { throw new VaultMeshRpcError(managedMutation(parsed) ? "execution-unknown" : "invalid-broker-response", "无法确认条目响应。"); }
    } catch (error) {
      if (managedMutation(parsed) && error instanceof VaultMeshRpcError && ["desktop-unavailable", "invalid-broker-response"].includes(error.code)) {
        throw new VaultMeshRpcError("execution-unknown", "结果未确认，请刷新检查；不要重复提交。");
      }
      throw error;
    } finally { confirmationToken = ""; clearLoginSecrets(raw); clearLoginSecrets(request.input); clearLoginSecrets(parsed); clearLoginSecrets(command); }
  }

  async loginTrash() {
    return LoginTrashSchema.parse(await this.request("items.trash.list"));
  }

  async prepareRecoveryFile(isCurrent: () => boolean) {
    const raw = await this.recoveryFileDialog({ phase: "prepare" }, isCurrent);
    try { return PreparedBrowserRecoveryFileSchema.parse(raw); } finally { clearLoginSecrets(raw); }
  }

  async finishRecoveryFile(cleanupId: string, isCurrent: () => boolean) {
    return FinishedBrowserRecoveryFileSchema.parse(await this.recoveryFileDialog({ phase: "finish", cleanupId }, isCurrent));
  }

  private async recoveryFileDialog(input: { phase: "prepare" } | { phase: "finish"; cleanupId: string }, isCurrent: () => boolean) {
    BrowserRecoveryFileInputSchema.parse(input);
    const userGestureId = createVaultMeshUuid();
    const confirmation = z.object({ confirmationToken: z.string().uuid(), expiresAt: z.string().datetime() })
      .parse(await this.request("confirmation.request", { operation: "items.recovery-codes.import-file", userGestureId }));
    try {
      const expiry = Date.parse(confirmation.expiresAt);
      if (!isCurrent() || expiry <= Date.now() || expiry > Date.now() + 30000) throw new VaultMeshRpcError("operation-expired", "导入确认已失效。");
      const result = await this.request("items.recovery-codes.import-file", { ...input, userGestureId, confirmationToken: confirmation.confirmationToken });
      if (!isCurrent()) { clearLoginSecrets(result); throw new VaultMeshRpcError("operation-expired", "导入已取消。"); }
      return result;
    } finally { confirmation.confirmationToken = ""; }
  }

  async recoveryCodes(id: string, masterPassword: string) {
    let raw: unknown;
    try {
      raw = await this.request("items.recovery-codes", { id: z.string().uuid().parse(id), masterPassword, userGestureId: createVaultMeshUuid() });
      return RecoveryCodesSchema.parse(raw);
    } finally { masterPassword = ""; clearLoginSecrets(raw); }
  }

  async copyRecoveryCode(id: string, index: number, masterPassword: string) {
    try {
      return z.object({ clearsAt: z.number().int().nonnegative() }).strict().parse(await this.request("items.copy-recovery-code", {
        id: z.string().uuid().parse(id), index: z.number().int().min(0).max(99).parse(index), masterPassword, userGestureId: createVaultMeshUuid(),
      }));
    } finally { masterPassword = ""; }
  }

  async loginHistory(id: string) {
    const result = LoginHistorySchema.parse(await this.request("items.history.list", { id: z.string().uuid().parse(id) }));
    if (result.some((entry) => entry.itemId !== id)) throw new VaultMeshRpcError("invalid-broker-response", "历史目标不匹配。");
    return result;
  }

  async recoverLogin(command: LoginRecoveryCommand, isCurrent: () => boolean): Promise<void> {
    const parsed = LoginRecoveryCommandSchema.parse(command);
    const userGestureId = createVaultMeshUuid();
    let confirmationToken = "";
    try {
      if (parsed.operation !== "items.trash.restore") {
        const confirmation = z.object({ confirmationToken: z.string().uuid(), expiresAt: z.string().datetime() })
          .parse(await this.request("confirmation.request", { operation: parsed.operation, userGestureId }));
        confirmationToken = confirmation.confirmationToken;
        confirmation.confirmationToken = "";
        const expiry = Date.parse(confirmation.expiresAt);
        if (expiry <= Date.now() || expiry > Date.now() + 30_000) throw new VaultMeshRpcError("operation-expired", "恢复确认已失效。");
      }
      if (!isCurrent()) throw new VaultMeshRpcError("operation-expired", "恢复会话已失效。");
      const input = parsed.operation === "items.trash.restore" || parsed.operation === "items.trash.purge" ? { trashId: parsed.trashId }
        : parsed.operation === "items.history.restore" ? { itemId: parsed.itemId, revisionId: parsed.revisionId }
        : parsed.operation === "items.history.clear" ? { id: parsed.id } : {};
      const raw = await this.request(parsed.operation, { ...input, userGestureId, ...(confirmationToken ? { confirmationToken } : {}) });
      try {
        if (parsed.operation === "items.trash.restore" || parsed.operation === "items.history.restore") {
          if (LoginSummarySchema.parse(raw).id !== parsed.itemId) throw new Error("mismatched-item");
        } else z.object({}).strict().parse(raw);
      } catch { throw new VaultMeshRpcError("execution-unknown", "恢复结果未确认，请刷新检查。"); }
      finally { clearLoginSecrets(raw); }
    } finally { confirmationToken = ""; }
  }

  async nativeLoginFill(input: Record<string, unknown>) {
    const raw = await this.request("browser.autofill.execute", input);
    try { return AssignmentSchema.parse(raw); }
    finally { clearAssignment(raw); }
  }

  async copyGenerated(generated: { mode: string; value: string }) {
    const input = { ...generated, userGestureId: createVaultMeshUuid() };
    try { return z.object({ clearsAt: z.number().int().nonnegative() }).strict().parse(await this.request("browser.generated.copy", input)); }
    finally { input.value = ""; }
  }

  async loginProfile(id: string) {
    const result = NativeLoginProfileSchema.parse(await this.request("browser.autofill.profile", { id }));
    if (result.id !== id) throw new VaultMeshRpcError("invalid-broker-response", "填充目标不匹配。");
    return result;
  }

  async candidates(pageUrl: string, context: "login" | "otp" | "card" | "identity" | "ssh" | "secret") {
    return NativeCandidatesSchema.parse(await this.request("browser.autofill.candidates", {
      topOrigin: new URL(pageUrl).origin, pageUrl, fieldKind: context === "login" || context === "otp" ? "login" : context,
      pageContext: context === "secret" ? "developer-secret" : context === "ssh" ? "ssh-console" : context === "card" || context === "identity" ? "unknown" : context,
    }));
  }

  async recordFill(input: { itemKind: "login" | "card" | "identity" | "ssh" | "secret"; itemId: string; itemTitle: string; origin: string; fieldCount: number }): Promise<void> {
    await this.request("browser.fill.record", input);
  }

  async events(after: number) {
    return z.object({ sequence: z.number().int().nonnegative(), events: z.array(z.object({
      sequence: z.number().int().nonnegative(), type: z.string().max(128), occurredAt: z.string().datetime(),
    })).max(32) }).parse(await this.request("events.poll", { after }));
  }

  async loginDetail(id: string) {
    const raw = await this.request("items.detail", { id: z.string().uuid().parse(id), userGestureId: createVaultMeshUuid() });
    try {
      const detail = LoginDetailSchema.parse(raw);
      if (detail.id !== id) {
        clearLoginSecrets(detail);
        throw new VaultMeshRpcError("invalid-broker-response", "编辑目标不匹配。");
      }
      return detail;
    } finally {
      clearLoginSecrets(raw);
    }
  }

  async copyLogin(id: string, field: "username" | "password" | "totp", masterPassword?: string) {
    const operation = { username: "items.copy-username", password: "items.copy-password", totp: "items.copy-totp" }[field];
    if (!operation) throw new VaultMeshRpcError("invalid-request", "无效复制操作。");
    try {
      return z.object({ clearsAt: z.number().int().nonnegative() }).strict().parse(await this.request(operation, {
        id: z.string().uuid().parse(id), masterPassword: masterPassword ?? null, userGestureId: createVaultMeshUuid(),
      }));
    } finally { masterPassword = undefined; }
  }

  async saveLogin(input: LoginSave) {
    const parsed = LoginSaveSchema.parse(input);
    try {
      const raw = await this.request(parsed.id ? "items.update" : "items.add", {
        ...parsed, userGestureId: createVaultMeshUuid(),
      });
      try {
        const summary = LoginSummarySchema.parse(raw);
        if (parsed.id && summary.id !== parsed.id) throw new Error("mismatched-item");
        return summary;
      } catch {
        throw new VaultMeshRpcError("execution-unknown", "保存结果未确认，请刷新检查。");
      } finally {
        clearLoginSecrets(raw);
      }
    } finally {
      clearLoginSecrets(parsed);
      clearLoginSecrets(input);
    }
  }

  async deleteLogin(id: string, isCurrent: () => boolean = () => true): Promise<void> {
    z.string().uuid().parse(id);
    const userGestureId = createVaultMeshUuid();
    const confirmation = z.object({ confirmationToken: z.string().uuid(), expiresAt: z.string().datetime() })
      .parse(await this.request("confirmation.request", { operation: "items.delete", userGestureId }));
    const expiresAt = Date.parse(confirmation.expiresAt);
    if (!isCurrent() || expiresAt <= Date.now() || expiresAt > Date.now() + 30_000) {
      throw new VaultMeshRpcError("operation-expired", "删除确认已失效。");
    }
    try {
      const result = await this.request("items.delete", { id, userGestureId, confirmationToken: confirmation.confirmationToken });
      if (!z.object({}).strict().safeParse(result).success) {
        throw new VaultMeshRpcError("execution-unknown", "删除结果未确认，请刷新检查。");
      }
    } finally {
      confirmation.confirmationToken = "";
    }
  }

  async unlock(masterPassword: string): Promise<void> {
    try {
      const result = z.object({ cancelled: z.literal(false), status: VaultMeshStatusSchema })
        .parse(await this.request("vault.unlock", { masterPassword, userGestureId: createVaultMeshUuid() }));
      if (!result.status.unlocked) throw new VaultMeshRpcError("unlock-required", "插件仍处于锁定状态。");
    } finally {
      masterPassword = "";
    }
  }

  async lock(): Promise<void> {
    const status = VaultMeshStatusSchema.parse(await this.request("vault.lock", { userGestureId: createVaultMeshUuid() }));
    if (status.unlocked) throw new VaultMeshRpcError("invalid-broker-response", "锁定状态未确认。");
  }

  onDisconnected(listener: (code: ConnectionCode) => void): () => void {
    return this.connection.onDisconnected(listener);
  }

  private async request(operation: string, input: Record<string, unknown> = {}): Promise<unknown> {
    const now = Date.now();
    const request: NativeRpcRequest = {
      kind: "vaultmesh.rpc",
      version: VAULTMESH_RPC_VERSION,
      requestId: createVaultMeshUuid(),
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + REQUEST_LIFETIME_MS).toISOString(),
      operation,
      input,
    };

    let response: unknown;
    try {
      response = await this.connection.request(request);
    } catch (error) {
      throw new VaultMeshRpcError(
        ["items.add", "items.update", "items.delete"].includes(operation) ? "execution-unknown" : connectionCode(error instanceof Error ? error.message : undefined),
        "无法确认桌面端响应。",
      );
    } finally {
      clearLoginSecrets(input);
      delete input.masterPassword;
    }

    const hostStatus = hostStatusSchema.safeParse(response);
    if (hostStatus.success) {
      if (hostStatus.data.requestId && hostStatus.data.requestId !== request.requestId) {
        throw new VaultMeshRpcError("invalid-broker-response", "响应关联无效。");
      }
      const code = hostStatus.data.status;
      const message = code === "unpaired"
        ? "VaultMesh 插件尚未与桌面端配对。"
        : "无法连接 VaultMesh 桌面端。";
      throw new VaultMeshRpcError(code, message);
    }

    const parsed = responseSchema.safeParse(response);
    if (!parsed.success || parsed.data.requestId !== request.requestId) {
      throw new VaultMeshRpcError("invalid-broker-response", "VaultMesh 桌面端返回了无效响应。");
    }
    if (parsed.data.ok === false) {
      throw new VaultMeshRpcError(parsed.data.error.code, parsed.data.error.message);
    }
    return parsed.data.result;
  }
}

export const vaultMeshRpcClient = new VaultMeshRpcClient();


export type VaultMeshStatusMessage = { kind: typeof VAULTMESH_STATUS_MESSAGE };

export function isVaultMeshStatusMessage(value: unknown): value is VaultMeshStatusMessage {
  return Boolean(value && typeof value === "object" && (value as { kind?: unknown }).kind === VAULTMESH_STATUS_MESSAGE);
}
