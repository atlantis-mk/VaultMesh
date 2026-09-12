import { isVaultMeshStatusMessage, vaultMeshRpcClient, VaultMeshRpcError } from "../vaultmesh/rpc";
import { VAULTMESH_STATUS_MESSAGE, SESSION_MESSAGE, SESSION_INVALIDATED, SessionMessageSchema } from "../vaultmesh/contracts";
import { sendSessionMessage } from "../vaultmesh/runtime";
import { clearLoginSecrets } from "../vaultmesh/login-contracts";
import { createVaultMeshUuid } from "../vaultmesh/uuid";
import { VaultMeshNativeFillBackground } from "../vaultmesh/native-fill-background";
import { VaultMeshNativeCaptureBackground } from "../vaultmesh/native-capture-background";
import type { AutofillService } from "../autofill/services/abstractions/autofill.service";
import { EditorWindows } from "../vaultmesh/editor-windows";
import { PreparedBrowserRecoveryFileSchema } from "../vaultmesh/vendor/browser-recovery-file";
import { VaultMeshPasskeyProxy } from "../vaultmesh/passkey-proxy";
import { startPluginSecurity } from "../vaultmesh/plugin-security";
import { QrAuthorization } from "../vaultmesh/qr-authorization";
import { EmailWatch } from "../vaultmesh/email-watch";

async function codesDigest(codes: string[]): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(codes));
  try { return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (byte) => byte.toString(16).padStart(2, "0")).join(""); }
  finally { bytes.fill(0); }
}

/** Native transport and validated popup actions live only in the background. */
export class VaultMeshRpcBackground {
  private readonly qr = new QrAuthorization();
  private readonly sessionId = createVaultMeshUuid();
  private generation = 0;
  private readonly editors = new EditorWindows(() => { this.generation++; this.cleanup.clear(); });
  private readonly cleanup = new Map<string, { tabId: number; expiresAt: number; digest: string; committed: boolean }>();
  private readonly mutations = new Map<string, number>();
  private mutationPending = false;
  private eventCursor?: number;
  private eventCheck?: Promise<void>;
  private readonly fill?: VaultMeshNativeFillBackground;
  private readonly capture: VaultMeshNativeCaptureBackground;
  private readonly passkeys: VaultMeshPasskeyProxy;
  private readonly emailWatch: EmailWatch;
  constructor(private readonly client = vaultMeshRpcClient, planner?: () => Pick<AutofillService, "generateFillScript">) {
    this.emailWatch = new EmailWatch(client, async () => { const generation = this.generation; await this.checkEvents(); return generation === this.generation && (await this.client.status()).unlocked; });
    this.passkeys = new VaultMeshPasskeyProxy(client, async () => {
      await this.checkEvents();
      return (await this.client.status()).unlocked;
    });
    this.capture = new VaultMeshNativeCaptureBackground(client, async () => {
      const generation = this.generation;
      await this.checkEvents();
      return (await this.client.status()).unlocked && generation === this.generation;
    });
    if (planner) this.fill = new VaultMeshNativeFillBackground(client, planner, async () => {
      const generation = this.generation;
      await this.checkEvents();
      return (await this.client.status()).unlocked && generation === this.generation;
    });
  }

  start(): void {
    this.emailWatch.start();
    this.qr.start();
    startPluginSecurity(() => this.handle({ kind: SESSION_MESSAGE, action: "lock" }));
    this.passkeys.start();
    this.editors.start();
    this.fill?.start();
    this.capture.start();
    this.client.onDisconnected(() => {
      this.emailWatch.cancel();
      this.qr.cancel();
      void this.passkeys.detach();
      this.cleanup.clear();
      this.fill?.cancel();
      this.capture.cancel();
      this.generation++;
      this.eventCursor = undefined;
      void sendSessionMessage({ kind: SESSION_INVALIDATED }).catch((): undefined => undefined);
    });
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (!this.trusted(sender)) return false;
      if (!isVaultMeshStatusMessage(message) && message?.kind !== SESSION_MESSAGE) return false;
      void this.handle(message, sender).then((response) => {
        try { sendResponse(response); }
        finally {
          // sendResponse clones synchronously; do not retain the privileged edit read.
          if (["email-candidates", "managed-item", "login-detail", "recovery-codes-view", "recovery-file-prepare"].includes(message?.action) && response && typeof response === "object" && "result" in response) {
            clearLoginSecrets(response.result);
          }
        }
      });
      return true;
    });
    this.client.start();
  }

  private trusted(sender: chrome.runtime.MessageSender): boolean {
    return this.editors.allows(sender) || (sender.id === chrome.runtime.id && sender.tab == null
      && sender.url?.split("#")[0] === chrome.runtime.getURL("popup/index.html"));
  }

  async handle(message: unknown, sender?: chrome.runtime.MessageSender): Promise<unknown> {
    if (isVaultMeshStatusMessage(message)) {
      try {
        await this.checkEvents();
        const vault = await this.client.status();
        await this.passkeys.sync(vault.unlocked);
        return { kind: VAULTMESH_STATUS_MESSAGE, status: vault.unlocked ? "ready" : "locked", vault, revision: this.generation, sessionId: this.sessionId };
      } catch (error) {
        void this.passkeys.detach();
        const code = error instanceof VaultMeshRpcError ? error.code : "unavailable";
        return {
          kind: VAULTMESH_STATUS_MESSAGE,
          status: code === "unpaired" ? "unpaired" : code === "unlock-required" ? "locked" : "unavailable",
        };
      }
    }
    const parsed = SessionMessageSchema.safeParse(message);
    if (!parsed.success) {
      this.clearInput(message);
      return { kind: SESSION_MESSAGE, ok: false, code: "invalid-message" };
    }
    const generation = this.generation;
    let ownsMutation = false;
    try {
      if ("mutationId" in parsed.data) {
        if (parsed.data.sessionId !== this.sessionId) throw new VaultMeshRpcError("operation-expired", "连接已重新建立。");
        const now = Date.now();
        for (const [id, expiry] of this.mutations) if (expiry <= now) this.mutations.delete(id);
        const expiry = Date.parse(parsed.data.expiresAt);
        if (expiry <= now || expiry > now + 60_000) throw new VaultMeshRpcError("operation-expired", "操作已过期。");
        if (this.mutations.has(parsed.data.mutationId)) throw new VaultMeshRpcError("duplicate-operation", "操作已处理。");
        if (this.mutationPending || this.mutations.size >= 128) throw new VaultMeshRpcError("operation-busy", "请等待当前操作完成。");
        this.mutations.set(parsed.data.mutationId, expiry);
        this.mutationPending = ownsMutation = true;
        await this.checkEvents();
        if (parsed.data.revision !== this.generation) throw new VaultMeshRpcError("operation-expired", "编辑会话已改变。");
      }
      let result: unknown;
      switch (parsed.data.action) {
        case "email-candidates": case "email-fill": {
          if (!this.fill || !sender || sender.tab || !this.trusted(sender)) throw new VaultMeshRpcError("invalid-message", "请使用工具栏。");
          const deadline = "expiresAt" in parsed.data ? Date.parse(parsed.data.expiresAt) : Date.now() + 30000;
          const current = async () => { await this.checkEvents(); return generation === this.generation && Date.now() < deadline && (await this.client.status()).unlocked; };
          result = parsed.data.action === "email-candidates" ? await this.fill.emailCandidates(current)
            : await this.fill.fillEmail(parsed.data.candidateId, current, { tabId: parsed.data.tabId, url: parsed.data.url });
          break;
        }
        case "passkey-management": {
          const expiresAt = Date.parse(parsed.data.expiresAt);
          result = await this.client.managePasskeys(parsed.data.command, () => generation === this.generation && Date.now() < expiresAt);
          if (parsed.data.command.verb === "list") await this.checkEvents();
          break;
        }
        case "qr-authorize": {
          if (!sender || sender.tab || !this.trusted(sender)) throw new VaultMeshRpcError("invalid-message", "仅允许工具栏扫描当前页面。");
          const expiresAt = Date.parse(parsed.data.expiresAt);
          result = await this.qr.authorize(async () => {
            await this.checkEvents();
            return generation === this.generation && Date.now() < expiresAt && (await this.client.status()).unlocked;
          });
          break;
        }
        case "security-tool": {
          const expiresAt = Date.parse(parsed.data.expiresAt);
          result = await this.client.securityTool(parsed.data.command, () => generation === this.generation && Date.now() < expiresAt);
          if (parsed.data.command.operation === "browser.pairing.revoke") { this.cleanup.clear(); this.fill?.cancel(); this.capture.cancel(); void this.passkeys.detach(); }
          break;
        }
        case "managed-item": {
          const expiresAt = Date.parse(parsed.data.expiresAt);
          result = await this.client.managedItem(parsed.data.command, () => generation === this.generation && Date.now() < expiresAt);
          if (["list", "detail", "trash", "history"].includes(parsed.data.command.verb)) await this.checkEvents();
          break;
        }
        case "editor-open":
          if (!sender || sender.tab || !this.trusted(sender)) throw new VaultMeshRpcError("invalid-message", "仅允许工具栏打开编辑窗口。");
          await this.editors.open(); break;
        case "editor-context": result = { independent: !!sender && this.editors.allows(sender) }; break;
        case "recovery-file-discard":
          if (sender && this.editors.allows(sender) && this.cleanup.get(parsed.data.cleanupId)?.tabId === sender.tab?.id) this.cleanup.delete(parsed.data.cleanupId);
          break;
        case "recovery-file-prepare":
        case "recovery-file-finish": {
          if (!sender || !this.editors.allows(sender)) throw new VaultMeshRpcError("invalid-message", "请使用独立编辑窗口。");
          const deadline = Math.min(Date.parse(parsed.data.expiresAt), Date.now() + 45_000);
          const current = () => generation === this.generation && this.editors.allows(sender) && Date.now() < deadline;
          for (const [id, value] of this.cleanup) if (value.expiresAt <= Date.now()) this.cleanup.delete(id);
          if (parsed.data.action === "recovery-file-finish") {
            const entry = this.cleanup.get(parsed.data.cleanupId);
            if (!entry?.committed || entry.tabId !== sender.tab?.id) throw new VaultMeshRpcError("operation-expired", "尚未确认保存，不能删除源文件。");
            this.cleanup.delete(parsed.data.cleanupId);
          } else if (this.cleanup.size >= 4) throw new VaultMeshRpcError("operation-busy", "待完成导入过多。");
          result = parsed.data.action === "recovery-file-prepare" ? await this.client.prepareRecoveryFile(current)
            : await this.client.finishRecoveryFile(parsed.data.cleanupId, current);
          if (parsed.data.action === "recovery-file-prepare") {
            const prepared = PreparedBrowserRecoveryFileSchema.parse(result);
            try {
              const digest = await codesDigest(prepared.codes);
              if (current() && prepared.cleanup.expiresAt > Date.now() && prepared.cleanup.expiresAt <= Date.now() + 300000) {
                this.cleanup.set(prepared.cleanup.id, { tabId: sender.tab!.id!, expiresAt: prepared.cleanup.expiresAt, digest, committed: false });
              } else { clearLoginSecrets(result); throw new VaultMeshRpcError("operation-expired", "导入已过期。"); }
            } catch (error) { clearLoginSecrets(result); throw error; }
            finally { clearLoginSecrets(prepared); }
          }
          try { await this.checkEvents(); await this.editors.focus(sender); }
          catch (error) { clearLoginSecrets(result); throw error; }
          if (!current()) { clearLoginSecrets(result); throw new VaultMeshRpcError("operation-expired", "文件对话框已失效。"); }
          break;
        }
        case "cancel-fill": this.generation++; this.qr.cancel(); this.fill?.cancel(); break;
        case "logins": result = await this.client.logins(); break;
        case "login-trash": result = await this.client.loginTrash(); await this.checkEvents(); break;
        case "login-history": result = await this.client.loginHistory(parsed.data.id); await this.checkEvents(); break;
        case "login-recovery": await this.client.recoverLogin(parsed.data.command, () => generation === this.generation); break;
        case "fill-context": result = await this.fill?.contexts() ?? []; break;
        case "login-detail":
          result = await this.client.loginDetail(parsed.data.id);
          try { await this.checkEvents(); }
          catch (error) { clearLoginSecrets(result); throw error; }
          break;
        case "login-save": {
          const entry = parsed.data.cleanupId ? this.cleanup.get(parsed.data.cleanupId) : undefined;
          if (parsed.data.cleanupId && (!sender || !this.editors.allows(sender) || !entry || entry.committed
            || entry.tabId !== sender.tab?.id || entry.expiresAt <= Date.now() || !parsed.data.input.recoveryCodes
            || entry.digest !== await codesDigest(parsed.data.input.recoveryCodes))) throw new VaultMeshRpcError("invalid-request", "导入内容已改变，请保留源文件。");
          result = await this.client.saveLogin(parsed.data.input);
          if (entry && generation === this.generation) entry.committed = true;
          break;
        }
        case "login-copy": result = await this.client.copyLogin(parsed.data.id, parsed.data.field, parsed.data.masterPassword); break;
        case "recovery-codes-view":
          result = await this.client.recoveryCodes(parsed.data.id, parsed.data.masterPassword);
          try { await this.checkEvents(); } catch (error) { clearLoginSecrets(result); throw error; }
          break;
        case "recovery-code-copy": result = await this.client.copyRecoveryCode(parsed.data.id, parsed.data.index, parsed.data.masterPassword); break;
        case "login-delete": await this.client.deleteLogin(parsed.data.id, () => generation === this.generation); break;
        case "item-fill":
        case "login-fill":
          if (!this.fill) throw new VaultMeshRpcError("unsupported-operation", "填充引擎尚未就绪。");
          result = await this.fill.fill(parsed.data.id, parsed.data.masterPassword, async () => {
            await this.checkEvents();
            const status = await this.client.status();
            return status.unlocked && generation === this.generation;
          }, parsed.data.frame, parsed.data.action === "item-fill" ? parsed.data.itemKind : "login");
          break;
        case "unlock": await this.client.unlock(parsed.data.masterPassword); break;
        case "lock":
          this.emailWatch.cancel();
          this.qr.cancel();
          void this.passkeys.detach();
          this.cleanup.clear();
          this.fill?.cancel();
          this.capture.cancel();
          this.generation++;
          void sendSessionMessage({ kind: SESSION_INVALIDATED }).catch((): undefined => undefined);
          await this.client.lock();
          break;
      }
      if (parsed.data.action !== "lock" && generation !== this.generation) {
        clearLoginSecrets(result);
        throw new VaultMeshRpcError(ownsMutation ? "execution-unknown" : "operation-expired", "会话已失效。");
      }
      return { kind: SESSION_MESSAGE, ok: true, result: result ?? null };
    } catch (error) {
      return { kind: SESSION_MESSAGE, ok: false, code: error instanceof VaultMeshRpcError ? error.code : "invalid-broker-response" };
    } finally {
      if (ownsMutation) this.mutationPending = false;
      this.clearInput(parsed.data);
      this.clearInput(message);
    }
  }

  private clearInput(message: unknown): void {
    clearLoginSecrets(message);
    if (message && typeof message === "object" && "input" in message) clearLoginSecrets(message.input);
  }

  private async checkEvents(): Promise<void> {
    if (this.eventCheck) return this.eventCheck;
    const generation = this.generation;
    this.eventCheck = (async () => {
      const result = await this.client.events(this.eventCursor ?? 0);
      if (generation !== this.generation) return;
      // Any broker event invalidates an edit snapshot, including a lock/unlock
      // cycle or a LAN merge that finishes between two status polls.
      if (this.eventCursor !== undefined && result.sequence !== this.eventCursor) {
        this.emailWatch.cancel();
        this.qr.cancel();
        if (result.events.some((event) => ["vault-locked", "pairing-revoked", "desktop-shutdown"].includes(event.type))
          || result.sequence - this.eventCursor > 32) { this.cleanup.clear(); void this.passkeys.detach(); }
        this.generation++;
        this.fill?.cancel();
        this.capture.cancel();
      }
      this.eventCursor = result.sequence;
    })();
    try { await this.eventCheck; }
    finally { this.eventCheck = undefined; }
  }
}
