import { ChangeDetectionStrategy, Component, DestroyRef, OnDestroy, OnInit, computed, inject, signal } from "@angular/core";
import { takeUntilDestroyed, toSignal } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { ButtonModule, FormFieldModule, ItemModule } from "@bitwarden/components";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import { loginSummaryView } from "./login-view";
import { LoginDraft } from "./login-draft";
import { clearLoginSecrets, type LoginSave } from "./login-contracts";
import { VaultMeshLoginEditorComponent } from "./login-editor.component";
import type { FillFrame } from "./contracts";
import type { LoginTrash, LoginHistory, LoginRecoveryCommand } from "./recovery-contracts";
import type { RecoveryFileCleanup } from "./vendor/browser-recovery-file";
import { VaultMeshManagedItemsComponent } from "./managed-items.component";
import { MANAGED_ITEMS, type ManagedKind } from "./managed-items";
import { VaultMeshSecurityToolsComponent } from "./security-tools.component";
import { VaultMeshGeneratorComponent } from "./generator.component";
import { VaultMeshVaultLifecycleComponent } from "./vault-lifecycle.component";
import { clearQr, type TotpQr } from "./qr-contracts";
import { collectQr } from "./qr-popup";
import type { PasskeyRows } from "./passkey-management";
import { clearEmail, type EmailPopup } from "./email-otp";

@Component({
  selector: "vaultmesh-session",
  templateUrl: "./session.component.html",
  imports: [FormsModule, ButtonModule, FormFieldModule, ItemModule, VaultMeshLoginEditorComponent, VaultMeshManagedItemsComponent, VaultMeshSecurityToolsComponent, VaultMeshGeneratorComponent, VaultMeshVaultLifecycleComponent],
  providers: [VaultMeshBrowserRpcService],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: "tw-block tw-h-full" },
})
export class VaultMeshSessionComponent implements OnInit, OnDestroy {
  private readonly destroyRef = inject(DestroyRef);
  protected readonly session = inject(VaultMeshBrowserRpcService);
  protected readonly state = toSignal(this.session.state$, { requireSync: true });
  protected password = "";
  protected readonly query = signal("");
  protected readonly surface = signal<"login" | "tools" | "generator" | "vault" | ManagedKind>("login");
  protected readonly managedTabs = Object.entries(MANAGED_ITEMS).map(([kind, value]) => ({ kind: kind as ManagedKind, label: value.label }));
  protected readonly managedSurface = computed(() => ["login", "tools", "generator", "vault"].includes(this.surface()) ? [] : [this.surface() as ManagedKind]);
  protected showSurface(surface: "login" | "tools" | "generator" | "vault" | ManagedKind): void {
    if (this.state().busy) return;
    this.closeEditor(); this.surface.set(surface);
  }
  protected readonly draft = signal<LoginDraft | null>(null);
  protected readonly independentEditor = signal(false);
  protected readonly fileDialogActive = signal(false);
  protected readonly savedSource = signal<{ cleanup: RecoveryFileCleanup; fileName: string } | null>(null);
  private importedSource?: { cleanup: RecoveryFileCleanup; fileName: string; codes: string[] };
  private dialogDeadline = 0;
  private dialogTimer?: ReturnType<typeof setTimeout>;
  private dialogAbort?: AbortController;
  private lifetime = 0;
  protected readonly deleteTarget = signal<{ id: string; title: string } | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly recovery = signal<{ title: string; itemId?: string; trash: LoginTrash; history: LoginHistory } | null>(null);
  protected readonly recoveryTarget = signal<{ command: LoginRecoveryCommand; title: string; destructive: boolean } | null>(null);
  protected readonly codesTarget = signal<{ id: string; title: string; index?: number } | null>(null);
  protected readonly codesView = signal<{ id: string; title: string; codes: string[] } | null>(null);
  protected readonly fillTarget = signal<{ id: string; title: string; reprompt: boolean } | null>(null);
  protected readonly copyTarget = signal<{ id: string; title: string; field: "username" | "password" | "totp"; reprompt: boolean } | null>(null);
  protected fillPassword = "";
  protected readonly fillFrames = signal<FillFrame[]>([]);
  protected fillFrameIndex = "";
  private editorGeneration = 0;
  protected readonly qrCandidates = signal<TotpQr[]>([]);
  protected readonly passkeyRows = signal<{ loginId: string; title: string; rows: PasskeyRows } | null>(null);
  protected readonly email = signal<EmailPopup | null>(null);
  private readonly pageNavigated = (event: { tabId: number; frameId: number }) => {
    if (this.email()?.tabId === event.tabId && event.frameId === 0) this.closeEditor();
    if (this.qrScanning() || this.qrCandidates().length) this.clearQrCandidates();
  };
  protected async openEmail(): Promise<void> {
    if (this.independentEditor() || this.state().busy || this.state().status !== "ready") return;
    this.closeEditor(); this.surface.set("login"); this.armEditorExpiry(30000); const generation = this.editorGeneration;
    const result = await this.session.emailCandidates();
    if (result.ok === false) { if (generation === this.editorGeneration) this.showError(result.code); return; }
    if (generation !== this.editorGeneration) { clearEmail(result.value); return; }
    result.value.candidates = result.value.candidates.filter((row) => row.expiresAt * 1000 > Date.now());
    this.email.set(result.value);
    if (result.value.candidates.length) { if (this.editorTimer) clearTimeout(this.editorTimer); this.armEditorExpiry(Math.min(30000, ...result.value.candidates.map((row) => row.expiresAt * 1000 - Date.now()))); }
  }
  protected async fillEmail(id: string): Promise<void> {
    const email = this.email(); const candidate = email?.candidates.find((row) => row.id === id);
    if (!email || !candidate || candidate.expiresAt * 1000 <= Date.now() || this.state().busy || Date.now() >= this.editorDeadline) return;
    const { tabId, url } = email; this.closeEditor();
    const result = await this.session.fillEmail(id, tabId, url);
    if (result.ok === false) this.showError(result.code); else this.notice.set(`已填入 ${result.value.filled} 个空验证码字段，未提交表单。`);
  }
  protected readonly passkeyDelete = signal<{ loginId: string; id: string; title: string } | null>(null);

  protected async openPasskeys(loginId: string): Promise<void> {
    if (this.state().busy || this.state().status !== "ready") return;
    const item = this.state().logins.find((row) => row.id === loginId); if (!item) return;
    this.closeEditor(); this.armEditorExpiry(300000); const generation = this.editorGeneration;
    const result = await this.session.managePasskeys({ verb: "list", loginId });
    if (generation !== this.editorGeneration) return;
    if (result.ok === true && result.value) this.passkeyRows.set({ loginId, title: item.title, rows: result.value });
    else if (result.ok === false) this.showError(result.code);
  }
  protected requestPasskeyDelete(id: string): void {
    const owner = this.passkeyRows(); const row = owner?.rows.find((row) => row.id === id);
    if (!owner || !row || this.state().busy || Date.now() >= this.editorDeadline) return;
    this.closeEditor(); this.passkeyDelete.set({ loginId: owner.loginId, id, title: row.title }); this.armEditorExpiry(30000);
  }
  protected async confirmPasskeyDelete(): Promise<void> {
    const target = this.passkeyDelete(); if (!target || this.state().busy || Date.now() >= this.editorDeadline) return;
    this.closeEditor();
    const result = await this.session.managePasskeys({ verb: "delete", loginId: target.loginId, id: target.id, confirmed: true });
    if (result.ok === false) this.showError(result.code); else this.notice.set("Passkey 已删除；网站端的注册记录不会自动删除。");
  }
  protected readonly qrScanning = signal(false);
  protected qrOverwrite = false;
  private qrGeneration = 0;
  private qrDeadline = 0;
  private qrTimer?: ReturnType<typeof setTimeout>;

  protected clearQrCandidates(): void {
    this.qrGeneration++; clearQr(this.qrCandidates()); this.qrCandidates.set([]); this.qrOverwrite = false; this.qrScanning.set(false);
    if (this.qrTimer) clearTimeout(this.qrTimer); this.qrTimer = undefined;
  }
  protected async scanQr(): Promise<void> {
    const draft = this.draft();
    if (!draft || this.independentEditor() || this.state().busy || this.qrScanning() || Date.now() >= this.editorDeadline) return;
    this.clearQrCandidates(); const generation = this.qrGeneration; const editor = this.editorGeneration;
    this.qrDeadline = Math.min(this.editorDeadline, Date.now() + 30000);
    const current = () => generation === this.qrGeneration && editor === this.editorGeneration && this.draft() === draft
      && this.state().status === "ready" && !document.hidden && Date.now() < this.qrDeadline;
    this.qrScanning.set(true); this.qrTimer = setTimeout(() => this.clearQrCandidates(), Math.max(1, this.qrDeadline - Date.now()));
    try {
      const result = await this.session.authorizeQr();
      if (!current()) return;
      if (result.ok === false) { this.showError(result.code); return; }
      const values = await collectQr(result.value, current);
      if (!current()) { clearQr(values); return; }
      this.qrCandidates.set(values);
      this.notice.set(values.length ? "请选择二维码候选；不会自动保存或覆盖已有密钥。" : "当前可见页面没有可读取的受支持 TOTP 二维码（SHA-1 / 6 位 / 30 秒）。");
    } catch { if (current()) this.notice.set("二维码扫描失败，请确认当前页面可访问后重试。"); }
    finally { if (generation === this.qrGeneration) this.qrScanning.set(false); }
  }
  protected applyQr(index: number): void {
    const value = this.qrCandidates()[index]; const draft = this.draft();
    if (!value || !draft || this.state().busy || Date.now() >= this.qrDeadline || Date.now() >= this.editorDeadline) { this.clearQrCandidates(); return; }
    if ((draft.hasTotpSecret || draft.cipher.login.totp) && !this.qrOverwrite) return;
    draft.cipher.login.totp = value.uri; draft.clearTotpSecret = false;
    this.clearQrCandidates(); this.notice.set("身份验证器密钥已写入当前草稿，保存后才生效。");
  }
  private editorDeadline = 0;
  private editorTimer?: ReturnType<typeof setTimeout>;
  protected readonly rows = computed(() => {
    const query = this.query().trim().toLocaleLowerCase();
    return this.state().logins
      .filter((item) => !query || [item.title, item.username, item.url ?? ""].some((v) => v.toLocaleLowerCase().includes(query)))
      .map(loginSummaryView);
  });
  private readonly clearInput = () => { this.password = ""; this.query.set(""); this.closeEditor(); };

  ngOnInit(): void {
    chrome.webNavigation.onCommitted.addListener(this.pageNavigated); chrome.webNavigation.onHistoryStateUpdated.addListener(this.pageNavigated); chrome.webNavigation.onReferenceFragmentUpdated.addListener(this.pageNavigated);
    let revision: number | undefined;
    let sessionId: string | undefined;
    this.session.state$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((state) => {
      if (revision !== undefined && revision !== state.revision) this.closeEditor();
      if (sessionId !== undefined && sessionId !== state.sessionId) this.closeEditor();
      revision = state.revision;
      sessionId = state.sessionId;
      if (state.status !== "locked") this.password = "";
      if (state.status !== "ready") { this.query.set(""); this.closeEditor(); }
    });
    this.session.start();
    if (new URLSearchParams(location.search).has("editor")) {
      const lifetime = this.lifetime;
      void this.session.editorContext().then((independent) => { if (lifetime === this.lifetime) this.independentEditor.set(independent); });
    }
    window.addEventListener("pagehide", this.onPageHide);
    window.addEventListener("pageshow", this.onPageShow);
    window.addEventListener("blur", this.onWindowBlur);
    document.addEventListener("visibilitychange", this.onVisibilityChange);
  }

  protected newLogin(): void {
    if (this.state().busy || this.state().status !== "ready") return;
    this.closeEditor();
    this.notice.set(null);
    this.draft.set(new LoginDraft());
    this.armEditorExpiry(5 * 60_000);
  }

  protected async editLogin(id: string): Promise<void> {
    if (this.state().busy || this.state().status !== "ready") return;
    this.closeEditor();
    this.notice.set(null);
    const generation = this.editorGeneration;
    const result = await this.session.editLogin(id);
    try {
      if (generation !== this.editorGeneration) return;
      if (result.ok === false) { this.showError(result.code); return; }
      this.draft.set(new LoginDraft(result.value));
      this.armEditorExpiry(5 * 60_000);
    } finally {
      if (result.ok) clearLoginSecrets(result.value);
    }
  }

  protected async saveLogin(): Promise<void> {
    const draft = this.draft();
    if (!draft || this.state().busy || this.state().status !== "ready") return;
    if (Date.now() >= this.editorDeadline) { this.expireEditor(); return; }
    let input: LoginSave;
    try { input = draft.toInput(); }
    catch { this.notice.set("请检查名称、字段长度、密码和恢复码格式后重试。"); return; }
    const imported = this.importedSource;
    const cleanup = imported && imported.cleanup.expiresAt > Date.now() && !input.clearRecoveryCodes
      && JSON.stringify(input.recoveryCodes) === JSON.stringify(imported.codes)
      ? { cleanup: { ...imported.cleanup }, fileName: imported.fileName } : undefined;
    const lifetime = this.lifetime;
    this.closeEditor(cleanup?.cleanup.id);
    this.notice.set(null);
    const result = cleanup ? await this.session.saveLogin(input, cleanup.cleanup.id) : await this.session.saveLogin(input);
    if (lifetime !== this.lifetime) return;
    if (result.ok === true) {
      this.notice.set("登录信息已保存。" + (imported && !cleanup ? "导入内容已改变或清理期限已过，源文件保持不变。" : ""));
      if (cleanup && this.independentEditor() && cleanup.cleanup.expiresAt > Date.now() && this.state().status === "ready") {
        this.savedSource.set(cleanup);
        this.armEditorExpiry(Math.min(30000, cleanup.cleanup.expiresAt - Date.now()));
      }
    }
    else this.showError(result.code);
  }

  protected requestDelete(): void {
    const draft = this.draft();
    if (!draft?.cipher.id || this.state().busy) return;
    if (Date.now() >= this.editorDeadline) { this.expireEditor(); return; }
    const target = { id: draft.cipher.id, title: draft.cipher.name };
    this.closeEditor();
    this.deleteTarget.set(target);
    this.armEditorExpiry(30_000);
  }

  protected async confirmDelete(): Promise<void> {
    const target = this.deleteTarget();
    if (!target || this.state().busy || this.state().status !== "ready") return;
    if (Date.now() >= this.editorDeadline) { this.expireEditor(); return; }
    this.closeEditor();
    this.notice.set(null);
    const result = await this.session.deleteLogin(target.id);
    if (result.ok === true) this.notice.set("登录信息已移至回收站，可从插件回收站恢复。");
    else this.showError(result.code);
  }

  protected closeEditor(preserveCleanupId?: string): void {
    this.clearQrCandidates();
    this.passkeyRows.set(null); this.passkeyDelete.set(null);
    clearEmail(this.email()); this.email.set(null);
    const cancelDialog = this.fileDialogActive();
    this.endFileDialog();
    this.editorGeneration++;
    if (this.editorTimer) clearTimeout(this.editorTimer);
    this.editorTimer = undefined;
    this.editorDeadline = 0;
    this.draft()?.clear();
    this.draft.set(null);
    for (const id of new Set([this.importedSource?.cleanup.id, this.savedSource()?.cleanup.id])) {
      if (id && id !== preserveCleanupId) this.session.discardRecoveryFile(id);
    }
    if (this.importedSource) clearLoginSecrets(this.importedSource);
    this.importedSource = undefined;
    this.savedSource.set(null);
    this.deleteTarget.set(null);
    this.fillTarget.set(null);
    this.copyTarget.set(null);
    this.recovery.set(null);
    this.recoveryTarget.set(null);
    this.codesTarget.set(null);
    const codes = this.codesView();
    if (codes) clearLoginSecrets(codes);
    this.codesView.set(null);
    this.fillPassword = "";
    this.fillFrames.set([]);
    this.fillFrameIndex = "";
    if (cancelDialog) this.session.cancelFileDialog();
  }

  protected async openEditorWindow(): Promise<void> {
    if (this.state().busy || this.independentEditor()) return;
    if (this.draft()) { this.notice.set("请先保存或取消当前草稿，再打开独立编辑窗口；草稿不会跨窗口迁移。"); return; }
    const result = await this.session.openEditorWindow();
    if (result.ok === false) this.showError(result.code);
  }

  protected async importRecoveryFile(): Promise<void> {
    const draft = this.draft();
    if (!draft || !this.independentEditor() || this.state().busy || this.state().status !== "ready") return;
    if (Date.now() >= this.editorDeadline) { this.expireEditor(); return; }
    this.notice.set(null);
    const generation = this.editorGeneration;
    const abort = this.beginFileDialog(Math.min(this.editorDeadline, Date.now() + 45000));
    const result = await this.session.prepareRecoveryFile();
    try {
      if (generation !== this.editorGeneration || abort.aborted) return;
      if (result.ok === false) { this.closeEditor(); this.showError(result.code); return; }
      if (!await this.waitForVisibleEditor(abort) || generation !== this.editorGeneration) return;
      if (result.value.cleanup.expiresAt <= Date.now()) { this.closeEditor(); return; }
      if (this.importedSource) {
        this.session.discardRecoveryFile(this.importedSource.cleanup.id);
        clearLoginSecrets(this.importedSource);
      }
      this.importedSource = { cleanup: { ...result.value.cleanup }, fileName: result.value.fileName, codes: [...result.value.codes] };
      draft.recoveryCodes = result.value.codes.join("\n");
      draft.clearRecoveryCodes = false;
      this.notice.set(`已导入 ${result.value.codes.length} 个恢复码，源文件仍保留。保存成功后可询问删除。`);
    } finally {
      if (result.ok === true) clearLoginSecrets(result.value);
      if (this.dialogAbort?.signal === abort) {
        this.endFileDialog();
        if (document.hidden) this.closeEditor();
      }
    }
  }

  protected async finishSourceCleanup(): Promise<void> {
    const source = this.savedSource();
    if (!source || !this.independentEditor() || this.state().busy || this.state().status !== "ready") return;
    if (Date.now() >= source.cleanup.expiresAt || Date.now() >= this.editorDeadline) { this.expireEditor(); return; }
    this.closeEditor(source.cleanup.id);
    const lifetime = this.lifetime;
    const abort = this.beginFileDialog(Math.min(source.cleanup.expiresAt, Date.now() + 45000));
    const result = await this.session.finishRecoveryFile(source.cleanup.id);
    const cancelled = abort.aborted;
    if (this.dialogAbort?.signal === abort) this.endFileDialog();
    if (lifetime !== this.lifetime || cancelled) return;
    if (result.ok === false) { this.showError(result.code); return; }
    this.notice.set(result.value.sourceFileStatus === "deleted" ? "已保存登录信息，并按原生确认删除源文件；删除不是安全擦除。"
      : result.value.sourceFileStatus === "kept" ? "源文件已保留。" : "源文件未删除，请检查文件是否发生变化或已被移动。");
  }

  private beginFileDialog(deadline: number): AbortSignal {
    this.endFileDialog();
    this.dialogDeadline = deadline;
    this.dialogAbort = new AbortController();
    this.fileDialogActive.set(true);
    this.dialogTimer = setTimeout(() => { this.closeEditor(); this.notice.set("文件操作已超时，草稿已清除；未完成保存的源文件保持不变。"); }, Math.max(0, deadline - Date.now()));
    return this.dialogAbort.signal;
  }

  private endFileDialog(): void {
    this.fileDialogActive.set(false);
    this.dialogAbort?.abort(); this.dialogAbort = undefined;
    if (this.dialogTimer) clearTimeout(this.dialogTimer);
    this.dialogTimer = undefined; this.dialogDeadline = 0;
  }

  private waitForVisibleEditor(signal: AbortSignal): Promise<boolean> {
    if (signal.aborted) return Promise.resolve(false);
    if (!document.hidden) return Promise.resolve(true);
    return new Promise((resolve) => {
      const complete = (visible: boolean) => { document.removeEventListener("visibilitychange", changed); signal.removeEventListener("abort", cancelled); resolve(visible); };
      const changed = () => { if (!document.hidden) complete(true); };
      const cancelled = () => complete(false);
      document.addEventListener("visibilitychange", changed); signal.addEventListener("abort", cancelled, { once: true });
    });
  }

  protected requestFill(id: string): void {
    if (this.state().busy || this.state().status !== "ready") return;
    const item = this.state().logins.find((entry) => entry.id === id);
    if (!item) return;
    this.closeEditor();
    this.notice.set(null);
    this.fillTarget.set({ id, title: item.title, reprompt: item.masterPasswordReprompt });
    this.armEditorExpiry(30_000);
    const generation = this.editorGeneration;
    void this.session.fillContexts().then((result) => {
      if (generation === this.editorGeneration && result.ok) this.fillFrames.set(result.value);
    });
  }

  protected async openRecovery(itemId?: string): Promise<void> {
    if (this.state().busy || this.state().status !== "ready") return;
    const item = itemId ? this.state().logins.find((entry) => entry.id === itemId) : undefined;
    if (itemId && !item) return;
    this.closeEditor(); this.notice.set(null);
    const generation = this.editorGeneration;
    if (itemId) {
      const result = await this.session.loginHistory(itemId);
      if (generation !== this.editorGeneration) return;
      if (result.ok === false) { this.showError(result.code); return; }
      this.recovery.set({ title: `${item!.title} · 历史版本`, itemId, trash: [], history: result.value });
    } else {
      const result = await this.session.loginTrash();
      if (generation !== this.editorGeneration) return;
      if (result.ok === false) { this.showError(result.code); return; }
      this.recovery.set({ title: "登录回收站", trash: result.value, history: [] });
    }
    this.armEditorExpiry(5 * 60_000);
  }

  protected requestRecovery(command: LoginRecoveryCommand, title: string): void {
    const current = this.recovery();
    if (!current || this.state().busy || Date.now() >= this.editorDeadline) return;
    const valid = command.operation === "items.trash.restore" ? current.trash.some((row) => row.trashId === command.trashId && row.itemId === command.itemId)
      : command.operation === "items.trash.purge" ? current.trash.some((row) => row.trashId === command.trashId)
      : command.operation === "items.trash.empty" ? !current.itemId && current.trash.length > 0
      : command.operation === "items.history.restore" ? current.itemId === command.itemId && current.history.some((row) => row.revisionId === command.revisionId)
      : current.itemId === command.id && current.history.length > 0;
    if (!valid) return;
    this.closeEditor();
    this.recoveryTarget.set({ command, title, destructive: !command.operation.endsWith("restore") });
    this.armEditorExpiry(30_000);
  }

  protected async confirmRecovery(): Promise<void> {
    const target = this.recoveryTarget();
    if (!target || this.state().busy || this.state().status !== "ready") return;
    if (Date.now() >= this.editorDeadline) { this.expireEditor(); return; }
    this.closeEditor(); this.notice.set(null);
    const result = await this.session.recoverLogin(target.command);
    if (result.ok === true) this.notice.set(target.destructive ? "清理已完成，已刷新登录列表。" : "恢复已完成，已刷新登录列表。");
    else this.showError(result.code);
  }

  protected displayTime(value: number): string { return new Date(value).toLocaleString(); }

  protected requestCodes(id: string, index?: number): void {
    if (this.state().busy || this.state().status !== "ready") return;
    const item = this.state().logins.find((entry) => entry.id === id);
    if (!item?.hasRecoveryCodes) return;
    if (index !== undefined && (this.codesView()?.id !== id || !Number.isInteger(index) || index < 0 || index >= this.codesView()!.codes.length)) return;
    this.closeEditor(); this.notice.set(null);
    this.codesTarget.set({ id, title: item.title, ...(index !== undefined ? { index } : {}) });
    this.armEditorExpiry(30_000);
  }

  protected hasRecoveryCodes(id: string): boolean { return this.state().logins.some((item) => item.id === id && item.hasRecoveryCodes); }

  protected async confirmCodes(): Promise<void> {
    const target = this.codesTarget();
    if (!target || this.state().busy || this.state().status !== "ready" || this.fillPassword.length < 8) return;
    if (Date.now() >= this.editorDeadline) { this.expireEditor(); return; }
    let password = this.fillPassword;
    this.closeEditor(); this.notice.set(null);
    const generation = this.editorGeneration;
    try {
      if (target.index !== undefined) {
        const result = await this.session.copyRecoveryCode(target.id, target.index, password);
        if (generation !== this.editorGeneration) return;
        if (result.ok === true) this.notice.set("桌面端已复制恢复码，并按安全设置自动清除剪贴板。");
        else this.showError(result.code);
      } else {
        const result = await this.session.recoveryCodes(target.id, password);
        try {
          if (generation !== this.editorGeneration) return;
          if (result.ok === false) { this.showError(result.code); return; }
          this.codesView.set({ id: target.id, title: target.title, codes: [...result.value.codes] });
          this.armEditorExpiry(30_000);
        } finally { if (result.ok === true) clearLoginSecrets(result.value); }
      }
    } finally { password = ""; }
  }

  protected requestCopy(id: string, field: "username" | "password" | "totp"): void {
    if (this.state().busy || this.state().status !== "ready") return;
    const item = this.state().logins.find((entry) => entry.id === id);
    if (!item || (field === "password" && !item.hasPassword) || (field === "totp" && !item.hasTotpSecret)) return;
    this.closeEditor(); this.notice.set(null);
    this.copyTarget.set({ id, field, title: item.title, reprompt: field !== "username" && item.masterPasswordReprompt });
    this.armEditorExpiry(30_000);
  }

  protected canCopy(id: string, field: "username" | "password" | "totp"): boolean {
    const item = this.state().logins.find((entry) => entry.id === id);
    return !!item && (field === "username" ? !!item.username : field === "password" ? item.hasPassword : item.hasTotpSecret);
  }

  protected async confirmCopy(): Promise<void> {
    const target = this.copyTarget();
    if (!target || this.state().busy || this.state().status !== "ready") return;
    if (Date.now() >= this.editorDeadline) { this.expireEditor(); return; }
    let password = this.fillPassword;
    this.closeEditor();
    const result = await this.session.copyLogin(target.id, target.field, password || undefined);
    password = "";
    if (result.ok === true) this.notice.set("桌面端已复制到系统剪贴板，并按安全设置自动清除。");
    else this.showError(result.code);
  }

  protected async confirmFill(): Promise<void> {
    const target = this.fillTarget();
    if (!target || this.state().busy || this.state().status !== "ready") return;
    if (Date.now() >= this.editorDeadline) { this.expireEditor(); return; }
    let password = this.fillPassword;
    const frame = this.fillFrameIndex === "" ? undefined : this.fillFrames()[Number(this.fillFrameIndex)];
    if (this.fillFrameIndex !== "" && !frame) return;
    this.closeEditor();
    const result = await this.session.fillLogin(target.id, password || undefined, frame);
    password = "";
    if (result.ok === false) { this.showError(result.code); return; }
    this.notice.set(result.value.filled > 0
      ? `已填入 ${result.value.filled} 个字段，未提交表单。${result.value.auditRecorded ? "" : "填充记录未保存，请勿因此重复填充。"}`
      : "没有字段完成填充。页面可能已变化，请重新选择。");
  }

  private armEditorExpiry(duration: number): void {
    this.editorDeadline = Date.now() + duration;
    this.editorTimer = setTimeout(() => this.expireEditor(), duration);
  }

  private expireEditor(): void {
    this.closeEditor();
    this.notice.set("编辑或确认已过期，请重新打开登录信息。");
  }

  private showError(code: string): void {
    this.notice.set(code === "execution-unknown"
      ? "尚未确认操作结果。请重新连接并刷新列表，检查后再决定是否重试。"
      : code === "operation-expired" ? "操作已过期，请重新打开登录信息。"
      : code === "operation-busy" || code === "duplicate-operation" ? "该操作正在处理或已处理，请刷新后检查。"
      : code === "no-fillable-fields" ? "当前目标没有可安全填充的登录字段；跨源内嵌页面请在确认页显式选择。"
      : code === "insecure-page" ? "已保存的 HTTPS 登录不能在此 HTTP 页面披露。"
      : code === "re-prompt-required" ? "此条目需要输入当前主密码确认填充。"
      : code === "page-unavailable" ? "当前页面无法填充，请刷新普通网页后重试。"
      : "操作未完成，请检查连接、解锁状态或输入内容后重试。");
  }

  protected async unlock(): Promise<void> {
    let password = this.password;
    this.password = "";
    try { await this.session.unlock(password); }
    finally { password = ""; }
  }

  protected lock(): void {
    this.clearInput();
    void this.session.lock();
  }

  private readonly onPageHide = () => {
    this.lifetime++;
    this.clearInput();
    this.session.ngOnDestroy();
  };
  private readonly onPageShow = () => this.session.start();
  private readonly onWindowBlur = () => {
    if (this.independentEditor() && !(this.fileDialogActive() && Date.now() < this.dialogDeadline)) { this.session.cancelManaged(); this.clearInput(); }
  };
  private readonly onVisibilityChange = () => {
    if (document.hidden && this.independentEditor() && this.fileDialogActive() && Date.now() < this.dialogDeadline) return;
    if (document.hidden) this.onPageHide();
    else this.onPageShow();
  };

  ngOnDestroy(): void {
    chrome.webNavigation.onCommitted.removeListener(this.pageNavigated); chrome.webNavigation.onHistoryStateUpdated.removeListener(this.pageNavigated); chrome.webNavigation.onReferenceFragmentUpdated.removeListener(this.pageNavigated);
    this.lifetime++;
    this.clearInput();
    window.removeEventListener("pagehide", this.onPageHide);
    window.removeEventListener("pageshow", this.onPageShow);
    window.removeEventListener("blur", this.onWindowBlur);
    document.removeEventListener("visibilitychange", this.onVisibilityChange);
  }
}
