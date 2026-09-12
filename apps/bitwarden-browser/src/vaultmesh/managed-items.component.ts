import { ChangeDetectionStrategy, Component, DestroyRef, Input, OnDestroy, OnInit, inject, signal } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { ButtonModule, FormFieldModule } from "@bitwarden/components";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import { ManagedDraft, ADDRESS_FIELDS, IDENTITY_COLLECTIONS } from "./managed-draft";
import { MANAGED_ITEMS, type ManagedKind, type ManagedCommand, type ManagedRow } from "./managed-items";
import { clearLoginSecrets } from "./login-contracts";
import { VaultMeshItemFillComponent } from "./item-fill.component";

@Component({ selector: "vaultmesh-managed-items", templateUrl: "./managed-items.component.html",
  imports: [FormsModule, ButtonModule, FormFieldModule, VaultMeshItemFillComponent], changeDetection: ChangeDetectionStrategy.OnPush })
export class VaultMeshManagedItemsComponent implements OnInit, OnDestroy {
  @Input({ required: true }) kind!: ManagedKind;
  @Input() independent = false;
  protected readonly definitions = MANAGED_ITEMS;
  protected readonly addressFields = ADDRESS_FIELDS;
  protected readonly collections = IDENTITY_COLLECTIONS;
  protected readonly rows = signal<ManagedRow[]>([]);
  protected readonly draft = signal<ManagedDraft | null>(null);
  protected readonly pending = signal<{ command: ManagedCommand; title: string; reprompt: boolean } | null>(null);
  protected readonly busy = signal(false);
  protected readonly notice = signal("");
  protected readonly fillTarget = signal<ManagedRow | null>(null);
  protected mode: "list" | "trash" | "history" = "list";
  protected historyId = "";
  protected query = "";
  protected masterPassword = "";
  private readonly session = inject(VaultMeshBrowserRpcService);
  private readonly destroyRef = inject(DestroyRef);
  private generation = 0;
  private deadline = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private ready = false;
  private sessionBusy = false;
  private readonly hide = () => { if (document.hidden) this.cancel(); };
  private readonly blur = () => { if (this.independent) this.cancel(); };
  private readonly leave = () => this.cancel();
  ngOnInit(): void {
    let identity = "";
    this.session.state$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((state) => {
      const next = `${state.sessionId}:${state.revision}`;
      if (identity && identity !== next || state.status !== "ready") this.cancel(false);
      identity = next;
      this.ready = state.status === "ready";
      this.sessionBusy = state.busy;
    });
    document.addEventListener("visibilitychange", this.hide);
    window.addEventListener("blur", this.blur);
    window.addEventListener("pagehide", this.leave);
    void this.load();
  }
  protected filtered(): ManagedRow[] { return this.rows().filter((row) => row.title.toLocaleLowerCase().includes(this.query.toLocaleLowerCase())); }
  protected text(row: ManagedRow, key: string): string { return typeof row[key] === "string" ? row[key] as string : ""; }
  protected date(row: ManagedRow): string { const time = row.savedAt ?? row.deletedAt; return typeof time === "number" ? new Date(time).toLocaleString() : ""; }
  protected copyFields(row: ManagedRow): string[] {
    const available: Record<string, string> = { "security-code": "hasSecurityCode", pin: "hasPin", password: "hasPassword",
      "public-key": "hasPublicKey", "private-key": "hasPrivateKey", "key-passphrase": "hasKeyPassphrase" };
    return [...MANAGED_ITEMS[this.kind].copy].filter((field) => !available[field] || row[available[field]] === true);
  }
  protected copyLabel(field: string): string { return ({ number: "卡号", "security-code": "安全码", pin: "PIN", password: "密码", "public-key": "公钥", "private-key": "私钥", "key-passphrase": "私钥口令", value: "受保护值" } as Record<string, string>)[field]; }
  protected async load(mode: "list" | "trash" | "history" = "list", id?: string): Promise<void> {
    if (!this.ready || this.busy() || this.sessionBusy || this.kind === "secret" && mode !== "list") return;
    this.cancel(false); this.mode = mode; this.historyId = id ?? "";
    const generation = this.generation; this.busy.set(true);
    const command: ManagedCommand = mode === "list" ? { kind: this.kind, verb: "list" }
      : mode === "trash" ? { kind: this.kind as "card" | "identity" | "ssh", verb: "trash" }
      : { kind: this.kind as "card" | "identity" | "ssh", verb: "history", id: id! };
    const result = await this.session.managedItem(command);
    if (generation !== this.generation) return;
    this.busy.set(false);
    if (result.ok && Array.isArray(result.value)) { this.rows.set(result.value); this.arm(300000); }
    else this.error(result.ok === false ? result.code : "invalid-broker-response");
  }
  protected create(): void {
    if (!this.ready || this.busy() || this.sessionBusy) return;
    this.cancel(false); this.draft.set(new ManagedDraft(this.kind)); this.arm(300000);
  }
  protected async edit(row: ManagedRow): Promise<void> {
    if (!row.id || !this.ready || this.busy() || this.sessionBusy) return;
    this.cancel(false); const generation = this.generation; this.busy.set(true);
    const result = await this.session.managedItem({ verb: "detail", kind: this.kind, id: row.id });
    try {
      if (generation !== this.generation) return;
      this.busy.set(false);
      if (result.ok && result.value && !Array.isArray(result.value)) { this.draft.set(new ManagedDraft(this.kind, result.value)); this.arm(300000); }
      else this.error(result.ok === false ? result.code : "invalid-broker-response");
    } finally { if (result.ok) clearLoginSecrets(result.value); }
  }
  protected async save(): Promise<void> {
    if (!this.draft() || !this.current()) return;
    let input: Record<string, unknown>;
    try { input = this.draft()!.toInput(); }
    catch { this.notice.set("请检查字段格式、必填内容和清除选项。未执行保存。"); return; }
    await this.execute({ verb: "save", kind: this.kind, input });
  }
  protected ask(command: ManagedCommand, title: string, reprompt = false): void {
    if (!this.ready || this.busy() || this.sessionBusy) return;
    this.cancel(false); this.pending.set({ command, title, reprompt }); this.arm(30000);
  }
  protected askDelete(row: ManagedRow): void { if (row.id) this.ask({ verb: "delete", kind: this.kind, id: row.id, confirmed: true }, `删除“${row.title}”${this.kind === "secret" ? "（服务密钥没有回收站，此操作无法撤销）" : "并移至回收站"}`); }
  protected askCopy(row: ManagedRow, field: string): void { if (row.id) this.ask({ verb: "copy", kind: this.kind, id: row.id, field }, `复制“${row.title}”的${this.copyLabel(field)}`, row.masterPasswordReprompt === true); }
  protected askRecovery(verb: "restore-trash" | "purge" | "empty-trash" | "restore-history" | "clear-history", row?: ManagedRow): void {
    if (this.kind === "secret") return;
    const kind = this.kind;
    const command: ManagedCommand | undefined = verb === "empty-trash" ? { kind, verb, confirmed: true }
      : verb === "clear-history" ? { kind, verb, id: this.historyId, confirmed: true }
      : verb === "restore-history" && row?.itemId && row.revisionId ? { kind, verb, itemId: row.itemId, revisionId: row.revisionId, confirmed: true }
      : verb === "restore-trash" && row?.trashId && row.itemId ? { kind, verb, trashId: row.trashId, itemId: row.itemId, confirmed: true }
      : verb === "purge" && row?.trashId ? { kind, verb, trashId: row.trashId, confirmed: true } : undefined;
    if (command) this.ask(command, `${verb.startsWith("restore") ? "恢复所选完整版本" : "永久清理，无法撤销"}：${row?.title ?? MANAGED_ITEMS[kind].label}`);
  }
  protected async confirm(): Promise<void> {
    const pending = this.pending();
    if (!pending || !this.current() || pending.reprompt && this.masterPassword.length < 8) return;
    const command = { ...pending.command };
    if (command.verb === "copy" && this.masterPassword) command.masterPassword = this.masterPassword;
    await this.execute(command);
  }
  private async execute(command: ManagedCommand): Promise<void> {
    this.cancel(false); const generation = this.generation; this.busy.set(true);
    const result = await this.session.managedItem(command);
    if (generation !== this.generation) return;
    this.busy.set(false);
    if (result.ok === false) { this.error(result.code); return; }
    this.notice.set(command.verb === "copy" ? "桌面端已复制，并按安全设置清理剪贴板。" : "操作已完成，可刷新查看最新条目。");
  }
  protected cancel(notify = true): void {
    this.fillTarget.set(null);
    if (notify && this.busy()) this.session.cancelManaged();
    this.generation++; this.busy.set(false); this.query = this.masterPassword = "";
    this.draft()?.clear(); this.draft.set(null);
    clearLoginSecrets(this.pending()?.command); this.pending.set(null); this.rows.set([]);
    if (this.timer) clearTimeout(this.timer); this.timer = undefined; this.deadline = 0;
  }
  private current(): boolean {
    if (!this.ready || this.busy() || this.sessionBusy) return false;
    if (Date.now() >= this.deadline) { this.cancel(); return false; }
    return true;
  }
  private arm(ms: number): void { this.deadline = Date.now() + ms; this.timer = setTimeout(() => { this.cancel(); this.notice.set("操作已过期，请重新打开。"); }, ms); }
  private error(code: string): void { this.notice.set(code === "execution-unknown" ? "结果未确认，不会自动重试。请刷新检查后再操作。" : "操作未完成，请检查字段、主密码及桌面连接后重试。"); }
  ngOnDestroy(): void { this.cancel(); document.removeEventListener("visibilitychange", this.hide); window.removeEventListener("blur", this.blur); window.removeEventListener("pagehide", this.leave); }
}
