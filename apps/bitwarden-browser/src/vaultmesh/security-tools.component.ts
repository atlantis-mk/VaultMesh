import { ChangeDetectionStrategy, Component, DestroyRef, Input, OnDestroy, OnInit, inject, signal } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { ButtonModule, FormFieldModule } from "@bitwarden/components";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import { type SecurityCommand } from "./security-tools";
import { DEFAULT_PLUGIN_POLICY, loadPluginPolicy, savePluginPolicy, type PluginPolicy } from "./plugin-security";
import * as model from "./vendor/model-contracts";

@Component({ selector: "vaultmesh-security-tools", templateUrl: "./security-tools.component.html",
  imports: [FormsModule, ButtonModule, FormFieldModule], changeDetection: ChangeDetectionStrategy.OnPush })
export class VaultMeshSecurityToolsComponent implements OnInit, OnDestroy {
  @Input() locked = false;
  @Input() independent = false;
  protected pin = "";
  protected pinConfirmation = "";
  protected failureLimit = 5;
  protected readonly pinStatus = signal<model.PinStatus | null>(null);
  protected readonly biometric = signal<model.BiometricStatus | null>(null);
  protected readonly settings = signal<model.SecuritySettings | null>(null);
  protected readonly paired = signal(false);
  protected readonly notice = signal("");
  protected readonly busy = signal(false);
  protected readonly confirmingRevoke = signal(false);
  protected readonly health = signal<model.PasswordHealthReport | null>(null);
  protected readonly fillHistory = signal<model.FillEvent[]>([]);
  protected readonly unlockHistory = signal<model.UnlockEvent[]>([]);
  protected pluginPolicy: PluginPolicy = { ...DEFAULT_PLUGIN_POLICY };
  private readonly session = inject(VaultMeshBrowserRpcService);
  private readonly destroyRef = inject(DestroyRef);
  private generation = 0;
  private revokeDeadline = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private readonly hide = () => { if (document.hidden) this.clear(); };
  private readonly blur = () => { if (this.independent) this.clear(); };
  private readonly leave = () => this.clear();
  ngOnInit(): void {
    let identity = "";
    this.session.state$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((state) => {
      const next = `${state.sessionId}:${state.revision}:${state.status}`;
      if (identity && identity !== next || !["ready", "locked"].includes(state.status)) this.clear(false);
      identity = next;
    });
    document.addEventListener("visibilitychange", this.hide); window.addEventListener("blur", this.blur); window.addEventListener("pagehide", this.leave);
    void this.load();
  }
  protected async load(): Promise<void> {
    if (this.busy()) return;
    this.clear(false); const generation = this.generation; this.busy.set(true);
    const operations: SecurityCommand["operation"][] = ["pin.status", "biometric.status", "browser.pairing.status", ...(!this.locked ? ["security.settings.get" as const] : [])];
    for (const operation of operations) {
      const result = await this.session.securityTool({ operation, input: {} });
      if (generation !== this.generation) return;
      if (result.ok === false) { this.busy.set(false); this.error(result.code); return; }
      if (operation === "pin.status") this.pinStatus.set(model.PinStatusSchema.parse(result.value));
      if (operation === "biometric.status") this.biometric.set(model.BiometricStatusSchema.parse(result.value));
      if (operation === "browser.pairing.status") this.paired.set((result.value as { paired: boolean }).paired);
      if (operation === "security.settings.get") this.settings.set(model.SecuritySettingsSchema.parse(result.value));
    }
    const policy = await loadPluginPolicy();
    if (generation !== this.generation) return;
    this.pluginPolicy = policy; this.busy.set(false);
    this.timer = setTimeout(() => this.clear(), 300000);
  }
  protected async run(operation: SecurityCommand["operation"], input: Record<string, unknown> = {}, prefix = ""): Promise<void> {
    if (this.busy()) return;
    if (operation === "browser.pairing.revoke" && (!this.confirmingRevoke() || Date.now() >= this.revokeDeadline)) return;
    this.clear(false); const generation = this.generation; this.busy.set(true);
    const result = await this.session.securityTool({ operation, input, ...(operation === "browser.pairing.revoke" ? { confirmed: true as const } : {}) });
    if (generation !== this.generation) return;
    this.busy.set(false);
    if (result.ok === false) { this.error(result.code); this.notice.set(prefix + this.notice()); return; }
    if (operation === "password.health") this.health.set(model.PasswordHealthReportSchema.parse(result.value));
    if (operation === "browser.fill.history") this.fillHistory.set(model.FillEventSchema.array().parse(result.value));
    if (operation === "vault.unlock-history") this.unlockHistory.set(model.UnlockEventSchema.array().parse(result.value));
    this.notice.set(prefix + "操作完成。可刷新读取当前设置。");
    this.timer = setTimeout(() => this.clear(), 300000);
  }
  protected savePin(): void { if (/^\d{6}$/.test(this.pin) && this.pin === this.pinConfirmation) void this.run("pin.enable", { pin: this.pin, failureLimit: Number(this.failureLimit) }); }
  protected unlockPin(): void { if (/^\d{6}$/.test(this.pin)) void this.run("pin.unlock", { pin: this.pin }); }
  protected async saveSettings(): Promise<void> {
    const settings = this.settings(); if (!settings || this.busy()) return;
    const parsed = model.SecuritySettingsSchema.safeParse({ ...settings, idleTimeoutMs: Number(settings.idleTimeoutMs), clipboardClearTimeoutMs: Number(settings.clipboardClearTimeoutMs) });
    if (!parsed.success) { this.notice.set("安全设置无效，未保存。"); return; }
    const generation = this.generation;
    this.busy.set(true);
    const saved = await savePluginPolicy({ ...this.pluginPolicy, idleTimeoutMinutes: Number(this.pluginPolicy.idleTimeoutMinutes) as PluginPolicy["idleTimeoutMinutes"] });
    if (generation !== this.generation) return;
    this.busy.set(false);
    if (!saved) { this.notice.set("插件策略未保存，桌面设置未修改。"); return; }
    await this.run("security.settings.update", parsed.data, "插件策略已保存；以下为桌面设置结果：");
  }
  protected requestRevoke(): void {
    if (this.busy()) return;
    this.confirmingRevoke.set(true); this.revokeDeadline = Date.now() + 30000;
    if (this.timer) clearTimeout(this.timer); this.timer = setTimeout(() => this.clear(), 30000);
  }
  protected timestamp(value: number): string { return new Date(value).toLocaleString(); }
  protected clear(notify = true): void {
    if (notify && this.busy()) this.session.cancelManaged();
    this.generation++; this.pin = this.pinConfirmation = ""; this.busy.set(false);
    this.pinStatus.set(null); this.biometric.set(null); this.settings.set(null); this.paired.set(false);
    this.health.set(null); this.fillHistory.set([]); this.unlockHistory.set([]); this.confirmingRevoke.set(false); this.revokeDeadline = 0;
    if (this.timer) clearTimeout(this.timer); this.timer = undefined;
  }
  private error(code: string): void { this.notice.set(code === "execution-unknown" ? "结果未确认，不会重试。请刷新检查。" : "操作未完成，请检查 PIN、授权与桌面连接。"); }
  ngOnDestroy(): void { this.clear(); document.removeEventListener("visibilitychange", this.hide); window.removeEventListener("blur", this.blur); window.removeEventListener("pagehide", this.leave); }
}
