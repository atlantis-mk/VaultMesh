import { ChangeDetectionStrategy, Component, DestroyRef, Input, OnDestroy, OnInit, inject, signal } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { ButtonModule, FormFieldModule } from "@bitwarden/components";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
@Component({ selector: "vaultmesh-vault-lifecycle", templateUrl: "./vault-lifecycle.component.html", imports: [FormsModule, ButtonModule, FormFieldModule], changeDetection: ChangeDetectionStrategy.OnPush })
export class VaultMeshVaultLifecycleComponent implements OnInit, OnDestroy {
  @Input() hasVault = true;
  @Input() independent = false;
  protected currentPassword = "";
  protected password = "";
  protected repeat = "";
  protected confirmed = false;
  protected readonly busy = signal(false);
  protected readonly notice = signal("");
  private readonly session = inject(VaultMeshBrowserRpcService);
  private readonly destroy = inject(DestroyRef);
  private generation = 0;
  private deadline = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private readonly hide = () => { if (document.hidden) this.clear(); };
  private readonly blur = () => { if (this.independent) this.clear(); };
  private readonly leave = () => this.clear();
  ngOnInit(): void {
    let previous = "";
    this.session.state$.pipe(takeUntilDestroyed(this.destroy)).subscribe((state) => {
      const identity = `${state.status}:${state.revision}:${state.sessionId}`;
      if (previous && identity !== previous) this.clear(false); previous = identity;
    });
    document.addEventListener("visibilitychange", this.hide); window.addEventListener("blur", this.blur); window.addEventListener("pagehide", this.leave);
  }
  protected changed(): void {
    if (!this.deadline) { this.deadline = Date.now() + 300000; this.timer = setTimeout(() => { this.clear(); this.notice.set("密码输入已过期并清除。"); }, 300000); }
  }
  protected async save(): Promise<void> {
    if (this.busy() || !this.confirmed || this.password.length < 8 || this.password.length > 1024 || this.password !== this.repeat
      || this.hasVault && this.currentPassword.length < 8 || !this.deadline || Date.now() >= this.deadline) return;
    const input = this.hasVault ? { currentPassword: this.currentPassword, newPassword: this.password } : { masterPassword: this.password };
    this.clear(false); const generation = this.generation; this.busy.set(true);
    const result = await this.session.securityTool({ operation: this.hasVault ? "vault.change-password" : "vault.create", input, confirmed: true });
    if (generation !== this.generation) return;
    this.busy.set(false);
    this.notice.set(result.ok === true ? "操作已由桌面确认。请刷新查看当前保险库状态。" : result.code === "execution-unknown" ? "桌面未确认结果，请先检查当前状态，勿重复提交。" : "操作未完成；验证失败或取消不会覆盖原保险库。");
  }
  protected clear(cancel = true): void {
    if (cancel && this.busy()) this.session.cancelManaged();
    this.generation++; this.currentPassword = this.password = this.repeat = ""; this.confirmed = false; this.busy.set(false);
    if (this.timer) clearTimeout(this.timer); this.timer = undefined; this.deadline = 0;
  }
  ngOnDestroy(): void { this.clear(); document.removeEventListener("visibilitychange", this.hide); window.removeEventListener("blur", this.blur); window.removeEventListener("pagehide", this.leave); }
}
