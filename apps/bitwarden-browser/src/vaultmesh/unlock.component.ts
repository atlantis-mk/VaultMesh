import { ChangeDetectionStrategy, Component, DestroyRef, Input, OnDestroy, OnInit, computed, inject, signal } from "@angular/core";
import { takeUntilDestroyed, toSignal } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { ButtonModule, CardComponent, FormFieldModule } from "@bitwarden/components";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import { BiometricStatusSchema, PinStatusSchema, type BiometricStatus, type PinStatus } from "./vendor/model-contracts";

type UnlockMethod = "pin" | "biometric" | "password";

@Component({
  selector: "vaultmesh-unlock", templateUrl: "./unlock.component.html",
  imports: [FormsModule, ButtonModule, CardComponent, FormFieldModule],
  host: { class: "tw-flex tw-min-h-[360px] tw-items-center tw-w-full" },
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class VaultMeshUnlockComponent implements OnInit, OnDestroy {
  @Input() independent = false;
  private readonly session = inject(VaultMeshBrowserRpcService);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly state = toSignal(this.session.state$, { requireSync: true });
  protected readonly pin = signal<PinStatus | null>(null);
  protected readonly biometric = signal<BiometricStatus | null>(null);
  protected readonly loading = signal(true);
  protected readonly working = signal(false);
  protected readonly notice = signal("");
  protected readonly credential = signal("");
  private readonly selected = signal<UnlockMethod | null>(null);
  protected readonly pinAvailable = computed(() => !!this.pin()?.enabled && !this.pin()?.locked && (this.pin()?.remainingAttempts ?? 0) > 0);
  protected readonly biometricAvailable = computed(() => !!this.biometric()?.available && !!this.biometric()?.enabled);
  protected readonly method = computed<UnlockMethod>(() => {
    const selected = this.selected();
    if (selected === "password" || selected === "pin" && this.pinAvailable() || selected === "biometric" && this.biometricAvailable()) return selected;
    return this.pinAvailable() ? "pin" : this.biometricAvailable() ? "biometric" : "password";
  });
  protected readonly disabled = computed(() => this.loading() || this.working() || this.state().busy);
  private generation = 0;
  private active = true;
  private readonly hide = () => { if (document.hidden) this.invalidate(); };
  private readonly blur = () => { if (this.independent) this.credential.set(""); };
  private readonly leave = () => this.invalidate();

  ngOnInit(): void {
    let identity: string | undefined;
    this.session.state$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(state => {
      const next = `${state.status}:${state.sessionId}:${state.revision}`;
      if (identity !== undefined && identity !== next) this.invalidate();
      identity = next;
    });
    document.addEventListener("visibilitychange", this.hide);
    window.addEventListener("blur", this.blur);
    window.addEventListener("pagehide", this.leave);
    void this.loadMethods();
  }

  private current(generation: number): boolean {
    return this.active && generation === this.generation && this.state().status === "locked" && !document.hidden;
  }

  protected async loadMethods(): Promise<void> {
    if (!this.active || this.working() || this.state().status !== "locked") return;
    const generation = ++this.generation;
    this.loading.set(true); this.pin.set(null); this.biometric.set(null);
    // Only these two credential-free reads may overlap; authentication stays serialized.
    try {
      const results = await this.session.readUnlockMethods();
      for (const [index, operation] of (["pin.status", "biometric.status"] as const).entries()) {
        const result = results[index];
        if (!this.current(generation)) return;
        if (!result.ok) { this.notice.set("部分解锁方式未能读取，未确认可用的方式不会显示。"); continue; }
        if (operation === "pin.status") this.pin.set(PinStatusSchema.parse(result.value));
        else this.biometric.set(BiometricStatusSchema.parse(result.value));
      }
    } catch { if (this.current(generation)) this.notice.set("解锁方式读取失败，请刷新重试。"); }
    finally { if (generation === this.generation) this.loading.set(false); }
  }

  protected choose(method: UnlockMethod): void {
    if (this.disabled() || method === "pin" && !this.pinAvailable() || method === "biometric" && !this.biometricAvailable()) return;
    this.credential.set(""); this.notice.set(""); this.selected.set(method);
  }

  protected inputCredential(value: string): void {
    if (this.disabled()) return;
    this.credential.set(this.method() === "pin" ? value.replace(/\D/g, "").slice(0, 6) : value.slice(0, 1024));
    if (this.method() === "pin" && this.credential().length === 6) void this.unlock();
  }

  protected async unlock(): Promise<void> {
    if (this.disabled() || !this.current(this.generation)) return;
    const method = this.method();
    if (method === "pin" && !/^\d{6}$/.test(this.credential()) || method === "password" && this.credential().length < 8) return;
    let credential = this.credential(); this.credential.set(""); this.notice.set(""); this.working.set(true);
    const generation = this.generation;
    try {
      if (method === "password") await this.session.unlock(credential);
      else {
        const input = method === "pin" ? { pin: credential } : {};
        credential = "";
        try {
          const result = await this.session.securityTool({ operation: method === "pin" ? "pin.unlock" : "biometric.unlock", input });
          if (this.current(generation) && result.ok === false) this.notice.set(result.code === "execution-unknown" ? "结果未确认，不会自动重试。" : method === "pin" ? "PIN 验证未通过，请重试或改用其他方式。" : "系统验证未完成或已取消，可重试或改用主密码。");
        } finally { if ("pin" in input) input.pin = ""; }
      }
    } catch { if (this.current(generation)) this.notice.set("解锁未完成，请检查桌面连接后重试。"); }
    finally {
      credential = "";
      if (generation === this.generation) {
        this.working.set(false);
        // Read remaining attempts after a rejected PIN, never automatically repeat authentication.
        if (method === "pin" && this.current(generation)) await this.loadMethods();
      }
    }
  }

  private invalidate(): void {
    this.generation++; this.credential.set(""); this.pin.set(null); this.biometric.set(null);
    this.selected.set(null); this.working.set(false); this.loading.set(false);
  }

  ngOnDestroy(): void {
    this.active = false; this.invalidate();
    document.removeEventListener("visibilitychange", this.hide);
    window.removeEventListener("blur", this.blur); window.removeEventListener("pagehide", this.leave);
  }
}
