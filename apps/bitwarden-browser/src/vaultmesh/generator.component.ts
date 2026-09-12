import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, Input, OnDestroy, OnInit, inject, signal } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { ButtonModule, FormFieldModule } from "@bitwarden/components";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import { DEFAULT_GENERATOR_PREFERENCES, GeneratorPreferencesSchema, loadGeneratorPreferences, saveGeneratorPreferences } from "./generator-preferences";
import { generateCredential } from "./credential-generator";
@Component({ selector: "vaultmesh-generator", imports: [FormsModule, ButtonModule, FormFieldModule], templateUrl: "./generator.component.html", changeDetection: ChangeDetectionStrategy.OnPush })
export class VaultMeshGeneratorComponent implements OnInit, OnDestroy {
  @Input() independent = false;
  protected preferences = GeneratorPreferencesSchema.parse(DEFAULT_GENERATOR_PREFERENCES);
  protected readonly value = signal("");
  protected readonly notice = signal("");
  protected readonly busy = signal(false);
  protected readonly loading = signal(true);
  private readonly session = inject(VaultMeshBrowserRpcService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly changeDetector = inject(ChangeDetectorRef);
  private generation = 0;
  private ready = false;
  private timer?: ReturnType<typeof setTimeout>;
  private readonly hide = () => { if (document.hidden) this.clear(); };
  private readonly blur = () => { if (this.independent) this.clear(); };
  private readonly leave = () => this.clear();
  ngOnInit(): void {
    let identity = "";
    this.session.state$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((state) => {
      const next = `${state.sessionId}:${state.revision}`;
      if (identity && identity !== next || state.status !== "ready") this.clear();
      identity = next; this.ready = state.status === "ready";
    });
    const generation = this.generation;
    void loadGeneratorPreferences().then((value) => { if (generation === this.generation) this.preferences = value; this.loading.set(false); this.changeDetector.markForCheck(); });
    document.addEventListener("visibilitychange", this.hide); window.addEventListener("blur", this.blur); window.addEventListener("pagehide", this.leave);
  }
  protected async generate(): Promise<void> {
    if (!this.ready || this.busy() || this.loading()) return;
    this.clear(); const generation = this.generation;
    const parsed = GeneratorPreferencesSchema.safeParse(this.preferences);
    if (!parsed.success) { this.notice.set("生成参数不合法，请检查长度、字符种类和最少数量。"); return; }
    this.busy.set(true);
    let generated = "";
    try {
      const saved = await saveGeneratorPreferences(parsed.data);
      if (generation !== this.generation) return;
      generated = await generateCredential(parsed.data);
      if (generation !== this.generation || !this.ready) return;
      this.value.set(generated); this.notice.set(saved ? "已生成；参数已保存，结果仅在当前组件保留 60 秒。" : "已生成，但参数未能保存。结果不会持久化。");
      this.timer = setTimeout(() => this.clear(), 60000);
    } catch { if (generation === this.generation) this.notice.set("生成失败，未保留结果。"); }
    finally { generated = ""; if (generation === this.generation) this.busy.set(false); }
  }
  protected clear(): void { this.generation++; this.value.set(""); this.busy.set(false); if (this.timer) clearTimeout(this.timer); this.timer = undefined; }
  ngOnDestroy(): void { this.clear(); document.removeEventListener("visibilitychange", this.hide); window.removeEventListener("blur", this.blur); window.removeEventListener("pagehide", this.leave); }
}
