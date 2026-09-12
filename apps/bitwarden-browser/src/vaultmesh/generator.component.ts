import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, Input, OnDestroy, OnInit, inject, signal } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { ButtonModule, FormFieldModule, CardComponent, ColorPasswordModule, IconButtonModule, ToggleGroupModule, CheckboxModule, FormControlModule } from "@bitwarden/components";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import { DEFAULT_GENERATOR_PREFERENCES, GeneratorPreferencesSchema, loadGeneratorPreferences, saveGeneratorPreferences } from "./generator-preferences";
import { generateCredential } from "./credential-generator";
import type { FillFrame } from "./contracts";
@Component({ selector: "vaultmesh-generator", imports: [FormsModule, ButtonModule, FormFieldModule, CardComponent, ColorPasswordModule, IconButtonModule, ToggleGroupModule, CheckboxModule, FormControlModule], templateUrl: "./generator.component.html", changeDetection: ChangeDetectionStrategy.OnPush })
export class VaultMeshGeneratorComponent implements OnInit, OnDestroy {
  @Input() independent = false;
  protected preferences = GeneratorPreferencesSchema.parse(DEFAULT_GENERATOR_PREFERENCES);
  protected readonly value = signal("");
  protected readonly notice = signal("");
  protected readonly busy = signal(false);
  protected readonly loading = signal(true);
  protected readonly frames = signal<FillFrame[]>([]);
  protected setMode(mode: unknown): void {
    if (this.busy() || this.loading()) return;
    if (mode === "password" || mode === "passphrase" || mode === "username" || mode === "uuid") {
      this.clear(); this.preferences.mode = mode;
    }
  }
  protected selected: FillFrame | null = null;
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
  protected async prepareInsert(): Promise<void> {
    if (!this.value() || this.busy()) return;
    const generation = this.generation;
    const result = await this.session.fillContexts();
    if (generation === this.generation && result.ok) this.frames.set(result.value);
  }
  protected async use(command: "copy" | "insert"): Promise<void> {
    if (!this.value() || this.busy() || command === "insert" && !this.selected) return;
    const generation = this.generation; this.busy.set(true);
    const generated = { mode: this.preferences.mode, value: this.value() };
    this.value.set(""); // consume before dispatch, never retry an uncertain result
    try {
      const result = await this.session.generatedValue(command, generated, this.selected ?? undefined);
      if (generation !== this.generation) return;
      this.notice.set(result.ok ? command === "copy" ? "桌面端已复制，将按安全设置清理剪贴板。" : `已插入 ${"filled" in result.value ? result.value.filled : 0} 个字段。`
        : "操作未确认。请检查目标字段或剪贴板，不会自动重试。");
    } finally { generated.value = ""; if (generation === this.generation) { this.busy.set(false); this.selected = null; this.frames.set([]); } }
  }
  protected clear(): void { this.generation++; this.value.set(""); const pending = this.busy(); this.busy.set(false); if (pending) this.session.cancelManaged(); this.selected = null; this.frames.set([]); if (this.timer) clearTimeout(this.timer); this.timer = undefined; }
  ngOnDestroy(): void { this.clear(); document.removeEventListener("visibilitychange", this.hide); window.removeEventListener("blur", this.blur); window.removeEventListener("pagehide", this.leave); }
}
