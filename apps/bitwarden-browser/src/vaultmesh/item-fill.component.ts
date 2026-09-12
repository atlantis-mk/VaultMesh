import { Component, DestroyRef, Input, OnDestroy, OnInit, inject, signal } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormsModule } from "@angular/forms";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import type { FillFrame } from "./contracts";

@Component({ selector: "vaultmesh-item-fill", imports: [FormsModule], template: `
  <form (ngSubmit)="fill()" autocomplete="off">
    <p>填充 {{ title }}：仅写入空字段，不提交表单。</p>
    <label>目标页面 <select name="fillFrame" [(ngModel)]="selected" [disabled]="busy()">
      <option [ngValue]="null">请选择并确认实际目标来源</option>
      @for (frame of frames(); track frame.frameId) { <option [ngValue]="frame">{{ frame.url }}</option> }
    </select></label>
    @if (kind === 'card') { <label>当前主密码 <input name="fillMasterPassword" type="password" [(ngModel)]="password" autocomplete="off" minlength="8" maxlength="1024" /></label> }
    <button type="submit" [disabled]="busy() || !selected || (kind === 'card' && password.length < 8)">确认填充</button>
    <p role="status">{{ notice() }}</p>
  </form>` })
export class VaultMeshItemFillComponent implements OnInit, OnDestroy {
  @Input({ required: true }) kind!: "card" | "identity";
  @Input({ required: true }) id!: string;
  @Input() title = "";
  @Input() independent = false;
  protected readonly frames = signal<FillFrame[]>([]);
  protected readonly notice = signal("");
  protected readonly busy = signal(false);
  protected selected: FillFrame | null = null;
  protected password = "";
  private readonly session = inject(VaultMeshBrowserRpcService);
  private readonly destroy = inject(DestroyRef);
  private revision = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private readonly hide = () => { if (document.hidden) this.clear(); };
  private readonly blur = () => { if (this.independent) this.clear(); };
  ngOnInit(): void {
    let identity = "";
    this.session.state$.pipe(takeUntilDestroyed(this.destroy)).subscribe((state) => {
      const next = `${state.sessionId}:${state.revision}`;
      if (state.status !== "ready" || identity && next !== identity) this.clear();
      identity = next;
    });
    const revision = this.revision;
    void this.session.fillContexts().then((result) => { if (revision === this.revision && result.ok) this.frames.set(result.value); });
    this.timer = setTimeout(() => this.clear(), 30000);
    document.addEventListener("visibilitychange", this.hide); window.addEventListener("blur", this.blur);
  }
  protected async fill(): Promise<void> {
    if (this.busy() || !this.selected) return;
    const revision = this.revision; this.busy.set(true);
    const password = this.password; this.password = "";
    const result = await this.session.fillItem(this.kind, this.id, this.selected, password || undefined);
    if (revision !== this.revision) return;
    this.busy.set(false); this.selected = null;
    this.notice.set(result.ok ? `已填入 ${result.value.filled} 个字段。` : "填充未确认，请检查页面、主密码或连接；不会自动重试。");
  }
  private clear(): void { this.revision++; this.password = ""; this.selected = null; this.frames.set([]); if (this.busy()) this.session.cancelManaged(); this.busy.set(false); }
  ngOnDestroy(): void { this.clear(); if (this.timer) clearTimeout(this.timer); document.removeEventListener("visibilitychange", this.hide); window.removeEventListener("blur", this.blur); }
}
