import { VaultMeshNativeFillContent, type CaptureControl } from "./native-fill-content";
import { nativePage, projectField, isFillControl } from "./native-fill-contracts";
import { planNativeItem, type NativeItemKind } from "./native-item-planner";
import type { NativeItemSource } from "./vendor/browser-native-item-plan";
import { CAPTURE_OPTIONS, CAPTURE_ITEM_SAVE, CAPTURE_STATUS, CaptureOptionsSchema, clearCapture } from "./native-capture-contracts";
import { createVaultMeshUuid } from "./uuid";
import { sendSessionMessage } from "./runtime";
import { MANAGED_ITEMS } from "./managed-items";

type Snapshot = { captureId: string; itemKind: NativeItemKind; values: { source: NativeItemSource; value: string }[]; url: string; expires: number };
type Field = CaptureControl & { source: NativeItemSource };
/** Precompute native roles without values; take a synchronous snapshot before SPA handlers remove nodes. */
export class NativeItemCaptureContent {
  private fields: Field[] = [];
  private dirty = new WeakSet<Element>();
  private readonly roots = new Set<Document | ShadowRoot>();
  private readonly seen = new WeakSet<Event>();
  private snapshot?: Snapshot;
  private host?: HTMLElement;
  private timer?: ReturnType<typeof setInterval>;
  private refreshing = false;
  private revision = 0;
  private url = location.href;
  constructor(private readonly content: VaultMeshNativeFillContent) {}
  start(): void {
    this.attach(document); void this.refresh();
    document.addEventListener("visibilitychange", this.hide); window.addEventListener("pagehide", this.clear);
    this.timer = setInterval(() => {
      if (this.url !== location.href) { this.url = location.href; this.clear(); this.fields = []; this.dirty = new WeakSet(); }
      if (this.snapshot && this.snapshot.expires <= Date.now()) this.clear();
      const snapshot = this.snapshot;
      if (snapshot) void sendSessionMessage({ kind: CAPTURE_STATUS }).then((result) => { if (result !== true && snapshot === this.snapshot) this.clear(); }, () => { if (snapshot === this.snapshot) this.clear(); });
      if (!document.hidden) void this.refresh();
    }, 1000);
  }
  private readonly hide = () => { if (document.hidden) { this.clear(); this.fields = []; } };
  private attach(root: Document | ShadowRoot): void { if (this.roots.has(root)) return; this.roots.add(root); for (const name of ["input", "change", "focusin", "submit", "formdata", "click", "keydown"]) root.addEventListener(name, this.event, true); }
  async refresh(): Promise<void> {
    if (this.refreshing) return; this.refreshing = true;
    const revision = this.revision; const url = location.href;
    try {
      const controls = await this.content.captureControls();
      if (!controls.length) { this.fields = []; return; }
      const fields: Field[] = [];
      for (const scope of new Set(controls.map((field) => field.scope))) {
        const group = controls.filter((field) => field.scope === scope);
        const page = nativePage({ requestId: createVaultMeshUuid(), documentId: createVaultMeshUuid(), url,
          expiresAt: new Date(Date.now() + 30000).toISOString(), forms: {}, fields: group.map((f) => projectField(f.field, createVaultMeshUuid())) });
        for (const kind of ["card", "identity", "ssh", "secret"] as const) {
          if ((kind === "ssh" || kind === "secret") && location.protocol !== "https:") continue;
          const plan = await planNativeItem(page, kind);
          for (const control of group) { const source = plan.get(control.field.opid); if (source) fields.push({ ...control, source }); }
        }
      }
      if (revision !== this.revision || url !== location.href || document.hidden) return;
      this.fields = fields;
      for (const field of fields) { const root = field.element.getRootNode(); if (root instanceof ShadowRoot) this.attach(root); }
      for (const root of this.roots) if (root instanceof ShadowRoot && !root.host.isConnected) this.detach(root);
    } catch { if (revision === this.revision) this.fields = []; }
    finally { this.refreshing = false; }
  }
  private readonly event = (event: Event) => {
    if (this.seen.has(event)) return; this.seen.add(event);
    const target = event.composedPath()[0]; if (!(target instanceof Element)) return;
    if (event.type === "focusin") { void this.refresh(); return; }
    if (["input", "change"].includes(event.type)) { if (event.isTrusted && isFillControl(target)) this.dirty.add(target); return; }
    if (event.type === "keydown") { const key = event as KeyboardEvent; if (!key.isTrusted || key.key !== "Enter" || key.isComposing || key.defaultPrevented || !(target instanceof HTMLInputElement) || target.form && !target.form.checkValidity()) return; }
    if (event.type === "click" && (!event.isTrusted || !target.closest("button[type=submit],input[type=submit],button:not([type])"))) return;
    this.observe(target);
  };
  observe(target: Element): void {
    const form = target instanceof HTMLFormElement ? target : isFillControl(target) || target instanceof HTMLButtonElement ? target.form : target.closest("form");
    const fields = this.fields.filter((f) => (form ? f.form === form : !f.form && f.scope.contains(target)) && this.content.captureFieldCurrent(f) && this.dirty.has(f.element) && f.element.value);
    if (new Set(fields.map((f) => f.scope)).size !== 1) return;
    const kinds = new Set(fields.map((f) => f.source.split(":")[0]));
    const values = fields.map((f) => ({ source: f.source, value: capturedControlValue(f) }));
    if (values.some((row) => !row.value || row.value.length > 10000) || new Set(values.map((row) => row.source)).size !== values.length) return;
    this.clear();
    const snapshot = this.snapshot = { captureId: createVaultMeshUuid(), itemKind: [...kinds][0] as NativeItemKind, values, url: location.href, expires: Date.now() + 30000 };
    if (kinds.size > 1) {
      const host = this.host = document.createElement("div"); this.content.ownHost(host);
      host.style.cssText = "position:fixed;right:8px;top:8px;z-index:2147483647;max-width:calc(100vw - 16px)";
      const root = host.attachShadow({ mode: "closed" });
      const box = document.createElement("div"); box.style.cssText = "background:white;color:#172033;padding:16px;border:1px solid #aaa;display:grid;gap:8px";
      box.textContent = "VaultMesh：此表单包含多类信息，请选择要保存的类型。";
      for (const kind of kinds) {
        const button = document.createElement("button"); button.textContent = MANAGED_ITEMS[kind as NativeItemKind].label;
        button.addEventListener("click", (event) => {
          if (!event.isTrusted || snapshot !== this.snapshot || snapshot.expires <= Date.now() || snapshot.url !== location.href) return;
          snapshot.itemKind = kind as NativeItemKind;
          for (const row of snapshot.values) if (!row.source.startsWith(`${kind}:`)) row.value = "";
          snapshot.values = snapshot.values.filter((row) => row.source.startsWith(`${kind}:`));
          this.host?.remove(); this.host = undefined; void this.offer(snapshot);
        }); box.append(button);
      }
      const ignore = document.createElement("button"); ignore.textContent = "忽略"; ignore.addEventListener("click", (event) => { if (event.isTrusted) this.clear(); });
      box.append(ignore); root.append(box); document.documentElement.append(host); return;
    }
    void this.offer(snapshot);
  }
  private async offer(snapshot: Snapshot): Promise<void> {
    try {
      const result = CaptureOptionsSchema.parse(await sendSessionMessage({ kind: CAPTURE_OPTIONS, captureId: snapshot.captureId, itemKind: snapshot.itemKind }));
      if (this.snapshot !== snapshot || snapshot.url !== location.href || document.hidden || snapshot.expires <= Date.now()) return;
      snapshot.expires = Math.min(snapshot.expires, Date.parse(result.expiresAt));
      const host = this.host = document.createElement("div"); this.content.ownHost(host);
      host.style.cssText = "position:fixed;right:8px;top:8px;z-index:2147483647;max-width:calc(100vw - 16px);max-height:calc(100vh - 16px);overflow:auto";
      const root = host.attachShadow({ mode: "closed" }); const box = document.createElement("div");
      box.style.cssText = "background:white;color:#172033;font:14px system-ui;padding:16px;border:1px solid #aaa;border-radius:8px;display:grid;gap:10px";
      const text = document.createElement("p"); text.textContent = `VaultMesh：检测到${MANAGED_ITEMS[snapshot.itemKind].label}提交，是否保存？这不代表网站已接受。`;
      if (snapshot.itemKind === "secret") text.textContent += " 密钥类型：" + snapshot.values.filter((row) => !["secret:account", "secret:provider"].includes(row.source)).map((row) => row.source.slice(7)).join("、") + "；新项目默认不要求再次输入主密码。";
      const select = document.createElement("select"); select.setAttribute("aria-label", "选择新建或更新同类型项目"); select.add(new Option("保存为新项目", ""));
      for (const row of result.candidates) select.add(new Option(`更新：${row.title}`, row.id));
      const save = document.createElement("button"); save.type = "button"; save.textContent = "保存";
      const ignore = document.createElement("button"); ignore.type = "button"; ignore.textContent = "忽略";
      ignore.addEventListener("click", (event) => { if (event.isTrusted) this.clear(); });
      save.addEventListener("click", async (event) => {
        if (!event.isTrusted || this.snapshot !== snapshot || snapshot.expires <= Date.now() || snapshot.url !== location.href) return;
        save.disabled = select.disabled = true;
        const message = { kind: CAPTURE_ITEM_SAVE, captureId: snapshot.captureId, nonce: result.nonce, itemKind: snapshot.itemKind,
          values: snapshot.values.map((row) => ({ ...row })), ...(select.value ? { itemId: select.value } : {}) };
        clearCapture(snapshot);
        try { const response = await sendSessionMessage(message); if (this.snapshot === snapshot) text.textContent = response && typeof response === "object" && "saved" in response && response.saved ? "已保存。" : "保存未确认，请刷新检查，不会自动重试。"; }
        catch { if (this.snapshot === snapshot) text.textContent = "保存未确认，不会自动重试。"; }
        finally { clearCapture(message); }
      });
      box.append(text, select, save, ignore); root.append(box); document.documentElement.append(host);
    } catch { if (this.snapshot === snapshot) this.clear(); }
  }
  private readonly clear = () => { this.revision++; clearCapture(this.snapshot); this.snapshot = undefined; this.host?.remove(); this.host = undefined; };
  private detach(root: Document | ShadowRoot): void { for (const name of ["input", "change", "focusin", "submit", "formdata", "click", "keydown"]) root.removeEventListener(name, this.event, true); this.roots.delete(root); }
  destroy(): void { this.clear(); if (this.timer) clearInterval(this.timer); for (const root of this.roots) this.detach(root); document.removeEventListener("visibilitychange", this.hide); window.removeEventListener("pagehide", this.clear); this.fields = []; }
}

function capturedControlValue(field: Field): string {
  const element = field.element;
  if (!(element instanceof HTMLSelectElement)) return element.value;
  const selected = element.options[element.selectedIndex];
  if (!selected || selected.disabled || !element.value) return "";
  if (field.source === "card:expMonth") {
    if (/^(?:0?[1-9]|1[0-2])$/.test(element.value)) return element.value;
    if (element.options.length === 12) return String(element.selectedIndex + 1);
    if (element.options.length === 13) return String(element.options[0].value ? element.selectedIndex + 1 : element.selectedIndex);
    return "";
  }
  if (field.source === "card:expYear") return /^\d{2}(?:\d{2})?$/.test(element.value) ? element.value : selected.text.trim();
  if (field.source === "identity:country" || field.source === "identity:state") return /^[a-z]{2}$/i.test(element.value) ? element.value : selected.text.trim();
  return element.value;
}
