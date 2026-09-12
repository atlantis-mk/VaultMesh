import { InlineMenuFieldQualificationService } from "../autofill/services/inline-menu-field-qualification.service";
import { VaultMeshNativeFillContent, type CaptureField } from "./native-fill-content";
import { createVaultMeshUuid } from "./uuid";
import { sendSessionMessage } from "./runtime";
import { CAPTURE_OPTIONS, CAPTURE_SAVE, CAPTURE_STATUS, CaptureOptionsSchema, clearCapture } from "./native-capture-contracts";

type Snapshot = { captureId: string; username: string; password: string; url: string; expires: number };

/** Native field roles and form ownership; submission is an observation, never success. */
export class VaultMeshNativeCaptureContent {
  private readonly qualification = new InlineMenuFieldQualificationService(true);
  private fields: CaptureField[] = [];
  private dirty = new WeakSet<HTMLInputElement>();
  private readonly roots = new Set<Document | ShadowRoot>();
  private readonly observed = new WeakSet<Event>();
  private snapshot?: Snapshot;
  private host?: HTMLElement;
  private revision = 0;
  private refreshing = false;
  private timer?: ReturnType<typeof setInterval>;
  private url = location.href;
  constructor(private readonly content: VaultMeshNativeFillContent) {}

  start(): void {
    this.attach(document);
    window.addEventListener("pagehide", this.onHide);
    document.addEventListener("visibilitychange", this.onVisibility);
    this.timer = setInterval(() => {
      if (this.url !== location.href) { this.url = location.href; this.clear(); this.fields = []; this.dirty = new WeakSet(); }
      if (this.snapshot && this.snapshot.expires <= Date.now()) this.clear();
      if (!document.hidden) void this.refresh();
      if (this.snapshot) {
        const snapshot = this.snapshot;
        void sendSessionMessage({ kind: CAPTURE_STATUS }).then((result) => {
          if (result !== true && this.snapshot === snapshot) this.clear();
        }, () => { if (this.snapshot === snapshot) this.clear(); });
      }
    }, 1000);
    void this.refresh();
  }

  private readonly onHide = () => { this.clear(); this.fields = []; this.dirty = new WeakSet(); };
  private readonly onVisibility = () => { if (document.hidden) this.onHide(); };
  private attach(root: Document | ShadowRoot): void {
    if (this.roots.has(root)) return;
    this.roots.add(root);
    for (const type of ["focusin", "input", "submit", "formdata", "click", "keydown"]) root.addEventListener(type, this.onEvent, true);
  }

  async refresh(): Promise<void> {
    if (this.refreshing) return;
    this.refreshing = true;
    const url = location.href;
    try {
      const fields = await this.content.captureFields();
      if (url !== location.href) return;
      if (fields.length) this.fields = fields;
      for (const field of fields) {
        const root = field.element.getRootNode();
        if (root instanceof ShadowRoot) this.attach(root);
      }
      for (const root of this.roots) if (root instanceof ShadowRoot && !root.host.isConnected) this.detach(root);
    } catch { /* A stale collector must not produce a capture. */ }
    finally { this.refreshing = false; }
  }

  private readonly onEvent = (event: Event) => {
    if (this.observed.has(event)) return;
    this.observed.add(event);
    const target = event.composedPath()[0];
    if (!(target instanceof Element) || target === this.host) return;
    if (event.type === "focusin") { void this.refresh(); return; }
    if (event.type === "input") {
      if (event.isTrusted && target instanceof HTMLInputElement) this.dirty.add(target);
      return;
    }
    if (event.type === "keydown") {
      const key = event as KeyboardEvent;
      if (!key.isTrusted || key.isComposing || key.key !== "Enter" || key.defaultPrevented || !(target instanceof HTMLInputElement)) return;
      const field = this.fields.find((field) => field.element === target);
      if (!field || this.qualification.isTotpField(field.field) || (target.form && !target.form.checkValidity())) return;
    }
    if (event.type === "click") {
      const button = target.closest("button,input[type=submit],input[type=button],a,[role=button]");
      if (!event.isTrusted || !(button instanceof HTMLElement)
        || (!this.qualification.isElementLoginSubmitButton(button) && !this.qualification.isElementChangePasswordSubmitButton(button))) return;
      this.observe(button); return;
    }
    // formdata contents are deliberately never inspected.
    this.observe(target);
  };

  observe(target: Element): void {
    const form = target instanceof HTMLFormElement ? target
      : target instanceof HTMLInputElement || target instanceof HTMLButtonElement ? target.form : null;
    const scopes = new Set(this.fields.filter((field) => form ? field.form === form : !field.form && field.scope.contains(target)).map((field) => field.scope));
    if (scopes.size !== 1) return;
    const scope = [...scopes][0];
    const fields = this.fields.filter((field) => (form ? field.form === form : !field.form && field.scope === scope)
      && this.content.captureFieldCurrent(field));
    const passwords = fields.filter((field) => this.qualification.isCurrentPasswordField(field.field));
    const newPasswords = fields.filter((field) => this.qualification.isNewPasswordField(field.field));
    const selected = newPasswords.length ? newPasswords : passwords;
    if (!selected.length || !selected.some((field) => this.dirty.has(field.element) || this.content.wasGenerated(field.element)) || selected.some((field) => field.element.readOnly)) return;
    const values = new Set(selected.map((field) => field.element.value));
    if (values.size !== 1 || values.has("")) return;
    const password = selected[0].element.value;
    if (password.length > 10000) return;
    const usernames = new Set(fields.filter((field) => this.qualification.isUsernameField(field.field)
      && !this.qualification.isTotpField(field.field)).map((field) => field.element.value).filter(Boolean));
    if (usernames.size > 1) return;
    const username = [...usernames][0] ?? "";
    if (username.length > 2048) return;
    if (this.snapshot?.password === password && this.snapshot.username === username && this.snapshot.url === location.href) return;
    this.clear();
    const snapshot = this.snapshot = { captureId: createVaultMeshUuid(), username, password, url: location.href, expires: Date.now() + 30_000 };
    void this.offer(snapshot);
  }

  private async offer(snapshot: Snapshot): Promise<void> {
    const revision = this.revision;
    try {
      const options = CaptureOptionsSchema.safeParse(await sendSessionMessage({ kind: CAPTURE_OPTIONS, captureId: snapshot.captureId }));
      if (!options.success || revision !== this.revision || snapshot !== this.snapshot || snapshot.url !== location.href || document.hidden) { if (snapshot === this.snapshot) this.clear(); return; }
      snapshot.expires = Math.min(snapshot.expires, Date.parse(options.data.expiresAt));
      const host = this.host = document.createElement("div");
      this.content.ownHost(host);
      host.style.cssText = "position:fixed;z-index:2147483647;right:8px;top:8px;max-width:calc(100vw - 16px);max-height:calc(100vh - 16px);overflow:auto";
      const root = host.attachShadow({ mode: "closed" });
      const style = document.createElement("style");
      style.textContent = ":host{font:13px system-ui;color:#172033}.box{background:white;border:1px solid #b4bccb;border-radius:8px;padding:12px;box-shadow:0 4px 18px #0003;display:grid;gap:8px;width:280px;max-width:calc(100vw - 42px)}button,select{font:inherit;padding:6px;border-radius:4px;border:1px solid #b4bccb;background:white;color:inherit}button{cursor:pointer}button:focus-visible,select:focus-visible{outline:2px solid #2563eb}";
      const box = document.createElement("div"); box.className = "box";
      const text = document.createElement("div"); text.textContent = "VaultMesh：检测到表单提交，是否保存？这不表示网站已接受登录或修改。";
      const select = document.createElement("select"); select.setAttribute("aria-label", "新建登录或选择更新目标");
      select.add(new Option("保存为新登录", ""));
      for (const candidate of options.data.candidates) select.add(new Option(`更新：${candidate.title} · ${candidate.subtitle}`, candidate.id));
      const save = document.createElement("button"); save.type = "button"; save.textContent = "保存";
      const ignore = document.createElement("button"); ignore.type = "button"; ignore.textContent = "忽略";
      ignore.addEventListener("click", (event) => { if (event.isTrusted) this.clear(); });
      save.addEventListener("click", async (event) => {
        if (!event.isTrusted || snapshot !== this.snapshot || snapshot.expires <= Date.now() || snapshot.url !== location.href) return;
        save.disabled = true; select.disabled = true; ignore.disabled = true;
        const message = { kind: CAPTURE_SAVE, captureId: snapshot.captureId, nonce: options.data.nonce,
          username: snapshot.username, password: snapshot.password, ...(select.value ? { itemId: select.value } : {}) };
        clearCapture(snapshot); // no local retry after dispatch
        try {
          const result = await sendSessionMessage(message);
          if (snapshot === this.snapshot) text.textContent = result && typeof result === "object" && "saved" in result && result.saved === true
            ? "已保存到 VaultMesh。" : "保存未确认，请在插件中刷新检查。不会自动重试。";
        } catch { if (snapshot === this.snapshot) text.textContent = "保存未确认，请在插件中刷新检查。不会自动重试。"; }
        finally { clearCapture(message); ignore.disabled = false; ignore.textContent = "关闭"; }
      });
      box.append(text, select, save, ignore); root.append(style, box); document.documentElement.append(host);
    } catch { if (snapshot === this.snapshot) this.clear(); }
  }

  private clear(): void {
    this.revision++; clearCapture(this.snapshot); this.snapshot = undefined; this.host?.remove(); this.host = undefined;
  }
  private detach(root: Document | ShadowRoot): void {
    for (const type of ["focusin", "input", "submit", "formdata", "click", "keydown"]) root.removeEventListener(type, this.onEvent, true);
    this.roots.delete(root);
  }
  destroy(): void {
    this.clear(); if (this.timer) clearInterval(this.timer);
    for (const root of this.roots) this.detach(root);
    window.removeEventListener("pagehide", this.onHide); document.removeEventListener("visibilitychange", this.onVisibility);
    this.fields = []; this.dirty = new WeakSet();
  }
}
