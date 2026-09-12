import { VaultMeshNativeFillContent } from "./native-fill-content";
import { sendSessionMessage } from "./runtime";
import { FILL_AUTOMATIC, FILL_CANDIDATES, FILL_SELECT, FILL_CANCEL, NativeCandidatesSchema } from "./native-fill-contracts";
import { EMAIL_SELECT, clearEmail, type EmailCandidate } from "./email-otp";
import { SESSION_INVALIDATED } from "./contracts";

/** Presentation/lifecycle only. Qualification, collection and fill stay in Bitwarden. */
export class VaultMeshNativePageContent {
  private host?: HTMLDivElement;
  private root?: ShadowRoot;
  private field?: HTMLInputElement;
  private target?: Awaited<ReturnType<VaultMeshNativeFillContent["createTarget"]>>;
  private revision = 0;
  private url = location.href;
  private attempted = new WeakSet<HTMLElement>();
  private scanning = false;
  private scanTimer?: ReturnType<typeof setTimeout>;
  private lifecycleTimer?: ReturnType<typeof setInterval>;
  private observer?: MutationObserver;
  private readonly owned = new WeakSet<Node>();
  private emailCandidates: EmailCandidate[] = [];
  private readonly invalidated = (message: unknown, sender: chrome.runtime.MessageSender) => {
    if (sender.id === chrome.runtime.id && !sender.tab && message && typeof message === "object" && "kind" in message && [SESSION_INVALIDATED, FILL_CANCEL].includes(message.kind as string)) { this.close(); this.content.invalidate(); }
  };
  constructor(private readonly content: VaultMeshNativeFillContent) {}

  start(): void {
    chrome.runtime.onMessage.addListener(this.invalidated);
    document.addEventListener("focusin", this.onFocus, true);
    document.addEventListener("pointerdown", this.onOutside, true);
    document.addEventListener("keydown", this.onKey, true);
    document.addEventListener("visibilitychange", this.onVisibility);
    window.addEventListener("pagehide", this.onPageHide);
    window.addEventListener("pageshow", this.onPageShow);
    window.addEventListener("scroll", this.position, true);
    window.addEventListener("resize", this.position);
    window.visualViewport?.addEventListener("resize", this.position);
    window.visualViewport?.addEventListener("scroll", this.position);
    this.observer = new MutationObserver((mutations) => {
      if (mutations.every((mutation) => this.owned.has(mutation.target)
        || (mutation.type === "childList" && [...mutation.addedNodes, ...mutation.removedNodes].every((node) => this.owned.has(node))))) return;
      if (this.target) {
        const field = this.field;
        this.close();
        if (field?.isConnected && document.activeElement === field) void this.offer(field).catch(() => this.close());
      }
      this.scheduleScan();
    });
    this.observer.observe(document, { childList: true, subtree: true, attributes: true,
      attributeFilter: ["type", "name", "id", "autocomplete", "readonly", "disabled", "hidden", "style", "class", "aria-label"] });
    this.lifecycleTimer = setInterval(() => {
      if (location.href !== this.url) {
        this.url = location.href; this.attempted = new WeakSet(); this.content.invalidate(); this.close(); this.scheduleScan();
      }
      if (this.target && !this.content.targetCurrent(this.target.targetRef)) this.close();
      if (this.emailCandidates.some((candidate) => candidate.expiresAt * 1000 <= Date.now())) this.close();
    }, 500);
    this.scheduleScan();
  }

  private readonly onVisibility = () => { if (document.hidden) { this.close(); this.content.invalidate(); } else this.scheduleScan(); };
  private readonly onPageHide = () => { this.close(); this.content.invalidate(); this.observer?.disconnect(); };
  private readonly onPageShow = () => {
    this.observer?.observe(document, { childList: true, subtree: true, attributes: true });
    this.scheduleScan();
  };
  private readonly onOutside = (event: Event) => {
    if (event.target !== this.field && !event.composedPath().includes(this.host!)) this.close();
  };
  private readonly onKey = (event: KeyboardEvent) => {
    if (event.isComposing || !this.host) return;
    if (event.key === "Escape") { this.close(); this.field?.focus(); }
    if (event.key === "Tab") this.close();
  };
  private readonly onFocus = (event: FocusEvent) => {
    const element = event.composedPath()[0];
    if (!event.isTrusted) return;
    if (!(element instanceof HTMLInputElement)) {
      if (!event.composedPath().includes(this.host!)) this.close();
      return;
    }
    void this.offer(element).catch(() => this.close());
  };

  async offer(element: HTMLInputElement): Promise<void> {
    this.close();
    const revision = this.revision;
    const target = await this.content.createTarget(element);
    if (!target || revision !== this.revision || document.hidden || !this.content.targetCurrent(target.targetRef)) return;
    this.field = element; this.target = target;
    const host = this.host = document.createElement("div");
    this.content.ownHost(host);
    this.owned.add(host);
    host.style.cssText = "all:initial;position:fixed;z-index:2147483647;display:block;";
    this.root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = "button{box-sizing:border-box;font:13px system-ui;color:#172033;background:#fff;border:1px solid #b4bccb;border-radius:6px;cursor:pointer;padding:6px;text-align:left}button:focus-visible{outline:2px solid #2563eb}button:hover{background:#edf3ff}.list{display:flex;flex-direction:column;gap:4px;background:#fff;padding:6px;border:1px solid #b4bccb;border-radius:8px;overflow:auto;max-height:60vh;box-shadow:0 4px 18px #0003}.notice{font:13px system-ui;color:#172033;background:white;padding:8px;max-width:260px}img{width:18px;height:18px;display:block}";
    this.root.append(style);
    const button = document.createElement("button");
    button.type = "button"; button.setAttribute("aria-label", "VaultMesh：选择填充");
    const icon = document.createElement("img"); icon.src = chrome.runtime.getURL("images/icon32.png"); icon.alt = "";
    button.append(icon);
    button.addEventListener("click", (event) => { if (event.isTrusted) void this.showCandidates(); });
    this.root.append(button); document.documentElement.append(host); this.position();
  }

  private async showCandidates(): Promise<void> {
    const target = this.target; const revision = this.revision;
    if (!target || !this.content.targetCurrent(target.targetRef)) { this.close(); return; }
    try {
      const raw = await sendSessionMessage({ kind: FILL_CANDIDATES, targetRef: target.targetRef, context: target.context });
      const response = NativeCandidatesSchema.safeParse(raw);
      if (raw && typeof raw === "object" && "emailOtpCandidates" in raw) clearEmail({ candidates: raw.emailOtpCandidates });
      if (revision !== this.revision) { if (response.success) clearEmail({ candidates: response.data.emailOtpCandidates }); return; }
      if (!this.content.targetCurrent(target.targetRef)) { this.close(); return; }
      if (!response.success || !response.data.candidates.length && !response.data.emailOtpCandidates?.length) { this.notice("请先在插件中解锁，或保存此网站的登录项目。"); return; }
      this.emailCandidates = response.data.emailOtpCandidates ?? [];
      this.root?.querySelector("button")?.remove();
      const list = document.createElement("div"); list.className = "list"; list.setAttribute("aria-label", "VaultMesh 登录候选");
      for (const candidate of this.emailCandidates) {
        if (candidate.expiresAt * 1000 <= Date.now()) { candidate.code = ""; continue; }
        const button = document.createElement("button"); button.type = "button"; button.textContent = `${candidate.code} · ${candidate.sourceDomain}`;
        button.addEventListener("click", async (event) => {
          if (!event.isTrusted || candidate.expiresAt * 1000 <= Date.now() || !this.content.targetCurrent(target.targetRef)) return;
          list.querySelectorAll("button").forEach((entry) => { entry.disabled = true; });
          const id = candidate.id; clearEmail({ candidates: this.emailCandidates });
          try { await sendSessionMessage({ kind: EMAIL_SELECT, targetRef: target.targetRef, context: "otp", id }); }
          finally { if (revision === this.revision) this.close(); }
        }); list.append(button);
      }
      for (const candidate of response.data.candidates) {
        const button = document.createElement("button"); button.type = "button";
        button.textContent = `${candidate.title} · ${candidate.subtitle}${candidate.masterPasswordReprompt ? " · 需要主密码" : ""}`;
        button.addEventListener("click", async (event) => {
          if (!event.isTrusted || !this.content.targetCurrent(target.targetRef)) return;
          list.querySelectorAll("button").forEach((entry) => { entry.disabled = true; });
          try {
            const result = await sendSessionMessage({ kind: FILL_SELECT, targetRef: target.targetRef, context: target.context, id: candidate.id });
            if (revision !== this.revision) return;
            if (result && typeof result === "object" && "reprompt" in result && result.reprompt === true) {
              this.notice("请打开 VaultMesh 插件，选择此项目并输入主密码。原表单目标保留 30 秒。");
            } else this.close();
          } catch { if (revision === this.revision) this.notice("填充未确认，请重新选择；不会自动重试。"); }
        });
        list.append(button);
      }
      list.addEventListener("keydown", (event) => {
        if (event.isComposing || !["ArrowDown", "ArrowUp"].includes(event.key)) return;
        event.preventDefault();
        const buttons = [...list.querySelectorAll("button")];
        const index = buttons.indexOf(this.root?.activeElement as HTMLButtonElement);
        buttons[(index + (event.key === "ArrowDown" ? 1 : buttons.length - 1)) % buttons.length]?.focus();
      });
      this.root?.append(list); this.position(); list.querySelector("button")?.focus();
    } catch { if (revision === this.revision) this.close(); }
  }

  private notice(text: string): void {
    this.root?.querySelectorAll("button,.list,.notice").forEach((node) => node.remove());
    const notice = document.createElement("div"); notice.className = "notice"; notice.textContent = text;
    this.root?.append(notice); this.position();
  }

  private readonly position = () => {
    if (!this.host || !this.field) return;
    const rect = this.field.getBoundingClientRect();
    const viewport = window.visualViewport;
    const left = viewport?.offsetLeft ?? 0, top = viewport?.offsetTop ?? 0;
    const width = viewport?.width ?? window.innerWidth, height = viewport?.height ?? window.innerHeight;
    this.host.style.maxWidth = `${Math.max(0, width - 8)}px`;
    this.host.style.maxHeight = `${Math.max(0, height - 8)}px`;
    this.host.style.overflow = "auto";
    this.host.style.left = `${Math.max(left + 4, Math.min(rect.right - 34, left + width - this.host.offsetWidth - 4))}px`;
    this.host.style.top = `${Math.max(top + 4, Math.min(rect.top, top + height - this.host.offsetHeight - 4))}px`;
  };

  private close(): void {
    clearEmail({ candidates: this.emailCandidates }); this.emailCandidates = [];
    this.revision++;
    if (this.target) this.content.releaseTarget(this.target.targetRef);
    this.host?.remove(); this.host = undefined; this.root = undefined; this.target = null;
  }

  private scheduleScan(): void {
    if (this.scanTimer) clearTimeout(this.scanTimer);
    this.scanTimer = setTimeout(() => { void this.automatic(); }, 500);
  }

  private async automatic(): Promise<void> {
    if (this.scanning || this.host || document.hidden) return;
    this.scanning = true;
    try {
      const url = location.href;
      for (const element of await this.content.automaticTargets()) {
        if (url !== location.href || this.host || document.hidden) return;
        const target = await this.content.createTarget(element);
        if (!target?.automatic || this.attempted.has(target.scope)) continue;
        this.attempted.add(target.scope); // one attempt per local form/document; never retry a page write
        await sendSessionMessage({ kind: FILL_AUTOMATIC, targetRef: target.targetRef, context: target.context });
      }
    } catch { /* Locked, ambiguous and stale automatic requests fail closed. */ }
    finally { this.scanning = false; }
  }

  destroy(): void {
    chrome.runtime.onMessage.removeListener(this.invalidated);
    this.close(); this.content.invalidate(); this.observer?.disconnect();
    if (this.scanTimer) clearTimeout(this.scanTimer);
    if (this.lifecycleTimer) clearInterval(this.lifecycleTimer);
    document.removeEventListener("focusin", this.onFocus, true); document.removeEventListener("pointerdown", this.onOutside, true);
    document.removeEventListener("keydown", this.onKey, true); document.removeEventListener("visibilitychange", this.onVisibility);
    window.removeEventListener("pagehide", this.onPageHide); window.removeEventListener("pageshow", this.onPageShow);
    window.removeEventListener("scroll", this.position, true); window.removeEventListener("resize", this.position);
    window.visualViewport?.removeEventListener("resize", this.position); window.visualViewport?.removeEventListener("scroll", this.position);
  }
}
