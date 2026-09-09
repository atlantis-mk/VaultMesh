import { LockKeyholeIcon } from "lucide-react";
import { createElement } from "react";
import { createRoot, type Root } from "react-dom/client";

export class InlineAutofillTrigger {
  readonly #host: HTMLDivElement;
  readonly #document: Document;
  readonly #onActivate: (target: HTMLElement) => void;
  readonly #button: HTMLButtonElement;
  readonly #iconRoot: Root;
  readonly #resizeObserver: ResizeObserver | null;
  #target: HTMLElement | null = null;
  #action: "autofill" | "generate-password" = "autofill";
  #locked = false;

  constructor(document: Document, onActivate: (target: HTMLElement) => void) {
    this.#document = document;
    const Observer = document.defaultView?.ResizeObserver;
    this.#resizeObserver = Observer ? new Observer(this.#position) : null;
    this.#onActivate = onActivate;
    this.#host = document.createElement("div");
    this.#host.dataset.vaultmeshAutofillTrigger = "";
    this.#host.style.cssText = "all:initial;position:fixed;z-index:2147483646;display:none";
    const shadow = this.#host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { color-scheme: light dark; }
      * { box-sizing:border-box; }
      button { all:unset;box-sizing:border-box;width:100%;height:100%;display:grid;place-items:center;position:relative;color:#fff;font:800 13px/1 system-ui,sans-serif;cursor:pointer;overflow:visible; }
      .available-mark { width:100%;height:100%;display:grid;place-items:center;border-radius:6px;background:#6d5dfc;box-shadow:0 1px 4px rgba(0,0,0,.22); }
      .locked-mark { width:100%;height:100%;display:grid;place-items:center;position:relative; }
      .lock-badge { position:absolute;right:-3px;bottom:-3px;width:13px;height:13px;display:grid;place-items:center;border-radius:4px;background:#fff;color:#4b5563;box-shadow:0 0 0 1px rgba(31,41,55,.3),0 1px 2px rgba(0,0,0,.2); }
      .lock-badge svg { width:10px;height:10px;stroke-width:2.5; }
      button:hover { filter:brightness(1.08); }
      button:focus-visible { outline:2px solid Highlight;outline-offset:1px; }
    `;
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("aria-label", "显示 VaultMesh 自动填充选项");
    button.title = "显示 VaultMesh 自动填充选项";
    this.#button = button;
    this.#iconRoot = createRoot(button);
    this.#renderIcon();
    shadow.append(style, button);
    document.documentElement.append(this.#host);
    this.#host.addEventListener("pointerdown", this.#onTriggerPointerDown);
    this.#host.addEventListener("click", this.#onClick);
    document.addEventListener("pointerdown", this.#onDocumentPointerDown, true);
    document.addEventListener("input", this.#onTargetInput, true);
    document.defaultView?.addEventListener("resize", this.#position);
    document.defaultView?.addEventListener("scroll", this.#position, true);
  }

  get visible() { return this.#host.style.display !== "none"; }
  get target() { return this.#target; }
  get locked() { return this.#locked; }

  owns(target: EventTarget | null) { return target === this.#host; }

  show(target: HTMLElement, action: "autofill" | "generate-password" = "autofill", locked = false) {
    this.#resizeObserver?.disconnect();
    this.#resizeObserver?.observe(target);
    this.#target = target;
    this.#action = action;
    this.setLocked(locked);
    this.#updateLabel();
    this.#host.style.display = "block";
    this.#host.style.visibility = "visible";
    this.#position();
    this.#document.defaultView?.requestAnimationFrame(this.#position);
  }

  hide() {
    this.#resizeObserver?.disconnect();
    this.#host.style.display = "none";
    this.#target = null;
  }

  setLocked(locked: boolean) {
    this.#locked = locked;
    this.#host.dataset.vaultmeshLocked = String(locked);
    this.#renderIcon();
    this.#updateLabel();
  }

  destroy() {
    this.hide();
    this.#iconRoot.unmount();
    this.#host.removeEventListener("pointerdown", this.#onTriggerPointerDown);
    this.#host.removeEventListener("click", this.#onClick);
    this.#document.removeEventListener("pointerdown", this.#onDocumentPointerDown, true);
    this.#document.removeEventListener("input", this.#onTargetInput, true);
    this.#document.defaultView?.removeEventListener("resize", this.#position);
    this.#document.defaultView?.removeEventListener("scroll", this.#position, true);
    this.#host.remove();
  }

  #updateLabel() {
    const label = this.#locked
      ? "VaultMesh 已锁定，点击解锁插件"
      : this.#action === "generate-password" ? "显示随机密码建议" : "显示 VaultMesh 自动填充选项";
    this.#button.setAttribute("aria-label", label);
    this.#button.title = label;
  }

  #renderIcon() {
    this.#iconRoot.render(this.#locked
      ? createElement("span", { className: "locked-mark", "aria-hidden": true },
          createElement("span", { className: "available-mark" }, "V"),
          createElement("span", { className: "lock-badge" }, createElement(LockKeyholeIcon)),
        )
      : createElement("span", { className: "available-mark", "aria-hidden": true }, "V"));
  }

  readonly #position = () => {
    if (!this.#target || !this.visible || !this.#target.isConnected) return this.hide();
    const rect = this.#target.getBoundingClientRect();
    const viewportWidth = this.#document.defaultView?.innerWidth ?? 0;
    const viewportHeight = this.#document.defaultView?.innerHeight ?? 0;
    if (rect.width <= 0 || rect.height <= 0 || rect.right <= 0 || rect.bottom <= 0 || rect.left >= viewportWidth || rect.top >= viewportHeight) {
      this.#host.style.visibility = "hidden";
      return;
    }
    const size = Math.min(28, Math.max(20, rect.height - 8));
    const nativeInset = this.#nativeTrailingInset(this.#target);
    const obstacleLeft = this.#trailingObstacleLeft(this.#target, rect);
    const trailingEdge = Math.min(rect.right - nativeInset, obstacleLeft === null ? Number.POSITIVE_INFINITY : obstacleLeft - 8);
    const left = trailingEdge - size;
    if (left < rect.left + 4) {
      this.#host.style.visibility = "hidden";
      return;
    }
    const top = rect.top + (rect.height - size) / 2;
    this.#host.style.left = `${left}px`;
    this.#host.style.top = `${top}px`;
    this.#host.style.width = `${size}px`;
    this.#host.style.height = `${size}px`;
    this.#host.style.visibility = "visible";
  };

  #nativeTrailingInset(target: HTMLElement) {
    if (!(target instanceof HTMLInputElement)) return 6;
    const paddingRight = Number.parseFloat(this.#document.defaultView?.getComputedStyle(target).paddingRight ?? "0");
    const hasAppleTrailingControl = target.matches(
      ".signin-form.fed-auth.hide-password .account-name input.form-textbox, " +
      ".signin-form.fed-auth.hide-password .account-name input.form-textbox-input, " +
      ".widget-container .fed-auth .password input.form-textbox-input, " +
      ".widget-container .fed-auth .password input.form-textbox-text",
    );
    const reservedTrailingPadding = hasAppleTrailingControl && Number.isFinite(paddingRight) ? paddingRight : 6;
    // Search controls can include an inaccessible browser-owned clear button.
    return target.type === "search" ? Math.max(42, reservedTrailingPadding) : reservedTrailingPadding;
  }

  #trailingObstacleLeft(target: HTMLElement, inputRect: DOMRect) {
    const selector = 'button,[role="button"],[aria-label],svg,[data-slot="input-end"],[class*="suffix" i],[class*="append" i],[class*="trailing" i],[class*="adornment" i],[class*="eye" i],[class*="clear" i]';
    let obstacleLeft: number | null = null;
    const scopes = new Set<Element>();
    let container = target.parentElement;
    for (let depth = 0; container && depth < 4; depth += 1) {
      if (container === this.#document.body || container === this.#document.documentElement) break;
      scopes.add(container);
      container = container.parentElement;
    }
    const form = target.closest("form,[role='form']");
    if (form && form !== this.#document.body) scopes.add(form);
    const candidates = new Set<Element>();
    for (const scope of scopes) {
      for (const candidate of scope.children) candidates.add(candidate);
      for (const candidate of scope.querySelectorAll<Element>(selector)) candidates.add(candidate);
    }
    for (const candidate of candidates) {
      if (candidate === target || candidate.contains(target) || candidate.closest("[data-vaultmesh-autofill],[data-vaultmesh-autofill-trigger]")) continue;
      const style = this.#document.defaultView?.getComputedStyle(candidate);
      if (style?.display === "none" || style?.visibility === "hidden") continue;
      const rect = candidate.getBoundingClientRect();
      const verticalOverlap = Math.min(inputRect.bottom, rect.bottom) - Math.max(inputRect.top, rect.top);
      if (rect.width <= 0 || rect.height <= 0 || rect.width > Math.min(96, inputRect.width / 2) || verticalOverlap < 4) continue;
      if (rect.left < inputRect.left + inputRect.width / 2 || rect.left >= inputRect.right || rect.right <= inputRect.left) continue;
      obstacleLeft = obstacleLeft === null ? rect.left : Math.min(obstacleLeft, rect.left);
    }
    return obstacleLeft;
  }

  readonly #onTriggerPointerDown = (event: PointerEvent) => event.preventDefault();

  readonly #onClick = () => {
    if (this.#target?.isConnected) this.#onActivate(this.#target);
  };

  readonly #onTargetInput = (event: Event) => {
    if (event.composedPath().includes(this.#target as EventTarget)) this.#document.defaultView?.requestAnimationFrame(this.#position);
  };

  readonly #onDocumentPointerDown = (event: PointerEvent) => {
    if (!this.visible || event.composedPath().includes(this.#host) || event.composedPath().includes(this.#target as EventTarget)) return;
    this.hide();
  };
}
