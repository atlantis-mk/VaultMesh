import { createElement } from "react";
import { flushSync } from "react-dom";
import { createRoot, type Root } from "react-dom/client";

import { InlineAutofillView } from "@/lib/inline-autofill-view";
import { classifyControl } from "@/lib/form-discovery";
import { inlineMenuLayout } from "@/lib/inline-menu-layout";
import type { GeneratedLogin, PasswordGeneratorOptions, UsernameGeneratorOptions } from "@/lib/generated-credentials";
import { DEFAULT_PASSWORD_GENERATOR_OPTIONS, DEFAULT_USERNAME_GENERATOR_OPTIONS } from "@/lib/generator-preferences";
import type { InlineAutofillCandidate } from "@/lib/protocol";

export class InlineAutofillMenu {
  readonly #host: HTMLDivElement;
  readonly #shadow: ShadowRoot;
  readonly #root: Root;
  readonly #document: Document;
  readonly #resizeObserver: ResizeObserver | null;
  readonly #onSelect: (candidate: InlineAutofillCandidate, target: HTMLElement) => void;
  readonly #onGeneratedSelect: (login: GeneratedLogin, target: HTMLElement) => void;
  readonly #onGeneratedPasswordSelect: (password: string, target: HTMLElement) => void;
  #target: HTMLElement | null = null;
  #anchor: HTMLElement | null = null;
  #candidates: InlineAutofillCandidate[] = [];
  #generatedLoginKey = 0;
  #generatedMode: "none" | "login" | "password" = "none";
  #generatedEmailRequired = false;
  #statusMessage: string | null = null;
  #passwordGeneratorOptions = DEFAULT_PASSWORD_GENERATOR_OPTIONS;
  #usernameGeneratorOptions = DEFAULT_USERNAME_GENERATOR_OPTIONS;

  constructor(
    document: Document,
    onSelect: (candidate: InlineAutofillCandidate, target: HTMLElement) => void,
    onGeneratedSelect: (login: GeneratedLogin, target: HTMLElement) => void,
    onGeneratedPasswordSelect: (password: string, target: HTMLElement) => void,
  ) {
    this.#document = document;
    const Observer = document.defaultView?.ResizeObserver;
    this.#resizeObserver = Observer ? new Observer(this.#position) : null;
    this.#onSelect = onSelect;
    this.#onGeneratedSelect = onGeneratedSelect;
    this.#onGeneratedPasswordSelect = onGeneratedPasswordSelect;
    this.#host = document.createElement("div");
    this.#host.dataset.vaultmeshAutofill = "";
    this.#host.style.cssText = "all:initial;position:fixed;z-index:2147483647;display:none";
    this.#shadow = this.#host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { color-scheme: light dark; }
      * { box-sizing: border-box; }
      .panel { box-sizing:border-box;width:100%; max-height:var(--vaultmesh-menu-max-height,280px); overflow:auto; border:1px solid rgba(127,127,127,.35); border-radius:10px; background:Canvas; color:CanvasText; box-shadow:0 12px 32px rgba(0,0,0,.22); font:13px/1.35 system-ui,sans-serif; }
      .mark { display:grid;place-items:center;width:22px;height:22px;border-radius:6px;background:#6d5dfc;color:white;font-weight:800; }
      .candidate-scroll { position:relative;max-height:var(--vaultmesh-menu-max-height,280px);overflow:hidden; }
      [data-slot="scroll-area-viewport"] { width:100%;max-height:inherit;overflow-x:hidden;overflow-y:auto;scrollbar-width:none; }
      [data-slot="scroll-area-content"] { width:100%;min-width:0; }
      [data-slot="scroll-area-scrollbar"] { position:absolute;top:3px;right:2px;bottom:3px;display:flex;width:8px;padding:1px;touch-action:none;user-select:none; }
      [data-slot="scroll-area-thumb"] { position:relative;flex:1;border-radius:999px;background:rgba(127,127,127,.45); }
      .groups { padding:4px; }
      .group + .group { margin-top:4px;padding-top:4px;border-top:1px solid rgba(127,127,127,.25); }
      .group-label { padding:5px 8px 4px;color:GrayText;font-size:11px;font-weight:650;letter-spacing:.01em; }
      .option { width:100%;display:flex;align-items:center;gap:10px;border:0;border-radius:7px;padding:8px;background:transparent;color:inherit;text-align:left;font:inherit;cursor:pointer; }
      .option:hover,.option:focus-visible { background:color-mix(in srgb, Highlight 14%, transparent);outline:2px solid transparent; }
      .text { min-width:0;display:flex;flex-direction:column; }
      .name,.subtitle { overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
      .name { font-weight:600; }.subtitle { color:GrayText;font-size:12px; }
      .generated { padding:4px; }
      .generated-heading { display:flex;align-items:center;justify-content:space-between;padding:4px 5px 2px 8px;color:GrayText;font-size:11px;font-weight:650; }
      .refresh { display:grid;place-items:center;width:24px;height:24px;border:0;border-radius:6px;background:transparent;color:inherit;font:700 17px/1 system-ui,sans-serif;cursor:pointer; }
      .refresh:hover,.refresh:focus-visible { background:color-mix(in srgb, Highlight 14%, transparent);outline:2px solid transparent; }
      .generated-mark { background:#268a5b; }
      .generated-password { font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:CanvasText; }
      .empty { padding:10px;color:GrayText; }
      .status { padding:10px;color:CanvasText;background:color-mix(in srgb, Mark 32%, transparent); }
    `;
    const mount = document.createElement("div");
    this.#shadow.append(style, mount);
    this.#root = createRoot(mount);
    document.documentElement.append(this.#host);
    document.addEventListener("keydown", this.#onKeyDown, true);
    document.addEventListener("pointerdown", this.#onPointerDown, true);
    document.defaultView?.addEventListener("resize", this.#position);
    document.defaultView?.addEventListener("scroll", this.#position, true);
    document.defaultView?.visualViewport?.addEventListener("resize", this.#position);
    document.defaultView?.visualViewport?.addEventListener("scroll", this.#position);
    document.defaultView?.addEventListener("blur", this.#onWindowBlur);
  }

  get visible() { return this.#host.style.display !== "none"; }
  get generatedMode() { return this.#generatedMode; }
  get statusMessage() { return this.#statusMessage; }

  owns(target: EventTarget | null) { return target === this.#host; }

  show(
    target: HTMLElement,
    candidates: InlineAutofillCandidate[],
    generatedMode: "none" | "login" | "password" = "none",
    options: {
      anchor?: HTMLElement;
      generatedEmailRequired?: boolean;
      passwordGeneratorOptions?: PasswordGeneratorOptions;
      usernameGeneratorOptions?: UsernameGeneratorOptions;
    } = {},
  ) {
    this.#target = target;
    this.#anchor = options.anchor ?? target;
    this.#resizeObserver?.disconnect();
    this.#resizeObserver?.observe(this.#anchor);
    this.#candidates = candidates;
    this.#generatedMode = generatedMode === "login" && candidates.length > 0 ? "none" : generatedMode;
    this.#statusMessage = null;
    this.#generatedEmailRequired = options.generatedEmailRequired ?? false;
    this.#passwordGeneratorOptions = options.passwordGeneratorOptions ?? DEFAULT_PASSWORD_GENERATOR_OPTIONS;
    this.#usernameGeneratorOptions = options.usernameGeneratorOptions ?? DEFAULT_USERNAME_GENERATOR_OPTIONS;
    this.#generatedLoginKey += 1;
    this.#render();
    this.#host.style.display = "block";
    this.#position();
  }

  showStatus(target: HTMLElement, message: string) {
    this.#target = target;
    this.#anchor = target;
    this.#resizeObserver?.disconnect();
    this.#resizeObserver?.observe(target);
    this.#candidates = [];
    this.#generatedMode = "none";
    this.#generatedEmailRequired = false;
    this.#statusMessage = message;
    this.#render();
    this.#host.style.display = "block";
    this.#position();
  }

  hide() {
    this.#resizeObserver?.disconnect();
    this.#host.style.display = "none";
    this.#target = null;
    this.#anchor = null;
    this.#candidates = [];
    this.#generatedMode = "none";
    this.#generatedEmailRequired = false;
    this.#statusMessage = null;
    flushSync(() => this.#root.render(null));
  }

  destroy() {
    this.hide();
    this.#document.removeEventListener("keydown", this.#onKeyDown, true);
    this.#document.removeEventListener("pointerdown", this.#onPointerDown, true);
    this.#document.defaultView?.removeEventListener("resize", this.#position);
    this.#document.defaultView?.removeEventListener("scroll", this.#position, true);
    this.#document.defaultView?.visualViewport?.removeEventListener("resize", this.#position);
    this.#document.defaultView?.visualViewport?.removeEventListener("scroll", this.#position);
    this.#document.defaultView?.removeEventListener("blur", this.#onWindowBlur);
    this.#root.unmount();
    this.#host.remove();
  }

  readonly #position = () => {
    if (!this.#target || !this.visible || !classifyControl(this.#target)) return this.hide();
    const rect = this.#anchor?.isConnected ? this.#anchor.getBoundingClientRect() : this.#target.getBoundingClientRect();
    const view = this.#document.defaultView;
    const visual = view?.visualViewport;
    const layout = inlineMenuLayout(rect, {
      width: visual?.width ?? view?.innerWidth ?? 640, height: visual?.height ?? view?.innerHeight ?? 640,
      left: visual?.offsetLeft, top: visual?.offsetTop,
    });
    if (!layout) return this.hide();
    this.#host.style.left = `${layout.left}px`;
    this.#host.style.width = `${layout.width}px`;
    this.#host.style.setProperty("--vaultmesh-menu-max-height", `${layout.maxHeight}px`);
    this.#host.style.top = layout.top === undefined ? "auto" : `${layout.top}px`;
    this.#host.style.bottom = layout.bottom === undefined ? "auto" : `${(view?.innerHeight ?? 640) - layout.bottom}px`;
  };

  readonly #onKeyDown = (event: KeyboardEvent) => {
    if (!this.visible || event.isComposing) return;
    if (event.key === "Tab") { this.hide(); return; }
    if (event.key === "Escape") {
      event.preventDefault();
      const target = this.#target;
      this.hide();
      target?.focus();
      return;
    }
    const buttons = Array.from(this.#shadow.querySelectorAll<HTMLButtonElement>('button[role="option"]'));
    const focused = this.#shadow.activeElement;
    if (event.key === "Enter" && focused instanceof HTMLButtonElement) {
      event.preventDefault();
      focused.click();
      return;
    }
    if (buttons.length === 0 || (event.key !== "ArrowDown" && event.key !== "ArrowUp")) return;
    const index = buttons.indexOf(focused as HTMLButtonElement);
    const next = event.key === "ArrowDown" ? (index + 1) % buttons.length : (index <= 0 ? buttons.length : index) - 1;
    event.preventDefault();
    buttons[next]?.focus();
  };

  readonly #onPointerDown = (event: PointerEvent) => {
    if (!this.visible || event.composedPath().includes(this.#host) || event.composedPath().includes(this.#target as EventTarget)) return;
    this.hide();
  };

  readonly #onWindowBlur = () => this.hide();

  #render() {
    const location = this.#document.defaultView?.location;
    flushSync(() => {
      this.#root.render(createElement(InlineAutofillView, {
        candidates: this.#candidates,
        currentHost: location?.host ?? "当前站点",
        currentHostname: location?.hostname ?? "当前域名",
        generatedLoginKey: this.#generatedLoginKey,
        generatedMode: this.#generatedMode,
        generatedEmailRequired: this.#generatedEmailRequired,
        statusMessage: this.#statusMessage,
        passwordGeneratorOptions: this.#passwordGeneratorOptions,
        usernameGeneratorOptions: this.#usernameGeneratorOptions,
        onGeneratedPasswordSelect: (password) => {
          const target = this.#target;
          this.hide();
          if (target) this.#onGeneratedPasswordSelect(password, target);
        },
        onGeneratedSelect: (login) => {
          const target = this.#target;
          this.hide();
          if (target) this.#onGeneratedSelect(login, target);
        },
        onSelect: (candidate) => {
          const target = this.#target;
          this.hide();
          if (target) this.#onSelect(candidate, target);
        },
      }));
    });
  }
}
