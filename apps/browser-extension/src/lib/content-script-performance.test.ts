import { afterEach, describe, expect, it, vi } from "vitest";

import { startAutofillPage } from "./autofill-page";
import { discoverFields } from "./form-discovery";
import { AutofillTargets } from "./autofill-targets";
import type { AutofillTarget } from "./protocol";

// Content-script cost is measured as DOM work, not as wall-clock time: element
// visits and computed-style reads are engine independent and do not depend on
// the machine running the suite.
type WorkCounters = {
  queryCalls: number;
  queryElements: number;
  starCalls: number;
  starElements: number;
  computedStyles: number;
};

function startWorkCounters(): WorkCounters {
  const counters: WorkCounters = { queryCalls: 0, queryElements: 0, starCalls: 0, starElements: 0, computedStyles: 0 };
  const record = (selector: string, length: number) => {
    counters.queryCalls += 1;
    counters.queryElements += length;
    if (selector === "*") {
      counters.starCalls += 1;
      counters.starElements += length;
    }
  };
  const documentQuery = document.querySelectorAll.bind(document);
  vi.spyOn(document, "querySelectorAll").mockImplementation(((selector: string) => {
    const result = documentQuery(selector);
    record(selector, result.length);
    return result;
  }) as typeof document.querySelectorAll);
  const elementQuery = Element.prototype.querySelectorAll;
  vi.spyOn(Element.prototype, "querySelectorAll").mockImplementation(function (this: Element, selector: string) {
    const result = elementQuery.call(this, selector);
    record(selector, result.length);
    return result;
  } as typeof Element.prototype.querySelectorAll);
  const computed = window.getComputedStyle.bind(window);
  vi.spyOn(window, "getComputedStyle").mockImplementation(((element: Element, pseudo?: string | null) => {
    counters.computedStyles += 1;
    return computed(element, pseudo as never);
  }) as typeof window.getComputedStyle);
  return counters;
}

function makeVisible(element: HTMLElement) {
  Object.defineProperty(element, "getClientRects", { value: () => [{ width: 240, height: 32 }] });
}

function buildLargePage(rows: number, scatteredInputs: number, withLoginForm: boolean) {
  const container = document.createElement("div");
  for (let row = 0; row < rows; row += 1) {
    const block = document.createElement("div");
    block.className = `row row-${row}`;
    for (let cell = 0; cell < 3; cell += 1) {
      block.append(document.createElement("span"));
    }
    if (scatteredInputs > 0 && row % Math.max(1, Math.floor(rows / scatteredInputs)) === 0) {
      const input = document.createElement("input");
      input.type = "text";
      input.name = `field-${row}`;
      block.append(input);
    }
    container.append(block);
  }
  if (withLoginForm) {
    container.insertAdjacentHTML("beforeend", '<form><input autocomplete="username"><input type="password"></form>');
  }
  document.body.append(container);
  for (const input of document.querySelectorAll<HTMLInputElement>("input")) makeVisible(input);
  return container;
}

type SendMessageSpy = { (message: unknown): Promise<unknown>; mock: { calls: unknown[][] } };

function readyCount(sendMessage: SendMessageSpy) {
  return sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready").length;
}

/**
 * jsdom marks every dispatched event untrusted, so the content script's
 * user-input path is exercised by invoking its registered listener with a
 * trusted-shaped event instead of weakening the production check.
 */
function mountWithInputControl(sendMessage: SendMessageSpy) {
  const inputListeners: EventListener[] = [];
  const addEventListener = document.addEventListener.bind(document);
  const registration = vi.spyOn(document, "addEventListener").mockImplementation((type, listener, options) => {
    if (type === "input") inputListeners.push(listener as EventListener);
    addEventListener(type, listener, options as AddEventListenerOptions);
  });
  const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
  registration.mockRestore();
  return {
    controller,
    dispatchInput: (target: Element) => inputListeners[inputListeners.length - 1]!({ isTrusted: true, composedPath: () => [target] } as unknown as Event),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  document.body.innerHTML = "";
  for (const host of document.querySelectorAll("[data-vaultmesh-autofill],[data-vaultmesh-autofill-trigger],[data-vaultmesh-save-prompt]")) host.remove();
});

describe("CT-AUTOFILL-001 content script discovery cost", () => {
  it("bounds whole-document walks for a large page with scattered fields", () => {
    for (let iteration = 0; iteration < 2; iteration += 1) {
      document.body.innerHTML = "";
      const container = buildLargePage(1200, 8, true);
      const elementCount = document.querySelectorAll("*").length;
      const counters = startWorkCounters();

      // Four discoveries with no DOM change in between: the previous
      // implementation re-walked the tree for every ancestor of every field,
      // which is what made these pages unusable.
      const passes = 4;
      for (let pass = 0; pass < passes; pass += 1) discoverFields(document);

      // One walk of the tree per discovery pass is expected; anything close to
      // the number of fields times the depth of the tree is the old failure.
      expect(counters.starCalls).toBeLessThanOrEqual(passes * 4);
      expect(counters.starElements).toBeLessThanOrEqual(elementCount * passes * 2);
      vi.restoreAllMocks();
      container.remove();
    }
  }, 20_000);

  it("does not rescan for page mutations", async () => {
    vi.useFakeTimers();
    buildLargePage(500, 0, true);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    await vi.advanceTimersByTimeAsync(200);
    expect(readyCount(sendMessage)).toBe(1);

    // Restyling thousands of unrelated nodes is what a live site does; it must
    // not schedule a page rescan for each batch.
    const rows = document.querySelectorAll("div.row");
    for (let index = 0; index < rows.length; index += 1) rows[index]!.className = `row restyled-${index}`;
    await vi.advanceTimersByTimeAsync(1_000);
    expect(readyCount(sendMessage)).toBe(1);

    // Even a field's own semantic metadata change is read by the next
    // discovery instead of buying a document-wide pass.
    document.querySelector<HTMLInputElement>('input[type="password"]')!.setAttribute("aria-label", "Current password");
    await vi.advanceTimersByTimeAsync(1_000);
    expect(readyCount(sendMessage)).toBe(1);
    expect(discoverFields(document).descriptors.some((field) => field.label.includes("Current password"))).toBe(true);
    controller.dispose();
  });

  it("does not walk the document for feed-style structural churn", async () => {
    vi.useFakeTimers();
    const container = buildLargePage(300, 0, true);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    await vi.advanceTimersByTimeAsync(200);
    expect(readyCount(sendMessage)).toBe(1);

    // Live lists append and remove plain markup continuously. None of it can
    // introduce a field, so none of it may buy a document-wide walk.
    const counters = startWorkCounters();
    const feed = document.createElement("div");
    container.append(feed);
    for (let tick = 0; tick < 40; tick += 1) {
      const item = document.createElement("div");
      item.className = "feed-item";
      item.append(document.createElement("span"));
      feed.append(item);
      feed.firstElementChild?.remove();
      await vi.advanceTimersByTimeAsync(30);
    }
    await vi.advanceTimersByTimeAsync(500);
    expect(readyCount(sendMessage)).toBe(1);

    // A real field restores readiness via its local container, not the document.
    const field = document.createElement("input");
    field.type = "password";
    makeVisible(field);
    feed.append(field);
    await vi.advanceTimersByTimeAsync(500);
    expect(readyCount(sendMessage)).toBe(2);
    expect(counters.starElements).toBeLessThanOrEqual(2);
    expect(document.querySelectorAll).not.toHaveBeenCalled();
    vi.restoreAllMocks();
    expect(discoverFields(document).descriptors.some((descriptor) => descriptor.inputType === "password")).toBe(true);
    controller.dispose();
  });

  it("ignores mutations of its own injected UI", async () => {
    vi.useFakeTimers();
    buildLargePage(50, 0, true);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    await vi.advanceTimersByTimeAsync(200);
    expect(readyCount(sendMessage)).toBe(1);

    const host = document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!;
    host.style.display = "block";
    host.dataset.vaultmeshLocked = "false";
    await vi.advanceTimersByTimeAsync(1_000);
    expect(readyCount(sendMessage)).toBe(1);
    controller.dispose();
  });

  it("tracks edits from keystrokes without running discovery", async () => {
    vi.useFakeTimers();
    buildLargePage(400, 0, false);
    document.body.insertAdjacentHTML("beforeend", '<form><input autocomplete="username" value="ada"><input id="password" type="password" autocomplete="current-password" value="privately-typed"></form>');
    for (const input of document.querySelectorAll<HTMLInputElement>("input")) makeVisible(input);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const { controller, dispatchInput } = mountWithInputControl(sendMessage);
    const username = document.querySelector<HTMLInputElement>('input[autocomplete="username"]')!;
    const password = document.querySelector<HTMLInputElement>("#password")!;
    controller.recordFilledItem({ kind: "login", id: crypto.randomUUID() }, [username, password]);

    const counters = startWorkCounters();
    for (let index = 0; index < 10; index += 1) {
      password.value += "x";
      dispatchInput(password);
    }
    expect(counters.starCalls).toBe(0);
    expect(counters.computedStyles).toBe(0);
    vi.restoreAllMocks();

    await vi.advanceTimersByTimeAsync(200);
    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture" }));
    controller.dispose();
  });

  it("does not offer a filled login again when the user never edited it", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = '<form><input autocomplete="username" value="ada"><input id="password" type="password" autocomplete="current-password" value="from-the-vault"></form>';
    document.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    controller.recordFilledItem({ kind: "login", id: crypto.randomUUID() }, [document.querySelector<HTMLInputElement>("#password")!]);

    await vi.advanceTimersByTimeAsync(200);
    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    expect(sendMessage.mock.calls.some(([message]) => (message as { kind?: string }).kind === "vaultmesh.save-capture")).toBe(false);
    controller.dispose();
  });

  it.each(["form", "section"])("signals an asynchronous %s with a resolvable target and no document discovery", async (tag) => {
    vi.useFakeTimers();
    buildLargePage(500, 10, false);
    const documentId = crypto.randomUUID();
    const targets = new AutofillTargets();
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, documentId, sendMessage, (control) => targets.capture(control, documentId));
    try {
      await vi.advanceTimersByTimeAsync(200);
      sendMessage.mockClear();
      const local = document.createElement(tag);
      local.innerHTML = '<input autocomplete="username" value="private-async-user"><input type="password" value="private-async-password">';
      const fields = [...local.querySelectorAll<HTMLInputElement>("input")];
      fields.forEach(makeVisible);
      const counters = startWorkCounters();
      document.body.append(local);
      await vi.advanceTimersByTimeAsync(150);
      expect(document.querySelectorAll).not.toHaveBeenCalled();
      expect(counters.starElements).toBeLessThanOrEqual(8);
      const ready = sendMessage.mock.calls.find(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready")?.[0] as { target: AutofillTarget };
      expect(ready).toBeDefined();
      expect(JSON.stringify(sendMessage.mock.calls)).not.toContain("private-async");
      vi.restoreAllMocks();
      expect(targets.resolve(ready.target, documentId)).toEqual(new Set(fields));
    } finally { controller.dispose(); }
  });

  it("restores a hidden form from a body visibility change without document discovery", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = '<form hidden><input autocomplete="username"><input type="password"></form>';
    const form = document.querySelector<HTMLFormElement>("form")!;
    form.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    try {
      expect(readyCount(sendMessage)).toBe(0);
      const counters = startWorkCounters();
      form.hidden = false;
      await vi.advanceTimersByTimeAsync(150);
      expect(readyCount(sendMessage)).toBe(1);
      expect(document.querySelectorAll).not.toHaveBeenCalled();
      expect(counters.starElements).toBeLessThanOrEqual(4);
    } finally { controller.dispose(); }
  });

  it.each(["hidden", "inert", "aria-hidden"])("withdraws a shadow-field trigger when its host becomes %s", async (attribute) => {
    vi.useFakeTimers();
    const host = document.createElement("vaultmesh-shadow-target");
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = '<form><input autocomplete="username"><input type="password"></form>';
    const field = root.querySelector<HTMLInputElement>("input")!;
    root.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);
    document.body.append(host);
    const controller = startAutofillPage(document, crypto.randomUUID(), vi.fn(async () => ({})));
    try {
      field.focus();
      await Promise.resolve();
      expect(controller.trigger.visible).toBe(true);
      host.setAttribute(attribute, attribute === "aria-hidden" ? "true" : "");
      await vi.advanceTimersByTimeAsync(150);
      expect(controller.trigger.visible).toBe(false);
    } finally { controller.dispose(); }
  });

  it("does not postpone dynamic readiness indefinitely under continuous semantic mutation", async () => {
    vi.useFakeTimers();
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    try {
      const form = document.createElement("form");
      form.innerHTML = '<input autocomplete="username"><input type="password">';
      form.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);
      document.body.append(form);
      for (let index = 0; index < 8; index += 1) {
        form.setAttribute("aria-label", `Login ${index}`);
        await vi.advanceTimersByTimeAsync(20);
      }
      expect(readyCount(sendMessage)).toBe(1);
    } finally { controller.dispose(); }
  });


  it("preserves canonical target binding when a password is inserted in a different nested wrapper", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = '<section><div><input autocomplete="username"></div><div id="step"></div></section>';
    const username = document.querySelector<HTMLInputElement>("input")!;
    const step = document.querySelector<HTMLElement>("#step")!;
    makeVisible(username);
    const id = crypto.randomUUID();
    const targets = new AutofillTargets();
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, id, sendMessage, (control) => targets.capture(control, id));
    try {
      await vi.advanceTimersByTimeAsync(200);
      sendMessage.mockClear();
      const password = document.createElement("input");
      password.type = "password";
      makeVisible(password);
      const counters = startWorkCounters();
      step.append(password);
      await vi.advanceTimersByTimeAsync(150);
      expect(document.querySelectorAll).not.toHaveBeenCalled();
      expect(counters.starElements).toBeLessThanOrEqual(12);
      const ready = sendMessage.mock.calls.find(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready")?.[0] as { target: AutofillTarget };
      expect(ready).toBeDefined();
      vi.restoreAllMocks();
      expect(targets.resolve(ready.target, id)).toEqual(new Set([username, password]));
    } finally { controller.dispose(); }
  });


  it("withdraws a focused username when its associated label changes to search", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = '<form><label for="user">Username</label><input id="user" autocomplete="username"><input type="password"></form>';
    const label = document.querySelector("label")!;
    const field = document.querySelector<HTMLInputElement>("#user")!;
    document.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);
    const controller = startAutofillPage(document, crypto.randomUUID(), vi.fn(async () => ({})));
    try {
      field.focus();
      await Promise.resolve();
      expect(controller.trigger.visible).toBe(true);
      startWorkCounters();
      label.textContent = "Search";
      await vi.advanceTimersByTimeAsync(150);
      expect(controller.trigger.visible).toBe(false);
      expect(document.querySelectorAll).not.toHaveBeenCalled();
    } finally { controller.dispose(); }
  });


  it.each(["section", "div"])("resolves a hidden formless %s with controls in separate wrappers after reveal", async (tag) => {
    vi.useFakeTimers();
    const container = document.createElement(tag);
    container.hidden = true;
    container.innerHTML = '<div><input autocomplete="username"></div><div><input type="password"></div>';
    const fields = [...container.querySelectorAll<HTMLInputElement>("input")];
    fields.forEach(makeVisible);
    document.body.append(container);
    const id = crypto.randomUUID();
    const targets = new AutofillTargets();
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, id, sendMessage, (control) => targets.capture(control, id));
    try {
      expect(readyCount(sendMessage)).toBe(0);
      startWorkCounters();
      container.hidden = false;
      await vi.advanceTimersByTimeAsync(150);
      expect(document.querySelectorAll).not.toHaveBeenCalled();
      const ready = sendMessage.mock.calls.find(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready")?.[0] as { target: AutofillTarget };
      expect(ready).toBeDefined();
      vi.restoreAllMocks();
      expect(targets.resolve(ready.target, id)).toEqual(new Set(fields));
    } finally { controller.dispose(); }
  });

});
