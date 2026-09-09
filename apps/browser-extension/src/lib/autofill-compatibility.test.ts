import { afterEach, describe, expect, it, vi } from "vitest";
import { classifyControl, discoverFields } from "./form-discovery";
import { startAutofillPage } from "./autofill-page";
import { fillGeneratedLogin } from "./generated-login-fill";

function visible(root: ParentNode) {
  for (const field of root.querySelectorAll<HTMLElement>("input,textarea,select,[contenteditable]")) {
    Object.defineProperty(field, "getClientRects", { value: () => [{ width: 240, height: 32 }] });
    Object.defineProperty(field, "getBoundingClientRect", { value: () => ({ left: 20, right: 260, top: 20, bottom: 52, width: 240, height: 32 }) });
  }
}

afterEach(() => {
  vi.useRealTimers();
  document.body.innerHTML = "";
  document.querySelectorAll("[data-vaultmesh-autofill],[data-vaultmesh-autofill-trigger]").forEach((element) => element.remove());
});

describe("CT-AUTOFILL-001 field qualification compatibility", () => {
  it.each([
    ['<input type="search" name="username">', "search on a login page"],
    ['<input name="fileName">', "file name"],
    ['<input name="serviceName">', "service name"],
    ['<input name="statement">', "statement"],
    ['<input name="accountFilter">', "account filter"],
    ['<input placeholder="图形验证码">', "captcha"],
    ['<input name="coupon">', "coupon"],
    ['<textarea name="message"></textarea>', "message"],
    ['<div contenteditable="plaintext-only" role="textbox" aria-label="Comment"></div>', "editor"],
    ['<input autocomplete="username" aria-readonly="true">', "ARIA readonly"],
    ['<fieldset disabled><input autocomplete="username"></fieldset>', "disabled fieldset"],
  ])("does not show an icon for %s (%s)", (markup) => {
    document.body.innerHTML = `<form><h1>Payment SSH API key settings</h1>${markup}</form>`;
    visible(document);
    const target = document.querySelector<HTMLElement>("input,textarea,[contenteditable]")!;
    const controller = startAutofillPage(document, crypto.randomUUID(), vi.fn(async () => ({})));
    target.dispatchEvent(new FocusEvent("focusin", { bubbles: true, composed: true }));
    expect(classifyControl(target)).toBeNull();
    expect(controller.trigger.visible).toBe(false);
    controller.dispose();
  });

  it("qualifies individual payment, identity and unsupported fields on the same checkout form", () => {
    document.body.innerHTML = `<form><h1>Checkout</h1><input id="card" autocomplete="cc-number"><input id="first" autocomplete="given-name"><input id="city" autocomplete="address-level2"><input id="coupon"><input id="quantity" type="number"></form>`;
    visible(document);
    expect([...document.querySelectorAll("input")].map(classifyControl)).toEqual(["card", "identity", "identity", null, null]);
  });

  it("does not classify an unrelated input beside segmented OTP digits as an OTP", () => {
    document.body.innerHTML = `<form><h1>Verification code</h1>${'<input maxlength="1" inputmode="numeric">'.repeat(6)}<input id="order-reference"></form>`;
    visible(document);
    expect(classifyControl(document.querySelector("#order-reference")!)).toBeNull();
    expect([...document.querySelectorAll('[maxlength="1"]')].map(classifyControl)).toEqual(Array(6).fill("login"));
    expect(discoverFields(document).descriptors.find((field) => field.id === "order-reference")?.context).not.toBe("otp");
  });

  it("retires an existing icon when its focused field becomes disabled without another focus event", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = '<input autocomplete="username">';
    visible(document);
    const controller = startAutofillPage(document, crypto.randomUUID(), vi.fn(async () => ({})));
    const input = document.querySelector("input")!;
    input.focus();
    expect(controller.trigger.visible).toBe(true);
    input.setAttribute("aria-readonly", "true");
    await vi.advanceTimersByTimeAsync(160);
    expect(controller.trigger.visible).toBe(false);
    controller.dispose();
  });

  it("does not open a delayed candidate response after the field loses qualification", async () => {
    document.body.innerHTML = '<input autocomplete="username">';
    visible(document);
    let resolve!: (response: unknown) => void;
    const controller = startAutofillPage(document, crypto.randomUUID(), (message) =>
      (message as { kind: string }).kind === "vaultmesh.autofill-candidates" ? new Promise((done) => { resolve = done; }) : Promise.resolve({}));
    document.querySelector("input")!.focus();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    document.querySelector("input")!.disabled = true;
    resolve({ status: "ready", candidates: [] });
    await Promise.resolve();
    await Promise.resolve();
    expect(controller.menu.visible).toBe(false);
    controller.dispose();
  });
});

describe("CT-AUTOFILL-002 scoped submission compatibility", () => {
  it("captures a formless SPA login before its click handler removes the fields", () => {
    document.body.innerHTML = '<section><input autocomplete="username" value="test-user"><input type="password" value="test-password"><button type="button">Sign in</button></section>';
    visible(document);
    const send = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), send);
    const button = document.querySelector("button")!;
    button.addEventListener("click", () => document.querySelector("section")!.remove());
    button.click();
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture", data: { login: { username: "test-user", password: "test-password" } } }));
    controller.dispose();
  });

  it("observes a native non-composed submit inside Shadow DOM", () => {
    const host = document.createElement("test-login");
    document.body.append(host);
    const shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML = '<form><input autocomplete="username" value="shadow-user"><input type="password" value="shadow-password"></form>';
    visible(shadow);
    const send = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), send);
    shadow.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true }));
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture", data: { login: { username: "shadow-user", password: "shadow-password" } } }));
    controller.dispose();
  });

  it("includes controls and submit buttons connected by form=", () => {
    document.body.innerHTML = '<form id="login"></form><input form="login" autocomplete="username" value="external-user"><input form="login" type="password" value="external-password"><button type="submit" form="login">Login</button>';
    visible(document);
    const send = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), send);
    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true }));
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture", data: { login: { username: "external-user", password: "external-password" } } }));
    controller.dispose();
  });

  it("does not capture another login when an unrelated formless save button is clicked", () => {
    document.body.innerHTML = '<section><input autocomplete="username" value="unrelated-user"><input type="password" value="unrelated-password"></section><section><input name="projectName" value="test-project"><button type="button">Save</button></section>';
    visible(document);
    const send = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), send);
    document.querySelector("button")!.click();
    expect(send.mock.calls.some(([message]: unknown[]) => (message as { kind?: string }).kind === "vaultmesh.save-capture")).toBe(false);
    controller.dispose();
  });

  it("fills a generated login only in its originating formless component", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = ['a', 'b'].map((id) => `<section id="${id}"><input autocomplete="username"><input autocomplete="new-password" type="password"></section>`).join("");
    visible(document);
    const fill = fillGeneratedLogin(document, crypto.randomUUID(), { username: "test-user", password: "test-password" }, document.querySelector<HTMLElement>('#b input')!);
    await vi.runAllTimersAsync();
    expect((await fill).results.map((result) => result.status)).toEqual(["filled", "filled"]);
    expect([...document.querySelectorAll<HTMLInputElement>('#a input')].map((input) => input.value)).toEqual(["", ""]);
    expect([...document.querySelectorAll<HTMLInputElement>('#b input')].map((input) => input.value)).toEqual(["test-user", "test-password"]);
  });

  it("keeps a generated password with its form and captures the user's later edit", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = '<form id="change"><input type="password" autocomplete="current-password" value="old-test-password"><input type="password" autocomplete="new-password"><input type="password" autocomplete="new-password"></form><form id="other"><input autocomplete="username" value="other-user"><input type="password" value="other-test-password"></form>';
    visible(document);
    const send = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), send);
    const loginId = crypto.randomUUID();
    const current = document.querySelector<HTMLInputElement>('[autocomplete="current-password"]')!;
    controller.recordFilledItem({ kind: "login", id: loginId }, [current]);
    const generation = controller.completePasswordChange({ kind: "login", id: loginId }, [current]);
    await vi.runAllTimersAsync();
    expect(await generation).toEqual({ status: "generated" });
    document.querySelectorAll<HTMLInputElement>('[autocomplete="new-password"]').forEach((input) => { input.value = "edited-test-password"; });
    document.querySelector("#other")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true }));
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture", data: { login: { username: "other-user", password: "other-test-password" } } }));
    document.querySelector("#change")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true }));
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture", data: { login: { username: "", password: "edited-test-password", loginId } } }));
    send.mockClear();
    document.querySelectorAll<HTMLInputElement>('[autocomplete="new-password"]').forEach((input) => { input.value = ""; });
    document.querySelector("#change")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true }));
    expect(send.mock.calls.some(([message]) => (message as { kind: string }).kind === "vaultmesh.save-capture")).toBe(false);
    controller.dispose();
  });
});
