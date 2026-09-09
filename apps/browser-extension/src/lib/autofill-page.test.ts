import { afterEach, describe, expect, it, vi } from "vitest";

import { isOtpRequestAction, startAutofillPage } from "./autofill-page";
import {
  DEFAULT_PASSWORD_GENERATOR_OPTIONS,
  DEFAULT_USERNAME_GENERATOR_OPTIONS,
  savePasswordGeneratorOptions,
  saveUsernameGeneratorOptions,
} from "./generator-preferences";

function makeVisible(element: HTMLElement) {
  Object.defineProperty(element, "getClientRects", { value: () => [{ width: 240, height: 32 }] });
  Object.defineProperty(element, "getBoundingClientRect", { value: () => ({ left: 20, right: 260, top: 20, bottom: 52, width: 240, height: 32, x: 20, y: 20, toJSON() {} }) });
}

afterEach(async () => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  await browser.storage.local.clear();
  document.body.innerHTML = "";
  for (const host of document.querySelectorAll("[data-vaultmesh-autofill]")) host.remove();
  for (const host of document.querySelectorAll("[data-vaultmesh-autofill-trigger]")) host.remove();
});

describe("startAutofillPage", () => {
  it("recognizes the pasted-form get-code action without reading field values", () => {
    document.body.innerHTML = `<form><input id="email" type="email" value="private@example.test"><button type="button">获取验证码</button><input id="verification_code" name="verification_code"></form>`;
    const button = document.querySelector<HTMLButtonElement>("button")!;
    expect(isOtpRequestAction(button)).toBe(true);
    expect(isOtpRequestAction(Object.assign(document.createElement("button"), { textContent: "注册" }))).toBe(false);
  });

  it("signals initial and dynamically inserted login forms without field values", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<input id="username" autocomplete="username" value="private-user">`;
    makeVisible(document.querySelector("input")!);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);

    await vi.advanceTimersByTimeAsync(160);
    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.autofill-page-ready", signature: expect.any(String) }));
    expect(JSON.stringify(sendMessage.mock.calls)).not.toContain("private-user");

    const password = document.createElement("input");
    password.type = "password";
    password.value = "private-password";
    makeVisible(password);
    document.body.append(password);
    await vi.advanceTimersByTimeAsync(160);
    expect(sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready")).toHaveLength(2);
    expect(JSON.stringify(sendMessage.mock.calls)).not.toContain("private-password");
    controller.dispose();
  });

  it("rescans when a dynamic login form adds ARIA semantic metadata", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<form action="/login"><input id="username" autocomplete="username"><input id="password" type="password"></form>`;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);

    await vi.advanceTimersByTimeAsync(160);
    const readyCalls = () => sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready");
    expect(readyCalls()).toHaveLength(1);

    document.querySelector("form")!.setAttribute("aria-label", "Secure login");
    document.querySelector<HTMLInputElement>("#password")!.setAttribute("aria-label", "Current password");
    await vi.advanceTimersByTimeAsync(160);

    expect(readyCalls()).toHaveLength(2);
    expect(readyCalls().every(([message]) => !("fields" in (message as object)))).toBe(true);
    controller.dispose();
  });

  it("restores value-free discovery after a back-forward cache round trip", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<form action="/login"><input autocomplete="username"><input type="password"></form>`;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, "153370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);
    const readyCalls = () => sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready");

    await vi.advanceTimersByTimeAsync(160);
    expect(readyCalls()).toHaveLength(1);

    window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true }));
    window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
    await vi.advanceTimersByTimeAsync(160);

    expect(readyCalls()).toHaveLength(2);
    expect(readyCalls().every(([message]) => !("fields" in (message as object)))).toBe(true);
    controller.dispose();
  });

  it("uses a fresh document identity after same-document navigation invalidation", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<form action="/login"><input autocomplete="username"><input type="password"></form>`;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    let documentId = crypto.randomUUID();
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, () => documentId, sendMessage);
    await vi.advanceTimersByTimeAsync(160);

    const nextDocumentId = crypto.randomUUID();
    documentId = nextDocumentId;
    controller.invalidatePageContext();
    await vi.advanceTimersByTimeAsync(160);

    const ready = sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready");
    expect(ready).toHaveLength(2);
    expect((ready[1]![0] as { documentId: string }).documentId).toBe(nextDocumentId);
    controller.dispose();
  });

  it("still disposes page-owned UI when a BFCache-restored document later navigates away", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<form action="/login"><input autocomplete="username"><input type="password"></form>`;
    const account = document.querySelector<HTMLInputElement>("input")!;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const controller = startAutofillPage(document, crypto.randomUUID(), vi.fn(async () => ({ status: "ready" })));

    account.focus();
    await Promise.resolve();
    expect(controller.trigger.visible).toBe(true);

    window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true }));
    window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
    await vi.advanceTimersByTimeAsync(160);
    window.dispatchEvent(new PageTransitionEvent("pagehide"));

    expect(document.querySelectorAll("[data-vaultmesh-autofill]")).toHaveLength(0);
    expect(document.querySelectorAll("[data-vaultmesh-autofill-trigger]")).toHaveLength(0);
  });

  it("places a bare password trigger at the trailing edge and loads candidates only after it is clicked", async () => {
    document.body.innerHTML = `<input id="password" type="password">`;
    const password = document.querySelector<HTMLInputElement>("input")!;
    makeVisible(password);
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates"
      ? { status: "ready", candidates: [{ id: "153370ec-4dc7-4c77-a6e0-f2a4f6e37f03", kind: "login", title: "Example", subtitle: "ada@example.test", autofillOnPageLoad: true, masterPasswordReprompt: false }] }
      : {});
    const controller = startAutofillPage(document, "253370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);

    password.focus();
    await Promise.resolve();
    await Promise.resolve();
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.autofill-candidates" }));
    expect(controller.trigger.visible).toBe(true);
    expect(controller.menu.visible).toBe(false);
    const triggerHost = document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!;
    expect(triggerHost.style.left).toBe("230px");
    expect(triggerHost.style.top).toBe("24px");
    expect(triggerHost.style.width).toBe("24px");

    triggerHost.click();
    await Promise.resolve();
    await Promise.resolve();
    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.autofill-candidates", fieldKind: "login", pageContext: "login" });
    expect(controller.menu.visible).toBe(true);
    expect(document.querySelectorAll("[data-vaultmesh-autofill]")).toHaveLength(1);
    const menuHost = document.querySelector<HTMLElement>("[data-vaultmesh-autofill]")!;
    expect(menuHost.style.left).toBe("20px");
    expect(menuHost.style.width).toBe("240px");

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(controller.menu.visible).toBe(false);
    window.dispatchEvent(new PageTransitionEvent("pagehide"));
    expect(document.querySelectorAll("[data-vaultmesh-autofill]")).toHaveLength(0);
    expect(document.querySelectorAll("[data-vaultmesh-autofill-trigger]")).toHaveLength(0);
  });

  it("offers existing logins instead of the signup generator on an rcvps-style login form", async () => {
    document.body.innerHTML = `
      <section>
        <form action="/login?action=email">
          <h2>邮箱登录</h2>
          <input id="email" name="email" placeholder="请输入您的邮箱或ID">
          <input type="password" name="password">
          <a href="/register">还没有账户？现在注册</a>
          <button type="submit">登录</button>
        </form>
      </section>
    `;
    const email = document.querySelector<HTMLInputElement>("#email")!;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const candidateId = crypto.randomUUID();
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates"
      ? { status: "ready", candidates: [{ id: candidateId, kind: "login", title: "chen atlan", subtitle: "chen atlan", autofillOnPageLoad: true, masterPasswordReprompt: false }] }
      : { status: "ready" });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    email.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.autofill-candidates", fieldKind: "login", pageContext: "login" });
    expect(controller.menu.visible).toBe(true);
    expect(controller.menu.generatedMode).toBe("none");
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.autofill-select",
      selectedItem: expect.objectContaining({ kind: "login", id: candidateId, title: "chen atlan" }),
    }));
    controller.dispose();
  });

  it("invalidates an open candidate menu and re-queries OTP candidates after a TOTP is saved", async () => {
    document.body.innerHTML = '<input id="otp" autocomplete="one-time-code">';
    const otp = document.querySelector<HTMLInputElement>("input")!;
    makeVisible(otp);
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates"
      ? { status: "ready", candidates: [{ id: crypto.randomUUID(), kind: "login", title: "GitHub", subtitle: "ada" }] }
      : { status: "ready" });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    otp.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();
    expect(controller.menu.visible).toBe(true);

    await controller.refreshOtpCandidates();
    expect(controller.menu.visible).toBe(false);
    expect(sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates")).toHaveLength(2);
    expect(sendMessage).toHaveBeenLastCalledWith({ kind: "vaultmesh.autofill-candidates", fieldKind: "login", pageContext: "otp" });
    controller.dispose();
  });

  it("shows global email OTP candidates on the field icon and selects by opaque ID only", async () => {
    document.body.innerHTML = '<input id="otp" autocomplete="one-time-code">';
    const otp = document.querySelector<HTMLInputElement>("input")!;
    makeVisible(otp);
    const candidate = {
      id: crypto.randomUUID(),
      code: "A12B34",
      sourceDomain: "example.test",
      receivedAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    };
    const sendMessage = vi.fn(async (message: unknown) => {
      const kind = (message as { kind?: string }).kind;
      if (kind === "vaultmesh.autofill-candidates") return { status: "ready", candidates: [], emailOtpCandidates: [candidate] };
      return { status: "ready" };
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    otp.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.autofill-candidates", fieldKind: "login", pageContext: "otp" });
    expect(controller.menu.visible).toBe(true);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.email-otp-select", candidateId: candidate.id });
    const selection = sendMessage.mock.calls.find(([message]) => (message as { kind?: string }).kind === "vaultmesh.email-otp-select")?.[0];
    expect(selection).not.toHaveProperty("code");
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.autofill-select", selectedItem: expect.objectContaining({ id: candidate.id }) }));
    controller.dispose();
  });

  it("offers OTP candidates instead of a generated credential for segmented verification codes left in a signup form", async () => {
    document.body.innerHTML = `
      <form><h1>Create account</h1>
        <input type="password" autocomplete="new-password">
        <div class="form-security-code-inputs">
          ${Array.from({ length: 6 }, (_, index) => `<input class="form-security-code-input" autocapitalize="off" autocorrect="off" spellcheck="false" autocomplete="off" aria-label="验证码数字 ${index + 1}" type="tel" value="">`).join("")}
        </div>
      </form>
    `;
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    inputs.forEach(makeVisible);
    const code = inputs[1]!;
    const codeGroup = document.querySelector<HTMLElement>(".form-security-code-inputs")!;
    Object.defineProperty(codeGroup, "getBoundingClientRect", { value: () => ({ left: 20, right: 332, top: 20, bottom: 52, width: 312, height: 32, x: 20, y: 20, toJSON() {} }) });
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates"
      ? { status: "ready", candidates: [] }
      : { status: "ready" });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    code.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.autofill-candidates", fieldKind: "login", pageContext: "otp" });
    expect(controller.menu.visible).toBe(true);
    expect(controller.menu.generatedMode).toBe("none");
    const menuHost = document.querySelector<HTMLElement>("[data-vaultmesh-autofill]")!;
    expect(menuHost.style.left).toBe("20px");
    expect(menuHost.style.width).toBe("312px");
    controller.dispose();
  });

  it("offers saved logins instead of generated credentials for an autocomplete-off Apple account field", async () => {
    document.body.innerHTML = `
      <form>
        <label id="apple_id_field_label">Apple Account</label>
        <input type="text" id="account_name_text_field" can-field="accountName" aria-labelledby="apple_id_field_label" autocorrect="off" autocapitalize="off" aria-required="true" required="required" spellcheck="false" ($focus)="appleIdFocusHandler($element)" ($blur)="appleIdBlurHandler()" class="force-ltr form-textbox-input" autocomplete="off" aria-invalid="false">
      </form>
    `;
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    inputs.forEach(makeVisible);
    const account = inputs[0]!;
    const candidate = { id: crypto.randomUUID(), kind: "login", title: "Apple", subtitle: "ada@example.test", autofillOnPageLoad: true, masterPasswordReprompt: false };
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates"
      ? { status: "ready", candidates: [candidate] }
      : { status: "ready" });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    account.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.autofill-candidates", fieldKind: "login", pageContext: "login" });
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(sendMessage).toHaveBeenCalledWith({
      kind: "vaultmesh.autofill-select",
      selectedItem: { kind: "login", id: candidate.id, title: "Apple" },
      replaceExistingAccount: true,
    });
    controller.dispose();
  });

  it("shows the SSH autofill icon on host and port controls", async () => {
    document.body.innerHTML = `<form><h1>SSH connection</h1><input id="host" name="host"><input id="port" name="port" type="number"></form>`;
    const host = document.querySelector<HTMLInputElement>("#host")!;
    const port = document.querySelector<HTMLInputElement>("#port")!;
    [host, port].forEach(makeVisible);
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates"
      ? { status: "ready", candidates: [{ id: crypto.randomUUID(), kind: "ssh", title: "Production SSH", subtitle: "deploy@server.example.test", masterPasswordReprompt: false }] }
      : { status: "ready" });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    host.focus();
    await Promise.resolve();
    expect(controller.trigger.visible).toBe(true);
    port.focus();
    await Promise.resolve();
    expect(controller.trigger.visible).toBe(true);
    const triggerHost = document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!;
    triggerHost.click();
    await Promise.resolve();
    await Promise.resolve();
    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.autofill-candidates", fieldKind: "ssh", pageContext: "ssh-console" });
    expect(controller.menu.visible).toBe(true);
    controller.dispose();
  });

  it("shows a locked icon and opens the plugin unlock popup when clicked", async () => {
    document.body.innerHTML = `<input id="password" type="password">`;
    const password = document.querySelector<HTMLInputElement>("input")!;
    makeVisible(password);
    const sendMessage = vi.fn(async (message: unknown) => {
      if ((message as { kind?: string }).kind === "vaultmesh.autofill-state") return { status: "locked" };
      if ((message as { kind?: string }).kind === "vaultmesh.open-unlock") return { status: "opened" };
      return {};
    });
    const controller = startAutofillPage(document, "a53370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);
    await Promise.resolve();
    await Promise.resolve();

    password.focus();
    await Promise.resolve();
    const triggerHost = document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!;
    expect(controller.trigger.locked).toBe(true);
    expect(triggerHost.dataset.vaultmeshLocked).toBe("true");

    triggerHost.click();
    await Promise.resolve();
    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.open-unlock" });
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.autofill-candidates" }));
    expect(controller.menu.visible).toBe(false);
    controller.dispose();
  });

  it("previews a generated password and only fills both controls after the suggestion is selected", async () => {
    vi.useFakeTimers();
    await savePasswordGeneratorOptions({
      ...DEFAULT_PASSWORD_GENERATOR_OPTIONS,
      length: 26,
      uppercase: false,
      numbers: false,
    });
    document.body.innerHTML = `
      <form>
        <label for="next">设置新密码</label><input id="next" type="password">
        <label for="confirmation">确认密码</label><input id="confirmation" type="password">
      </form>
    `;
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    inputs.forEach(makeVisible);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, "753370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);

    inputs[0]!.focus();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await vi.runAllTimersAsync();
    expect(inputs[0]!.value).toBe("");
    expect(inputs[1]!.value).toBe("");
    expect(controller.menu.visible).toBe(true);

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await vi.runAllTimersAsync();

    expect(inputs[0]!.value).toHaveLength(26);
    expect(inputs[0]!.value).toMatch(/^[a-z]+$/);
    expect(inputs[1]!.value).toBe(inputs[0]!.value);
    expect(sendMessage).not.toHaveBeenCalledWith({ kind: "vaultmesh.autofill-candidates", fieldKind: "login" });
    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.save-capture",
      pageContext: "password-reset",
      data: { login: { username: "", password: inputs[0]!.value } },
    }));
    controller.dispose();
  });

  it("does not automatically offer an existing login on signup or password-change forms", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `
      <form><h1>Create account</h1><input autocomplete="email"><input type="password" autocomplete="new-password"></form>
      <form><input type="password" autocomplete="current-password"><input type="password" autocomplete="new-password"></form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    await vi.advanceTimersByTimeAsync(200);
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.autofill-page-ready" }));
    controller.dispose();
  });

  it("shows a bounded typed failure after an explicit rcvps-style current-password selection", async () => {
    document.body.innerHTML = `
      <form id="modifyPwdForm">
        <label for="oldPwd">原密码</label><input type="password" name="old_password" id="oldPwd" placeholder="请输入原密码">
        <label for="pwd">新密码</label><input type="password" name="password" id="pwd" placeholder="请输入新密码">
        <label for="rePwd">重复新密码</label><input type="password" name="re_password" id="rePwd" placeholder="重复新密码">
      </form>
    `;
    const [oldPassword, newPassword, repeatedPassword] = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    [oldPassword, newPassword, repeatedPassword].forEach(makeVisible);
    const candidate = { id: crypto.randomUUID(), kind: "login", title: "rcvps.cn", subtitle: "ada@example.test", masterPasswordReprompt: false } as const;
    const sendMessage = vi.fn(async (message: unknown) => {
      const kind = (message as { kind?: string }).kind;
      if (kind === "vaultmesh.autofill-candidates") return { status: "ready", candidates: [candidate] };
      if (kind === "vaultmesh.autofill-select") return { status: "document-changed" };
      return { status: "ready" };
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    oldPassword!.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await Promise.resolve();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith({
      kind: "vaultmesh.autofill-select",
      selectedItem: { kind: "login", id: candidate.id, title: "rcvps.cn" },
    });
    expect(controller.menu.visible).toBe(true);
    expect(controller.menu.statusMessage).toContain("页面已经变化");
    expect(oldPassword!.value).toBe("");
    expect(newPassword!.value).toBe("");
    expect(repeatedPassword!.value).toBe("");
    controller.dispose();
  });

  it("does not show a stale selection failure after focus moves to another field", async () => {
    document.body.innerHTML = `<form><input id="account" autocomplete="username"><input id="password" type="password"></form>`;
    const account = document.querySelector<HTMLInputElement>("#account")!;
    const password = document.querySelector<HTMLInputElement>("#password")!;
    [account, password].forEach(makeVisible);
    const candidate = { id: crypto.randomUUID(), kind: "login", title: "Example", subtitle: "ada@example.test", masterPasswordReprompt: false } as const;
    let resolveSelection: ((response: unknown) => void) | undefined;
    const sendMessage = vi.fn((message: unknown) => {
      const kind = (message as { kind?: string }).kind;
      if (kind === "vaultmesh.autofill-candidates") return Promise.resolve({ status: "ready", candidates: [candidate] });
      if (kind === "vaultmesh.autofill-select") return new Promise<unknown>((resolve) => { resolveSelection = resolve; });
      return Promise.resolve({ status: "ready" });
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    account.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await Promise.resolve();
    expect(resolveSelection).toBeTypeOf("function");

    password.focus();
    resolveSelection!({ status: "document-changed" });
    await Promise.resolve();
    await Promise.resolve();

    expect(controller.menu.visible).toBe(false);
    expect(controller.trigger.visible).toBe(true);
    controller.dispose();
  });

  it("generates and fills both empty new-password fields after a successful rcvps-style Login assignment", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `
      <form id="modifyPwdForm">
        <label for="oldPwd">原密码</label><input type="password" name="old_password" id="oldPwd" placeholder="请输入原密码">
        <label for="pwd">新密码</label><input type="password" name="password" id="pwd" placeholder="请输入新密码">
        <label for="rePwd">重复新密码</label><input type="password" name="re_password" id="rePwd" placeholder="重复新密码">
      </form>
    `;
    const [oldPassword, newPassword, repeatedPassword] = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    [oldPassword, newPassword, repeatedPassword].forEach(makeVisible);
    oldPassword!.value = "stored-current-password";
    const loginId = crypto.randomUUID();
    const controller = startAutofillPage(document, crypto.randomUUID(), vi.fn(async () => ({})));
    controller.recordFilledItem({ kind: "login", id: loginId }, [oldPassword!]);

    const completion = controller.completePasswordChange({ kind: "login", id: loginId }, [oldPassword!]);
    await vi.runAllTimersAsync();

    expect(await completion).toEqual({ status: "generated" });
    expect(oldPassword!.value).toBe("stored-current-password");
    expect(newPassword!.value).not.toBe("");
    expect(repeatedPassword!.value).toBe(newPassword!.value);
    controller.dispose();
  });

  it("preserves existing new-password input instead of auto-generating over it", async () => {
    document.body.innerHTML = `
      <form id="modifyPwdForm">
        <label for="oldPwd">原密码</label><input type="password" name="old_password" id="oldPwd">
        <label for="pwd">新密码</label><input type="password" name="password" id="pwd" value="user-entered">
        <label for="rePwd">重复新密码</label><input type="password" name="re_password" id="rePwd">
      </form>
    `;
    const [oldPassword, newPassword, repeatedPassword] = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    [oldPassword, newPassword, repeatedPassword].forEach(makeVisible);
    const loginId = crypto.randomUUID();
    const controller = startAutofillPage(document, crypto.randomUUID(), vi.fn(async () => ({})));

    expect(await controller.completePasswordChange({ kind: "login", id: loginId }, [oldPassword!]))
      .toEqual({ status: "preserved-existing" });
    expect(newPassword!.value).toBe("user-entered");
    expect(repeatedPassword!.value).toBe("");
    controller.dispose();
  });

  it("passes protected Login metadata and leaves feedback to the popup confirmation", async () => {
    document.body.innerHTML = `
      <form id="modifyPwdForm">
        <input type="password" name="old_password" id="oldPwd" placeholder="请输入原密码">
        <input type="password" name="password" id="pwd" placeholder="请输入新密码">
        <input type="password" name="re_password" id="rePwd" placeholder="重复新密码">
      </form>
    `;
    const oldPassword = document.querySelector<HTMLInputElement>("#oldPwd")!;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const candidate = { id: crypto.randomUUID(), kind: "login", title: "rcvps.cn", subtitle: "ada@example.test", masterPasswordReprompt: true } as const;
    const sendMessage = vi.fn(async (message: unknown) => {
      const kind = (message as { kind?: string }).kind;
      if (kind === "vaultmesh.autofill-candidates") return { status: "ready", candidates: [candidate] };
      if (kind === "vaultmesh.autofill-select") return { status: "confirmation-required" };
      return { status: "ready" };
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    oldPassword.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await Promise.resolve();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith({
      kind: "vaultmesh.autofill-select",
      selectedItem: { kind: "login", id: candidate.id, title: "rcvps.cn", masterPasswordReprompt: true },
    });
    expect(controller.menu.visible).toBe(false);
    expect(controller.menu.statusMessage).toBeNull();
    controller.dispose();
  });

  it("offers a random account and password on signup instead of existing login candidates", async () => {
    vi.useFakeTimers();
    await savePasswordGeneratorOptions({
      ...DEFAULT_PASSWORD_GENERATOR_OPTIONS,
      length: 18,
      uppercase: false,
      numbers: false,
    });
    await saveUsernameGeneratorOptions({
      ...DEFAULT_USERNAME_GENERATOR_OPTIONS,
      length: 12,
      prefix: "acct",
      style: "random",
      includeNumber: false,
    });
    document.body.innerHTML = `
      <form id="signup"><h1>Create account / 注册</h1>
        <input id="signup-email" type="email" autocomplete="email">
        <input id="signup-password" name="password" type="password" autocomplete="off">
        <input id="signup-confirm" name="password_confirmation" aria-label="Confirm Password" type="password" autocomplete="off">
      </form>
      <form id="change"><input type="password" autocomplete="current-password"><input id="change-new" type="password" autocomplete="new-password"></form>
    `;
    const signupEmail = document.querySelector<HTMLInputElement>("#signup-email")!;
    const signupPassword = document.querySelector<HTMLInputElement>("#signup-password")!;
    const signupConfirm = document.querySelector<HTMLInputElement>("#signup-confirm")!;
    const changePassword = document.querySelector<HTMLInputElement>("#change-new")!;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates"
      ? { status: "ready", candidates: [{ id: crypto.randomUUID(), kind: "login", title: "Existing", subtitle: "existing@example.test" }] }
      : { status: "ready" });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    signupEmail.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await vi.runAllTimersAsync();
    expect(controller.menu.visible).toBe(true);
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.autofill-candidates" }));

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await vi.runAllTimersAsync();

    expect(signupEmail.value).toMatch(/^acct_[a-z2-9]{7}@vaultmesh\.invalid$/);
    expect(signupPassword.value).toHaveLength(18);
    expect(signupPassword.value).toMatch(/^[a-z]+$/);
    expect(signupConfirm.value).toBe(signupPassword.value);
    expect(changePassword.value).toBe("");
    controller.dispose();
  });

  it("does not append an email suffix for an explicit username signup field", async () => {
    vi.useFakeTimers();
    await saveUsernameGeneratorOptions({
      ...DEFAULT_USERNAME_GENERATOR_OPTIONS,
      length: 12,
      prefix: "",
      style: "random",
      includeNumber: false,
    });
    document.body.innerHTML = `
      <form><h1>Sign up</h1>
        <input id="signup-username" autocomplete="username">
        <input id="signup-password" type="password" autocomplete="new-password">
        <input id="signup-confirm" name="confirm_password" type="password">
      </form>
    `;
    const username = document.querySelector<HTMLInputElement>("#signup-username")!;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const controller = startAutofillPage(document, crypto.randomUUID(), vi.fn(async () => ({ status: "ready" })));

    username.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await vi.runAllTimersAsync();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await vi.runAllTimersAsync();

    expect(username.value).toMatch(/^[a-z2-9]{12}$/);
    expect(username.value).not.toContain("@");
    expect(document.querySelector<HTMLInputElement>("#signup-confirm")!.value)
      .toBe(document.querySelector<HTMLInputElement>("#signup-password")!.value);
    controller.dispose();
  });

  it("places the trigger before an existing input suffix control", async () => {
    document.body.innerHTML = `<div><input id="password" type="password"><button id="reveal" type="button" aria-label="显示密码">显示</button></div>`;
    const password = document.querySelector<HTMLInputElement>("input")!;
    const reveal = document.querySelector<HTMLButtonElement>("button")!;
    makeVisible(password);
    Object.defineProperty(reveal, "getBoundingClientRect", {
      value: () => ({ left: 228, right: 256, top: 22, bottom: 50, width: 28, height: 28, x: 228, y: 22, toJSON() {} }),
    });
    const controller = startAutofillPage(document, "653370ec-4dc7-4c77-a6e0-f2a4f6e37f03", vi.fn(async () => ({})));

    password.focus();
    await Promise.resolve();
    const triggerHost = document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!;
    const triggerRight = Number.parseFloat(triggerHost.style.left) + Number.parseFloat(triggerHost.style.width);
    expect(triggerRight).toBeLessThanOrEqual(220);
    expect(triggerRight).toBeLessThan(Number.parseFloat(reveal.getBoundingClientRect().left.toString()));
    controller.dispose();
  });

  it("places the trigger before a custom account-field status element", async () => {
    document.body.innerHTML = `<div class="field"><input id="account" autocomplete="username"><i class="field-state" aria-hidden="true">·</i></div>`;
    const account = document.querySelector<HTMLInputElement>("input")!;
    const status = document.querySelector<HTMLElement>("i")!;
    makeVisible(account);
    Object.defineProperty(status, "getBoundingClientRect", {
      value: () => ({ left: 228, right: 250, top: 25, bottom: 47, width: 22, height: 22, x: 228, y: 25, toJSON() {} }),
    });
    const controller = startAutofillPage(document, "853370ec-4dc7-4c77-a6e0-f2a4f6e37f03", vi.fn(async () => ({})));

    account.focus();
    await Promise.resolve();
    const triggerHost = document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!;
    const triggerRight = Number.parseFloat(triggerHost.style.left) + Number.parseFloat(triggerHost.style.width);
    expect(triggerRight).toBeLessThanOrEqual(220);
    expect(triggerRight).toBeLessThan(status.getBoundingClientRect().left);
    controller.dispose();
  });

  it("preserves the submitted account when selecting a login on a multi-step password page", async () => {
    document.body.innerHTML = `
      <form>
        <input id="account" autocomplete="username webauthn" value="displayed-account@example.test">
        <input id="password" type="password" autocomplete="current-password">
      </form>
    `;
    const account = document.querySelector<HTMLInputElement>("#account")!;
    const password = document.querySelector<HTMLInputElement>("#password")!;
    makeVisible(account);
    makeVisible(password);
    const candidate = { id: "453370ec-4dc7-4c77-a6e0-f2a4f6e37f03", kind: "login", title: "Bilibili", subtitle: "19983812600", autofillOnPageLoad: true, masterPasswordReprompt: false };
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates"
      ? { status: "ready", candidates: [candidate] }
      : {});
    const controller = startAutofillPage(document, "553370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);

    password.focus();
    await Promise.resolve();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));

    expect(sendMessage).toHaveBeenCalledWith({
      kind: "vaultmesh.autofill-select",
      selectedItem: { kind: "login", id: candidate.id, title: "Bilibili" },
    });
    expect(controller.menu.visible).toBe(false);
    controller.dispose();
  });

  it("allows account replacement only when the login is selected from the account control", async () => {
    document.body.innerHTML = `
      <form>
        <input id="account" autocomplete="username webauthn" value="old-account@example.test">
        <input id="password" type="password" autocomplete="current-password">
      </form>
    `;
    const account = document.querySelector<HTMLInputElement>("#account")!;
    const password = document.querySelector<HTMLInputElement>("#password")!;
    makeVisible(account);
    makeVisible(password);
    const candidate = { id: "453370ec-4dc7-4c77-a6e0-f2a4f6e37f03", kind: "login", title: "Other account", subtitle: "new-account@example.test", autofillOnPageLoad: true, masterPasswordReprompt: false };
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.autofill-candidates"
      ? { status: "ready", candidates: [candidate] }
      : {});
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    account.focus();
    await Promise.resolve();
    document.querySelector<HTMLElement>("[data-vaultmesh-autofill-trigger]")!.click();
    await Promise.resolve();
    await Promise.resolve();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));

    expect(sendMessage).toHaveBeenCalledWith({
      kind: "vaultmesh.autofill-select",
      selectedItem: { kind: "login", id: candidate.id, title: "Other account" },
      replaceExistingAccount: true,
    });
    controller.dispose();
  });

  it("observes login controls added inside an open shadow root", async () => {
    vi.useFakeTimers();
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, "353370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);
    await vi.advanceTimersByTimeAsync(160);

    const host = document.createElement("div");
    const shadow = host.attachShadow({ mode: "open" });
    const password = document.createElement("input");
    password.type = "password";
    makeVisible(password);
    shadow.append(password);
    document.body.append(host);
    await vi.advanceTimersByTimeAsync(160);

    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.autofill-page-ready" }));
    controller.dispose();
  });

  it("discovers a shadow root attached after its custom-element host without another DOM mutation", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<vaultmesh-login></vaultmesh-login>`;
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, "353370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);
    await vi.advanceTimersByTimeAsync(160);

    const host = document.querySelector<HTMLElement>("vaultmesh-login")!;
    const shadow = host.attachShadow({ mode: "open" });
    const password = document.createElement("input");
    password.type = "password";
    makeVisible(password);
    shadow.append(password);
    await vi.advanceTimersByTimeAsync(410);

    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.autofill-page-ready",
      documentId: "353370ec-4dc7-4c77-a6e0-f2a4f6e37f03",
    }));
    controller.dispose();
  });

  it("stages the username for a multi-step login before the password page", async () => {
    document.body.innerHTML = `<form><input autocomplete="username" value="ada@example.test"></form>`;
    const sendMessage = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    expect(sendMessage).toHaveBeenCalledWith({
      kind: "vaultmesh.account-stage",
      pageUrl: "http://localhost:3000/",
      username: "ada@example.test",
    });
    controller.dispose();
  });

  it("shows the login trigger for username webauthn and rescans when the hidden password step expands", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `
      <form>
        <input id="account" autocomplete="username webauthn">
        <div id="password-step" aria-hidden="true" style="height:0;overflow:hidden">
          <input id="password" type="password" autocomplete="off">
        </div>
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    await vi.advanceTimersByTimeAsync(160);
    document.querySelector<HTMLInputElement>("#account")!.focus();
    await Promise.resolve();

    expect(controller.trigger.visible).toBe(true);
    const firstReady = sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready");
    expect(firstReady).toHaveLength(1);
    expect((firstReady[0]![0] as { signature: string }).signature).toContain("account");
    expect((firstReady[0]![0] as { signature: string }).signature).not.toContain("password");

    const passwordStep = document.querySelector<HTMLElement>("#password-step")!;
    passwordStep.setAttribute("aria-hidden", "false");
    passwordStep.style.height = "40px";
    await vi.advanceTimersByTimeAsync(160);

    const readyAfterExpansion = sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.autofill-page-ready");
    expect(readyAfterExpansion).toHaveLength(2);
    expect((readyAfterExpansion[1]![0] as { signature: string }).signature).toContain("password");
    controller.dispose();
  });
});
