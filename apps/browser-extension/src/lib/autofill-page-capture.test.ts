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

describe("startAutofillPage save capture", () => {
  it("captures keyboard SPA submission before the target handler unmounts its form", async () => {
    document.body.innerHTML = '<form><input autocomplete="username" value="ada"><input type="password" value="test-password"></form>';
    document.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    const password = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    password.addEventListener("keydown", () => document.querySelector("form")!.remove());
    password.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture", data: { login: { username: "ada", password: "test-password" } } }));
    controller.dispose();
  });

  it("ignores composition Enter and observes formdata without reading arbitrary entries", () => {
    document.body.innerHTML = '<form><input autocomplete="username" value="ada"><input type="password" value="test-password"><input name="unrelated" value="never-capture"></form>';
    document.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    document.querySelector("input")!.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", isComposing: true, bubbles: true }));
    expect(sendMessage.mock.calls.some(([message]: unknown[]) => (message as {kind?:string}).kind === "vaultmesh.save-capture")).toBe(false);
    // jsdom does not implement native form.submit(); exercise its formdata event boundary.
    document.querySelector("form")!.dispatchEvent(new Event("formdata", { bubbles: true }));
    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture", data: { login: { username: "ada", password: "test-password" } } }));
    expect(JSON.stringify(sendMessage.mock.calls)).not.toContain("never-capture");
    controller.dispose();
  });

  it("recognizes input type=button save actions", () => {
    document.body.innerHTML = '<div role="form"><input autocomplete="given-name" value="Ada"><input type="button" value="保存"></div>';
    const sendMessage = vi.fn(async () => ({})); const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    document.querySelector<HTMLInputElement>('input[type="button"]')!.click();
    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture", data: { identity: expect.objectContaining({ firstName: "Ada" }) } }));
    controller.dispose();
  });
  it("captures profile data from SPA save buttons that do not submit a native form", async () => {
    document.body.innerHTML = `<div role="form"><input autocomplete="given-name" value="Ada"><button type="button">保存</button></div>`;
    const sendMessage = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    document.querySelector("button")!.click();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.save-capture",
      data: { identity: expect.objectContaining({ firstName: "Ada" }) },
    }));
    controller.dispose();
  });

  it("captures a password change from an SPA update button that does not submit a native form", async () => {
    document.body.innerHTML = `
      <div role="form">
        <input type="password" autocomplete="current-password" value="old password">
        <input type="password" autocomplete="new-password" value="new password">
        <input type="password" autocomplete="new-password" value="new password">
        <button type="button">更新密码</button>
      </div>
    `;
    const sendMessage = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    document.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);

    document.querySelector("button")!.click();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.save-capture",
      pageContext: "password-change",
      data: { login: { username: "", password: "new password" } },
    }));
    controller.dispose();
  });

  it("captures an automatically generated password change against the filled Login id", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `
      <form id="modifyPwdForm">
        <label for="oldPwd">原密码</label><input type="password" name="old_password" id="oldPwd" value="stored password">
        <label for="pwd">新密码</label><input type="password" name="password" id="pwd">
        <label for="rePwd">重复新密码</label><input type="password" name="re_password" id="rePwd">
      </form>
    `;
    document.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    const oldPassword = document.querySelector<HTMLInputElement>("#oldPwd")!;
    const loginId = crypto.randomUUID();
    controller.recordFilledItem({ kind: "login", id: loginId }, [oldPassword]);

    const completion = controller.completePasswordChange({ kind: "login", id: loginId }, [oldPassword]);
    await vi.runAllTimersAsync();
    expect(await completion).toEqual({ status: "generated" });
    const generatedPassword = document.querySelector<HTMLInputElement>("#pwd")!.value;

    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.save-capture",
      pageContext: "password-change",
      data: { login: { username: "", password: generatedPassword, loginId } },
    }));
    controller.dispose();
  });

  it("does not carry a generated password capture across same-document navigation", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `
      <form id="change"><input id="old" type="password" name="old_password" value="stored-password"><input id="new" type="password" name="password"><input id="confirm" type="password" name="re_password"></form>
    `;
    document.querySelectorAll<HTMLInputElement>("input").forEach(makeVisible);
    const sendMessage = vi.fn(async (message: unknown) => {
      const value = message as { kind?: string; captureId?: string };
      return value.kind === "vaultmesh.save-capture"
        ? { status: "queued", captureId: value.captureId, hostname: "example.test", labels: ["登录信息"], update: false, expiresAt: Date.now() + 10_000 }
        : {};
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    const oldPassword = document.querySelector<HTMLInputElement>("#old")!;
    const loginId = crypto.randomUUID();
    controller.recordFilledItem({ kind: "login", id: loginId }, [oldPassword]);
    const completion = controller.completePasswordChange({ kind: "login", id: loginId }, [oldPassword]);
    await vi.runAllTimersAsync();
    expect(await completion).toEqual({ status: "generated" });

    document.body.innerHTML = `<form id="login" action="/login"><input autocomplete="username" value="next@example.test"><input type="password" autocomplete="current-password" value="next-password"></form>`;
    controller.invalidatePageContext();
    sendMessage.mockClear();
    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.save-capture",
      pageContext: "login",
      data: { login: { username: "next@example.test", password: "next-password" } },
    }));
    controller.dispose();
  });

  it("dispatches the full capture without showing a second page confirmation", async () => {
    document.body.innerHTML = `<form><h1>Sign in</h1><input autocomplete="username" value="ada@example.test"><input type="password" autocomplete="current-password" value="saved password"></form>`;
    let promptVisibleWhenCaptureStarted: boolean | null = null;
    const sendMessage = vi.fn(async (message: unknown) => {
      const value = message as { kind?: string; captureId?: string };
      if (value.kind === "vaultmesh.save-capture") {
        promptVisibleWhenCaptureStarted = document.querySelector<HTMLElement>("[data-vaultmesh-save-prompt]")?.style.display !== "none";
        return { status: "queued", captureId: value.captureId, hostname: "localhost", labels: ["登录信息"], update: false, expiresAt: Date.now() + 10_000 };
      }
      if (value.kind === "vaultmesh.save-capture-decision") return { status: "saved" };
      return {};
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    sendMessage.mockClear();

    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await Promise.resolve();

    expect((sendMessage.mock.calls[0]?.[0] as { kind?: string }).kind).toBe("vaultmesh.save-capture");
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.account-stage" }));
    expect(promptVisibleWhenCaptureStarted).toBe(false);
    await Promise.resolve();

    expect(controller.savePrompt.visible).toBe(false);
    controller.savePrompt.show({ captureId: crypto.randomUUID(), hostname: "localhost", labels: ["登录信息"], update: true });
    expect(controller.savePrompt.title).toBe("更新密码？");
    controller.savePrompt.show({
      captureId: crypto.randomUUID(), hostname: "localhost", labels: ["登录信息", "支付卡"], update: true,
      actions: { login: "new", card: "update" },
    });
    expect(controller.savePrompt.title).toBe("保存并更新这些信息？");
    expect(document.querySelector("[data-vaultmesh-save-prompt]")).not.toBeNull();
    await controller.savePrompt.choose("save");
    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.save-capture-decision",
      decision: "save",
    }));
    controller.dispose();
  });

  it("keeps the page prompt hidden when an independent confirmation is pending after navigation", async () => {
    document.body.innerHTML = `<main><h1>Dashboard</h1></main>`;
    const captureId = crypto.randomUUID();
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.save-capture-pending"
      ? { status: "queued", captureId, hostname: "localhost", labels: ["登录信息"], update: false, expiresAt: Date.now() + 10_000, actions: { login: "new" } }
      : {});

    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    await Promise.resolve();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.save-capture-pending" });
    expect(controller.savePrompt.visible).toBe(false);
    expect(controller.savePrompt.captureId).toBeNull();
    controller.dispose();
  });

  it("does not show a page prompt when the background reports an independent confirmation", async () => {
    document.body.innerHTML = `<main><h1>Dashboard</h1></main>`;
    const captureId = crypto.randomUUID();
    const sendMessage = vi.fn(async () => ({ status: "none" }));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    expect(controller.showPendingCapture({
      status: "queued",
      captureId,
      hostname: "localhost",
      labels: ["登录信息"],
      update: false,
      expiresAt: Date.now() + 10_000,
      actions: { login: "new" },
    })).toBe(true);
    expect(controller.savePrompt.visible).toBe(false);
    expect(controller.savePrompt.captureId).toBeNull();
    controller.dispose();
  });

  it("retries pending prompt recovery when navigation wins the background queue race", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<main><h1>Dashboard</h1></main>`;
    const captureId = crypto.randomUUID();
    let pendingLookups = 0;
    const sendMessage = vi.fn(async (message: unknown) => {
      if ((message as { kind?: string }).kind !== "vaultmesh.save-capture-pending") return {};
      pendingLookups += 1;
      return pendingLookups === 1
        ? { status: "none" }
        : { status: "queued", captureId, hostname: "localhost", labels: ["登录信息"], update: false, expiresAt: Date.now() + 10_000, actions: { login: "new" } };
    });

    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    await vi.advanceTimersByTimeAsync(251);

    expect(pendingLookups).toBe(2);
    expect(controller.savePrompt.visible).toBe(false);
    expect(controller.savePrompt.captureId).toBeNull();
    controller.dispose();
  });

  it("keeps waiting when the background is still preparing a capture after the old retry window", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<main><h1>Dashboard</h1></main>`;
    const captureId = crypto.randomUUID();
    let pendingLookups = 0;
    const sendMessage = vi.fn(async (message: unknown) => {
      if ((message as { kind?: string }).kind !== "vaultmesh.save-capture-pending") return {};
      pendingLookups += 1;
      return pendingLookups < 5
        ? { status: "preparing", captureId }
        : { status: "queued", captureId, hostname: "localhost", labels: ["登录信息"], update: false, expiresAt: Date.now() + 10_000, actions: { login: "new" } };
    });

    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    await vi.advanceTimersByTimeAsync(2_100);

    expect(pendingLookups).toBe(5);
    expect(controller.savePrompt.visible).toBe(false);
    expect(controller.savePrompt.captureId).toBeNull();
    controller.dispose();
  });

  it("cancels pending prompt recovery retries when the document is disposed", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<main><h1>Dashboard</h1></main>`;
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.save-capture-pending"
      ? { status: "none" }
      : {});

    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    await Promise.resolve();
    await Promise.resolve();
    controller.dispose();
    await vi.advanceTimersByTimeAsync(1_000);

    expect(sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.save-capture-pending")).toHaveLength(1);
  });

  it("leaves the ten-second expiry to the background without creating a page prompt", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<form><h1>Sign in</h1><input autocomplete="username" value="ada@example.test"><input type="password" autocomplete="current-password" value="saved password"></form>`;
    const sendMessage = vi.fn(async (message: unknown) => {
      const value = message as { kind?: string; captureId?: string };
      if (value.kind === "vaultmesh.save-capture") {
        return { status: "queued", captureId: value.captureId, hostname: "localhost", labels: ["登录信息"], update: false, expiresAt: Date.now() + 10_000 };
      }
      if (value.kind === "vaultmesh.save-capture-decision") return { status: "discarded" };
      return {};
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await vi.advanceTimersByTimeAsync(1);
    expect(controller.savePrompt.visible).toBe(false);

    await vi.advanceTimersByTimeAsync(9_998);
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture-decision" }));
    expect(controller.savePrompt.visible).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture-decision" }));
    expect(controller.savePrompt.visible).toBe(false);
    controller.dispose();
  });

  it("keeps the save prompt hidden while the background is still preparing the capture", () => {
    document.body.innerHTML = `<form><h1>Sign in</h1><input autocomplete="username" value="ada@example.test"><input type="password" autocomplete="current-password" value="saved password"></form>`;
    const sendMessage = vi.fn((message: unknown) => (message as { kind?: string }).kind === "vaultmesh.save-capture"
      ? new Promise<unknown>(() => undefined)
      : Promise.resolve({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    expect(controller.savePrompt.visible).toBe(false);
    expect(controller.savePrompt.captureId).not.toBeNull();
    controller.dispose();
  });

  it("captures a submitted login when an HTTP content context has no crypto.randomUUID", async () => {
    vi.stubGlobal("crypto", {
      getRandomValues(array: Uint8Array) {
        array.set(Array.from({ length: 16 }, (_, index) => index));
        return array;
      },
    });
    document.body.innerHTML = `<form><input autocomplete="username" value="ada@example.test"><input type="password" autocomplete="current-password" value="saved password"></form>`;
    const sendMessage = vi.fn(async (message: unknown) => {
      const value = message as { kind?: string; captureId?: string };
      return value.kind === "vaultmesh.save-capture"
        ? { status: "account-check-failed", captureId: value.captureId }
        : {};
    });
    const controller = startAutofillPage(document, "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", sendMessage);

    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await Promise.resolve();
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.save-capture",
      captureId: "00010203-0405-4607-8809-0a0b0c0d0e0f",
    }));
    controller.dispose();
  });

  it("identifies an old background response instead of reporting that the extension is missing", async () => {
    document.body.innerHTML = `<form><h1>Sign in</h1><input autocomplete="username" value="ada@example.test"><input type="password" autocomplete="current-password" value="saved password"></form>`;
    const sendMessage = vi.fn(async (message: unknown) => (message as { kind?: string }).kind === "vaultmesh.save-capture"
      ? { status: "queued" }
      : {});
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await Promise.resolve();
    await Promise.resolve();

    expect(document.querySelector<HTMLElement>("[data-vaultmesh-save-prompt]")?.dataset.vaultmeshQueueFailure).toBe("background-outdated");
    controller.dispose();
  });

  it("reports account verification failure instead of showing a new-account prompt", async () => {
    document.body.innerHTML = `<form><input autocomplete="username" value="ada@example.test"><input type="password" autocomplete="current-password" value="changed password"></form>`;
    const sendMessage = vi.fn(async (message: unknown) => {
      const value = message as { kind?: string; captureId?: string };
      return value.kind === "vaultmesh.save-capture"
        ? { status: "account-check-failed", captureId: value.captureId }
        : {};
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await Promise.resolve();
    await Promise.resolve();

    const prompt = document.querySelector<HTMLElement>("[data-vaultmesh-save-prompt]");
    expect(prompt?.dataset.vaultmeshQueueFailure).toBe("account-check-failed");
    expect(prompt?.dataset.vaultmeshPromptTitle).toBe("正在检查账号…");
    expect(controller.savePrompt.visible).toBe(true);
    controller.dispose();
  });

  it("closes the preparing prompt when the existing account password is unchanged", async () => {
    document.body.innerHTML = `<form><input autocomplete="username" value="ada@example.test"><input id="password" type="password" autocomplete="current-password" value="same password"></form>`;
    const sendMessage = vi.fn(async (message: unknown) => {
      const value = message as { kind?: string; captureId?: string };
      return value.kind === "vaultmesh.save-capture"
        ? { status: "unchanged", captureId: value.captureId }
        : {};
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    controller.recordFilledItem({ kind: "login", id: crypto.randomUUID() }, [document.querySelector("#password")!]);
    controller.recordEditedItem("login", document.querySelector("#password")!);

    const form = document.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    expect(controller.savePrompt.visible).toBe(false);
    await Promise.resolve();
    await Promise.resolve();

    expect(controller.savePrompt.visible).toBe(false);
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    expect(sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.save-capture")).toHaveLength(1);
    controller.dispose();
  });

  it("offers every supported kind of manually entered data for saving after use", () => {
    const expirationYear = new Date().getFullYear() + 1;
    document.body.innerHTML = `
    <form id="login-save">
      <h1>Sign in</h1>
      <input autocomplete="username" value="ada@example.test">
      <input type="password" autocomplete="current-password" value="saved password">
      <button type="submit">Sign in</button>
    </form>
    <form id="identity-save">
      <h1>Shipping address</h1>
      <input autocomplete="given-name" value="Ada">
      <input autocomplete="family-name" value="Lovelace">
      <input autocomplete="email" value="ada@example.test">
      <input autocomplete="shipping address-line1" value="文一西路 969 号">
      <button type="submit">Save address</button>
    </form>
    <form id="card-save">
      <h1>Payment</h1>
      <input autocomplete="cc-name" value="Ada Lovelace">
      <input autocomplete="cc-number" value="4242 4242 4242 4242">
      <input autocomplete="cc-exp-month" value="12">
      <input autocomplete="cc-exp-year" value="${expirationYear}">
      <button type="submit">Pay</button>
    </form>`;
    const sendMessage = vi.fn(async (_message: unknown) => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);

    for (const form of document.querySelectorAll("form")) {
      form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    }

    const saveMessages = sendMessage.mock.calls
      .map(([message]) => message as { kind?: string; data?: Record<string, unknown> })
      .filter((message) => message.kind === "vaultmesh.save-capture");
    expect(saveMessages).toHaveLength(3);
    expect(saveMessages[0]?.data).toEqual({
      login: { username: "ada@example.test", password: "saved password" },
    });
    expect(saveMessages[1]?.data).toEqual({
      identity: expect.objectContaining({
        firstName: "Ada",
        lastName: "Lovelace",
        emails: [{ label: "主要", value: "ada@example.test", preferred: true }],
        addresses: [expect.objectContaining({ label: "收货", addressLine1: "文一西路 969 号" })],
      }),
    });
    expect(saveMessages[2]?.data).toEqual({
      card: expect.objectContaining({
        cardholderName: "Ada Lovelace",
        cardNumber: "4242424242424242",
        expirationMonth: 12,
        expirationYear,
      }),
    });
    controller.dispose();
  });

  it("does not offer to re-save an unchanged login that VaultMesh just filled", () => {
    document.body.innerHTML = `<form><input autocomplete="username" value="ada"><input type="password" autocomplete="current-password" value="saved password"></form>`;
    const sendMessage = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    controller.recordFilledItem({ kind: "login", id: crypto.randomUUID() }, [document.querySelector("input")!]);

    document.querySelector("form")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.save-capture" }));
    controller.dispose();
  });

  it("offers an edited autofilled password again when the first save prompt was ignored", async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `<form><input autocomplete="username" value="ada"><input id="password" type="password" autocomplete="current-password" value="new password"></form>`;
    const sendMessage = vi.fn(async (message: unknown) => {
      const value = message as { kind?: string; captureId?: string };
      if (value.kind === "vaultmesh.save-capture") {
        return { status: "queued", captureId: value.captureId, hostname: "localhost", labels: ["登录信息"], update: true, expiresAt: Date.now() + 10_000 };
      }
      if (value.kind === "vaultmesh.save-capture-decision") return { status: "discarded" };
      return {};
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    controller.recordFilledItem({ kind: "login", id: crypto.randomUUID() }, [document.querySelector("#password")!]);
    controller.recordEditedItem("login", document.querySelector("#password")!);

    const form = document.querySelector("form")!;
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await Promise.resolve();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(10_001);
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    await Promise.resolve();

    expect(sendMessage.mock.calls.filter(([message]) => (message as { kind?: string }).kind === "vaultmesh.save-capture")).toHaveLength(2);
    controller.dispose();
  });

  it("does not carry a filled login id into a different form", () => {
    document.body.innerHTML = `
      <form id="old"><input autocomplete="username" value="old@example.test"><input id="old-password" type="password" autocomplete="current-password" value="changed"></form>
      <form id="new"><input autocomplete="username" value="new@example.test"><input type="password" autocomplete="current-password" value="new password"></form>
    `;
    const sendMessage = vi.fn(async () => ({}));
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    controller.recordFilledItem({ kind: "login", id: crypto.randomUUID() }, [document.querySelector("#old-password")!]);
    controller.recordEditedItem("login", document.querySelector("#old-password")!);

    document.querySelector<HTMLFormElement>("#new")!.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.save-capture",
      data: { login: { username: "new@example.test", password: "new password" } },
    }));
    controller.dispose();
  });

  it("does not let an older capture response overwrite the latest account action", async () => {
    document.body.innerHTML = `<form><input id="username" autocomplete="username" value="old@example.test"><input id="password" type="password" autocomplete="current-password" value="first password"></form>`;
    const captureResolvers: Array<(value: unknown) => void> = [];
    const captureIds: string[] = [];
    const sendMessage = vi.fn((message: unknown) => {
      const value = message as { kind?: string; captureId?: string };
      if (value.kind === "vaultmesh.save-capture") {
        captureIds.push(value.captureId!);
        return new Promise<unknown>((resolve) => captureResolvers.push(resolve));
      }
      if (value.kind === "vaultmesh.save-capture-decision") return Promise.resolve({ status: "discarded" });
      return Promise.resolve({});
    });
    const controller = startAutofillPage(document, crypto.randomUUID(), sendMessage);
    const form = document.querySelector("form")!;

    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    expect(controller.savePrompt.title).toBe("正在检查账号…");
    document.querySelector<HTMLInputElement>("#username")!.value = "new@example.test";
    document.querySelector<HTMLInputElement>("#password")!.value = "second password";
    form.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));

    captureResolvers[1]!({ status: "queued", captureId: captureIds[1], hostname: "localhost", labels: ["登录信息"], update: false, expiresAt: Date.now() + 10_000 });
    await Promise.resolve();
    expect(controller.savePrompt.visible).toBe(false);

    captureResolvers[0]!({ status: "queued", captureId: captureIds[0], hostname: "localhost", labels: ["登录信息"], update: true, expiresAt: Date.now() + 10_000 });
    await Promise.resolve();
    expect(controller.savePrompt.visible).toBe(false);
    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.save-capture-decision", captureId: captureIds[0], decision: "ignore" });
    controller.dispose();
  });
});
