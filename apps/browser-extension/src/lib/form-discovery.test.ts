import { describe, expect, it } from "vitest";

import { analyzeControlSemantics, applyAssignments, classifyControl, discardFieldHandles, discoverFields, hasLoginFields, isNewPasswordControl, loginFormSignature, selectAutofillPageContext, shouldPreserveExistingLoginAccount } from "./form-discovery";

function makeVisible(element: HTMLElement) {
  Object.defineProperty(element, "getClientRects", {
    value: () => [{ width: 10, height: 10 }],
  });
}

describe("discoverFields", () => {
  it("preserves account fields for every non-account login control", () => {
    document.body.innerHTML = `
      <form>
        <input id="account" autocomplete="username webauthn" value="Ada@Example.test">
        <input id="password" type="password" autocomplete="off">
        <input id="otp" autocomplete="one-time-code">
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const password = document.querySelector("#password")!;

    expect(shouldPreserveExistingLoginAccount(password)).toBe(true);
    expect(shouldPreserveExistingLoginAccount(document.querySelector("#otp")!)).toBe(true);
    expect(shouldPreserveExistingLoginAccount(document.querySelector("#account")!)).toBe(false);
  });

  it("returns value-free descriptors for supported identity fields", () => {
    document.body.innerHTML = `
      <label for="email">Email address</label>
      <input id="email" name="email" autocomplete="email" value="private@example.com" />
      <select id="country" autocomplete="country"><option value="CN">China</option></select>
    `;
    document.querySelectorAll<HTMLElement>("input, select").forEach(makeVisible);

    const result = discoverFields(document);

    expect(result.descriptors).toHaveLength(2);
    expect(result.descriptors[0]).toMatchObject({
      control: "input",
      isEmpty: false,
      autocomplete: ["email"],
      label: "Email address",
    });
    expect(JSON.stringify(result.descriptors)).not.toContain("private@example.com");
  });

  it("discovers an autocomplete-off Apple account-name field as a login account", () => {
    document.body.innerHTML = `
      <label id="apple_id_field_label">Apple Account</label>
      <input type="text" id="account_name_text_field" can-field="accountName" aria-labelledby="apple_id_field_label" autocorrect="off" autocapitalize="off" aria-required="true" required="required" spellcheck="false" ($focus)="appleIdFocusHandler($element)" ($blur)="appleIdBlurHandler()" class="force-ltr form-textbox-input" autocomplete="off" aria-invalid="false">
    `;
    const input = document.querySelector<HTMLInputElement>("#account_name_text_field")!;
    makeVisible(input);

    const { descriptors } = discoverFields(document);
    expect(classifyControl(input)).toBe("login");
    expect(shouldPreserveExistingLoginAccount(input)).toBe(false);
    expect(descriptors).toEqual([
      expect.objectContaining({ id: "account_name_text_field", inputType: "text", context: "login", isEmpty: true }),
    ]);
  });

  it("discovers value-free login/card controls but excludes unrelated sensitive, hidden, and read-only controls", () => {
    document.body.innerHTML = `
      <input name="password" type="password" />
      <input name="card_number" autocomplete="cc-number" />
      <input name="code" autocomplete="one-time-code" />
      <input name="readonly" readonly />
      <input name="hidden" type="hidden" />
      <input name="first_name" autocomplete="given-name" />
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    const result = discoverFields(document);

    expect(result.descriptors.map((field) => field.autocomplete)).toEqual([[], ["cc-number"], ["one-time-code"], ["given-name"]]);
    expect(JSON.stringify(result.descriptors)).not.toContain("value");
  });

  it("discovers a username webauthn field while excluding its ancestor-hidden password step", () => {
    document.body.innerHTML = `
      <form>
        <input id="account" autocomplete="username webauthn" value="private-account">
        <div id="password-step" aria-hidden="true" style="height:0;overflow:hidden">
          <input id="password" type="password" autocomplete="off" value="private-password">
        </div>
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    const firstStep = discoverFields(document);

    expect(firstStep.descriptors).toEqual([
      expect.objectContaining({ id: "account", autocomplete: ["username", "webauthn"], context: "login" }),
    ]);
    expect(classifyControl(document.querySelector("#account")!)).toBe("login");
    expect(loginFormSignature(firstStep.descriptors)).toContain("account");
    expect(JSON.stringify(firstStep.descriptors)).not.toContain("private-account");
    expect(JSON.stringify(firstStep.descriptors)).not.toContain("private-password");

    const passwordStep = document.querySelector<HTMLElement>("#password-step")!;
    passwordStep.setAttribute("aria-hidden", "false");
    passwordStep.style.height = "40px";
    const secondStep = discoverFields(document);
    expect(secondStep.descriptors.map((field) => field.id)).toEqual(["account", "password"]);
  });

  it("excludes controls hidden or clipped by an ancestor", () => {
    document.body.innerHTML = `
      <div hidden><input id="hidden-attribute"></div>
      <div aria-hidden="true"><input id="aria-hidden"></div>
      <div inert><input id="inert"></div>
      <div style="display:none"><input id="display-none"></div>
      <div style="visibility:hidden"><input id="visibility-hidden"></div>
      <div style="opacity:0"><input id="transparent"></div>
      <div style="height:0;overflow:hidden"><input id="clipped"></div>
      <input id="aria-disabled" aria-disabled="true">
      <div><input id="visible" autocomplete="username"></div>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    expect(discoverFields(document).descriptors.map((field) => field.id)).toEqual(["visible"]);
  });

  it("discovers open shadow-root controls and classifies autofill field kinds", () => {
    document.body.innerHTML = `<div id="login-host"></div><input id="card" autocomplete="cc-number"><input id="first" autocomplete="given-name">`;
    const shadow = document.querySelector("#login-host")!.attachShadow({ mode: "open" });
    shadow.innerHTML = `<label id="password-label">Password</label><input id="password" type="password" aria-labelledby="password-label">`;
    const password = shadow.querySelector<HTMLInputElement>("input")!;
    const card = document.querySelector<HTMLInputElement>("#card")!;
    const first = document.querySelector<HTMLInputElement>("#first")!;
    [password, card, first].forEach(makeVisible);

    const result = discoverFields(document);

    expect(result.descriptors).toHaveLength(3);
    expect(result.descriptors.find((field) => field.id === "password")?.label).toBe("Password");
    expect(classifyControl(password)).toBe("login");
    expect(classifyControl(card)).toBe("card");
    expect(classifyControl(first)).toBe("identity");
    expect(hasLoginFields(result.descriptors)).toBe(true);
    expect(loginFormSignature(result.descriptors)).toContain("password");
  });

  it("discovers closed shadow-root controls through the extension DOM API", () => {
    document.body.innerHTML = `<div id="closed-login"></div>`;
    const host = document.querySelector<HTMLElement>("#closed-login")!;
    const closed = host.attachShadow({ mode: "closed" });
    closed.innerHTML = `<input id="closed-password" type="password">`;
    makeVisible(closed.querySelector<HTMLInputElement>("input")!);
    const extensionBrowser = browser as unknown as { dom?: { openOrClosedShadowRoot: (target: Element) => ShadowRoot | null } };
    extensionBrowser.dom = { openOrClosedShadowRoot: (target) => target === host ? closed : null };
    try {
      const result = discoverFields(document);
      expect(result.descriptors).toHaveLength(1);
      expect(result.descriptors[0]).toMatchObject({ id: "closed-password", inputType: "password" });
    } finally {
      delete extensionBrowser.dom;
    }
  });

  it("distinguishes signup, password-change, OTP, secret, SSH, and checkout contexts", () => {
    document.body.innerHTML = `
      <form id="signup"><h1>注册</h1><input id="signup-email" type="email" autocomplete="email"><input id="signup-password" type="password" autocomplete="new-password"></form>
      <form id="change"><input id="old-password" type="password" autocomplete="current-password"><input id="new-password" type="password" autocomplete="new-password"></form>
      <input id="otp" autocomplete="one-time-code">
      <textarea id="api-key" aria-label="API key"></textarea>
      <div id="ssh-key" contenteditable="plaintext-only" aria-label="SSH private key"></div>
      <input id="expiry" type="month" autocomplete="cc-exp">
    `;
    document.querySelectorAll<HTMLElement>("input, textarea, [contenteditable]").forEach(makeVisible);

    const { descriptors } = discoverFields(document);
    const byId = (id: string) => descriptors.find((entry) => entry.id === id)!;
    expect(byId("signup-email")).toMatchObject({ context: "signup" });
    expect(classifyControl(document.querySelector("#signup-email")!)).toBe("login");
    expect(byId("old-password")).toMatchObject({ context: "password-change" });
    expect(byId("otp")).toMatchObject({ context: "otp" });
    expect(classifyControl(document.querySelector("#api-key")!)).toBe("secret");
    expect(byId("ssh-key")).toMatchObject({ control: "contenteditable", context: "ssh-console" });
    expect(byId("expiry")).toMatchObject({ inputType: "month", context: "checkout" });
    expect(selectAutofillPageContext(descriptors.filter((entry) => ["signup-email", "signup-password"].includes(entry.id)))).toBe("unknown");
  });

  it("keeps an rcvps-style email login form in login context when registration links are nearby", () => {
    document.body.innerHTML = `
      <section class="account-panel">
        <form id="email-login" action="/login?action=email">
          <h2>邮箱登录</h2>
          <label for="email">邮箱</label><input id="email" name="email" placeholder="请输入您的邮箱或ID">
          <label for="password">密码</label><input id="password" name="password" type="password">
          <a href="/register">还没有账户？现在注册</a>
          <button type="submit">登录</button>
        </form>
        <a href="/register">创建账户</a>
      </section>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    const email = document.querySelector<HTMLInputElement>("#email")!;
    const password = document.querySelector<HTMLInputElement>("#password")!;
    const emailAnalysis = analyzeControlSemantics(email);
    const passwordAnalysis = analyzeControlSemantics(password);

    expect(emailAnalysis).toMatchObject({ context: "login", role: "account", confidence: "high" });
    expect(passwordAnalysis).toMatchObject({ context: "login", role: "current-password", confidence: "high" });
    expect(emailAnalysis.reasons).toEqual(expect.arrayContaining(["structure:account-and-current-password", "route:login", "submit:login"]));
    expect(emailAnalysis.reasons).not.toContain("heading:signup");
  });

  it("selects a real login cluster independently from a signup form on the same page", () => {
    document.body.innerHTML = `
      <form id="login" action="/login"><input autocomplete="username"><input type="password" autocomplete="current-password"><button>Sign in</button></form>
      <form id="signup" action="/register"><input autocomplete="email"><input type="password" autocomplete="new-password"><button>Create account</button></form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    const { descriptors } = discoverFields(document);
    expect(descriptors.filter((field) => field.context === "login")).toHaveLength(2);
    expect(descriptors.filter((field) => field.context === "signup")).toHaveLength(2);
    expect(selectAutofillPageContext(descriptors)).toBe("login");
  });

  it("keeps semantic diagnostics bounded to reason codes without field values", () => {
    document.body.innerHTML = `<form action="/login"><input id="account" autocomplete="username" value="private@example.test"><input type="password" autocomplete="current-password" value="private-password"><button>登录</button></form>`;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    const analysis = analyzeControlSemantics(document.querySelector<HTMLInputElement>("#account")!);
    expect(JSON.stringify(analysis)).not.toContain("private@example.test");
    expect(JSON.stringify(analysis)).not.toContain("private-password");
    expect(analysis.reasons.every((reason) => /^[a-z-]+:[a-z-]+$/.test(reason))).toBe(true);
  });

  it("recognizes heuristic and segmented authentication-code controls without autocomplete hints", () => {
    document.body.innerHTML = `
      <form><h1>Two-factor authentication</h1><label>Authentication code</label>
        ${Array.from({ length: 6 }, (_, index) => `<input id="digit-${index}" name="code_${index}" maxlength="1" inputmode="numeric">`).join("")}
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    const { descriptors } = discoverFields(document);
    expect(descriptors).toHaveLength(6);
    expect(descriptors.every((field) => field.context === "otp" && field.maxLength === 1)).toBe(true);
    expect(descriptors.every((field) => classifyControl(document.getElementById(field.id)!) === "login")).toBe(true);
    expect(hasLoginFields(descriptors)).toBe(true);
    expect(loginFormSignature(descriptors)).toContain("digit-0");
  });

  it("keeps aria-labelled segmented verification codes in OTP context inside a signup form", () => {
    document.body.innerHTML = `
      <form><h1>Create account</h1>
        <input type="password" autocomplete="new-password">
        <div class="form-security-code-inputs">
          ${Array.from({ length: 6 }, (_, index) => `<input class="form-security-code-input" autocapitalize="off" autocorrect="off" spellcheck="false" autocomplete="off" aria-label="验证码数字 ${index + 1}" type="tel" value="">`).join("")}
        </div>
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    const codeInputs = Array.from(document.querySelectorAll<HTMLInputElement>(".form-security-code-input"));
    const { descriptors } = discoverFields(document);
    expect(codeInputs.every((input) => analyzeControlSemantics(input).context === "otp")).toBe(true);
    expect(codeInputs.every((input) => classifyControl(input) === "login")).toBe(true);
    expect(descriptors.filter((field) => field.label.startsWith("验证码数字")).map((field) => field.context)).toEqual(Array(6).fill("otp"));
  });

  it("keeps a named verification_code field in OTP context beside signup credentials", () => {
    document.body.innerHTML = `
      <form><h1>注册</h1>
        <input id="username" name="username" type="text">
        <input id="password" name="password" type="password">
        <input id="email" name="email" type="email">
        <button type="button">获取验证码</button>
        <label for="verification_code">验证码</label>
        <input id="verification_code" name="verification_code" type="text" placeholder="输入验证码">
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const code = document.querySelector<HTMLInputElement>("#verification_code")!;
    expect(analyzeControlSemantics(code).context).toBe("otp");
    expect(classifyControl(code)).toBe("login");
    expect(discoverFields(document).descriptors.find((field) => field.id === "verification_code")).toMatchObject({ context: "otp", isEmpty: true });
  });

  it("classifies SSH host and numeric port controls as SSH fields", () => {
    document.body.innerHTML = `
      <form><h1>SSH connection</h1>
        <label for="host">Host</label><input id="host" name="host">
        <label for="port">Port</label><input id="port" name="port" type="number">
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const host = document.querySelector<HTMLInputElement>("#host")!;
    const port = document.querySelector<HTMLInputElement>("#port")!;

    expect(classifyControl(host)).toBe("ssh");
    expect(classifyControl(port)).toBe("ssh");
    expect(discoverFields(document).descriptors).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "host", context: "ssh-console" }),
      expect.objectContaining({ id: "port", inputType: "number", context: "ssh-console" }),
    ]));
  });

  it("keeps account and password controls inside a developer-secret form out of login classification", () => {
    document.body.innerHTML = `
      <form><h1>API key credentials</h1>
        <label for="account">Account</label><input id="account" name="account">
        <label for="credential">Password</label><input id="credential" name="password" type="password">
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const account = document.querySelector<HTMLInputElement>("#account")!;
    const credential = document.querySelector<HTMLInputElement>("#credential")!;

    expect(classifyControl(account)).toBe("secret");
    expect(classifyControl(credential)).toBe("secret");
  });

  it("distinguishes new-password fields from the current password using metadata and form context", () => {
    document.body.innerHTML = `
      <form>
        <label for="current">当前密码</label><input id="current" type="password">
        <label for="next">设置新密码</label><input id="next" type="password">
        <label for="confirmation">确认密码</label><input id="confirmation" type="password">
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    expect(isNewPasswordControl(document.querySelector("#current")!)).toBe(false);
    expect(isNewPasswordControl(document.querySelector("#next")!)).toBe(true);
    expect(isNewPasswordControl(document.querySelector("#confirmation")!)).toBe(true);
  });

  it("treats an unannotated signup password followed by Confirm Password as one new-password pair", () => {
    document.body.innerHTML = `
      <form><h1>Sign Up</h1>
        <input id="password" name="password" type="password" autocomplete="off">
        <input id="confirmation" name="confirm_password" aria-label="Confirm Password" type="password" autocomplete="off">
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    expect(isNewPasswordControl(document.querySelector("#password")!)).toBe(true);
    expect(isNewPasswordControl(document.querySelector("#confirmation")!)).toBe(true);
    expect(analyzeControlSemantics(document.querySelector("#password")!).context).toBe("signup");
  });

  it("treats a generic password before an explicit new password as the original password", () => {
    document.body.innerHTML = `
      <form>
        <label for="current">密码</label><input id="current" name="password" type="password">
        <label for="next">设置新密码</label><input id="next" type="password">
        <label for="confirmation">确认新密码</label><input id="confirmation" type="password">
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    expect(isNewPasswordControl(document.querySelector("#current")!)).toBe(false);
    expect(isNewPasswordControl(document.querySelector("#next")!)).toBe(true);
    expect(isNewPasswordControl(document.querySelector("#confirmation")!)).toBe(true);
  });

  it("keeps 登录密码 classified as the original password inside a password-setup form", () => {
    document.body.innerHTML = `
      <form>
        <label for="login-password">登录密码</label><input id="login-password" name="login_secret" type="password">
        <label for="next">设置新密码</label><input id="next" name="new_password" type="password">
        <label for="confirmation">确认新密码</label><input id="confirmation" name="confirm_password" type="password">
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);

    expect(isNewPasswordControl(document.querySelector("#login-password")!)).toBe(false);
    expect(isNewPasswordControl(document.querySelector("#next")!)).toBe(true);
    expect(isNewPasswordControl(document.querySelector("#confirmation")!)).toBe(true);
  });

  it("fills approved handles with animated controlled-input events and never overwrites by default", async () => {
    document.body.innerHTML = `<input id="name"><input id="prefilled" value="keep"><select id="country"><option value="GB">United Kingdom</option></select>`;
    document.querySelectorAll<HTMLElement>("input, select").forEach(makeVisible);
    const { handles, descriptors } = discoverFields(document);
    const name = descriptors.find((field) => field.id === "name")!;
    const prefilled = descriptors.find((field) => field.id === "prefilled")!;
    const country = descriptors.find((field) => field.id === "country")!;
    const values: string[] = [];
    document.querySelector<HTMLInputElement>("#name")!.addEventListener("input", (event) => values.push((event.currentTarget as HTMLInputElement).value));

    const result = await applyAssignments({
      documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", currentOrigin: "https://example.test", fields: handles,
      message: { kind: "vaultmesh.apply-assignments", requestId: "a5370ec1-4dc7-4c77-a6e0-f2a4f6e37f03", documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", frameOrigin: "https://example.test", expiresAt: new Date(Date.now() + 10_000).toISOString(), assignments: [{ handle: name.handle, value: "Ada", overwrite: false }, { handle: prefilled.handle, value: "replace", overwrite: false }, { handle: country.handle, value: "GB", overwrite: true }] },
    });
    expect(result.results.map((entry) => entry.status)).toEqual(["filled", "skipped-non-empty", "filled"]);
    expect(document.querySelector<HTMLInputElement>("#name")!.value).toBe("Ada");
    expect(document.querySelector<HTMLSelectElement>("#country")!.value).toBe("GB");
    expect(values).toEqual(["A", "Ad", "Ada"]);
  });

  it("clears stale handle maps without filling a replacement document", async () => {
    document.body.innerHTML = `<input id="email">`;
    makeVisible(document.querySelector("input")!);
    const { handles, descriptors } = discoverFields(document);
    document.querySelector("input")!.remove();
    const result = await applyAssignments({
      documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", currentOrigin: "https://example.test", fields: handles,
      message: { kind: "vaultmesh.apply-assignments", requestId: "a5370ec1-4dc7-4c77-a6e0-f2a4f6e37f03", documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", frameOrigin: "https://example.test", expiresAt: new Date(Date.now() + 10_000).toISOString(), assignments: [{ handle: descriptors[0]!.handle, value: "ada@example.test", overwrite: false }] },
    });
    expect(result.results).toEqual([{ handle: descriptors[0]!.handle, status: "missing" }]);
  });

  it("retires discovered handles on same-document navigation before a delayed assignment arrives", async () => {
    document.body.innerHTML = `<input id="account" autocomplete="username">`;
    const input = document.querySelector<HTMLInputElement>("#account")!;
    makeVisible(input);
    const { handles, descriptors } = discoverFields(document);
    discardFieldHandles(handles);

    const result = await applyAssignments({
      documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", currentOrigin: "https://example.test", fields: handles,
      message: { kind: "vaultmesh.apply-assignments", requestId: "a5370ec1-4dc7-4c77-a6e0-f2a4f6e37f03", documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", frameOrigin: "https://example.test", expiresAt: new Date(Date.now() + 10_000).toISOString(), assignments: [{ handle: descriptors[0]!.handle, value: "synthetic-account", overwrite: true }] },
    });

    expect(result.results).toEqual([{ handle: descriptors[0]!.handle, status: "missing" }]);
    expect(input.value).toBe("");
  });

  it("rejects origin, document, and expiration races without touching the page", async () => {
    document.body.innerHTML = `<input id="username">`;
    makeVisible(document.querySelector("input")!);
    const { handles, descriptors } = discoverFields(document);
    const base = { kind: "vaultmesh.apply-assignments" as const, requestId: crypto.randomUUID(), documentId: crypto.randomUUID(), frameOrigin: "https://example.test", expiresAt: new Date(Date.now() + 10_000).toISOString(), assignments: [{ handle: descriptors[0]!.handle, value: "should-not-fill", overwrite: true }] };
    expect((await applyAssignments({ message: base, documentId: crypto.randomUUID(), fields: handles, currentOrigin: "https://example.test" })).status).toBe("stale-document");
    expect((await applyAssignments({ message: base, documentId: base.documentId, fields: handles, currentOrigin: "https://other.test" })).status).toBe("stale-document");
    expect((await applyAssignments({ message: { ...base, expiresAt: new Date(Date.now() - 1).toISOString() }, documentId: base.documentId, fields: handles, currentOrigin: "https://example.test" })).status).toBe("stale-document");
    expect(document.querySelector<HTMLInputElement>("#username")!.value).toBe("");
  });

  it("types the account before the password even when assignments arrive in reverse order", async () => {
    document.body.innerHTML = `<input id="account" autocomplete="username" value="old-account"><input id="password" type="password" autocomplete="current-password" value="old-password">`;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const { handles, descriptors } = discoverFields(document);
    const account = descriptors.find((field) => field.id === "account")!;
    const password = descriptors.find((field) => field.id === "password")!;
    const progress: string[] = [];
    document.querySelector<HTMLInputElement>("#account")!.addEventListener("input", (event) => progress.push(`account:${(event.currentTarget as HTMLInputElement).value}`));
    document.querySelector<HTMLInputElement>("#password")!.addEventListener("input", (event) => progress.push(`password:${(event.currentTarget as HTMLInputElement).value}`));

    const result = await applyAssignments({
      documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", currentOrigin: "https://example.test", fields: handles,
      message: { kind: "vaultmesh.apply-assignments", requestId: "a5370ec1-4dc7-4c77-a6e0-f2a4f6e37f03", documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", frameOrigin: "https://example.test", expiresAt: new Date(Date.now() + 10_000).toISOString(), clearBeforeFill: true, assignments: [{ handle: password.handle, value: "12", overwrite: true }, { handle: account.handle, value: "ab", overwrite: true }] },
    });

    expect(result.results.map((entry) => entry.status)).toEqual(["filled", "filled"]);
    expect(progress).toEqual(["account:", "password:", "account:a", "account:ab", "password:1", "password:12"]);
  });

  it("clears unmatched SSH username and password fields before filling the selected SSH item", async () => {
    document.body.innerHTML = `
      <form><h1>SSH connection</h1>
        <input id="host" name="ssh_host" value="old-host">
        <input id="port" name="ssh_port" type="number" value="22">
        <input id="username" name="ssh_username" value="old-user">
        <input id="password" name="ssh_password" type="password" value="old-password">
      </form>
    `;
    document.querySelectorAll<HTMLElement>("input").forEach(makeVisible);
    const { handles, descriptors } = discoverFields(document);
    const host = descriptors.find((field) => field.id === "host")!;
    const port = descriptors.find((field) => field.id === "port")!;

    const result = await applyAssignments({
      documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", currentOrigin: "https://example.test", fields: handles,
      message: {
        kind: "vaultmesh.apply-assignments", requestId: "b5370ec1-4dc7-4c77-a6e0-f2a4f6e37f03",
        documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", frameOrigin: "https://example.test",
        expiresAt: new Date(Date.now() + 10_000).toISOString(), clearBeforeFill: true,
        selectedItem: { kind: "ssh", id: "c5370ec1-4dc7-4c77-a6e0-f2a4f6e37f03", title: "Production SSH" },
        assignments: [{ handle: host.handle, value: "new-host", overwrite: true }, { handle: port.handle, value: "2222", overwrite: true }],
      },
    });

    expect(result.results.map((entry) => entry.status)).toEqual(["filled", "filled"]);
    expect(document.querySelector<HTMLInputElement>("#host")!.value).toBe("new-host");
    expect(document.querySelector<HTMLInputElement>("#port")!.value).toBe("2222");
    expect(document.querySelector<HTMLInputElement>("#username")!.value).toBe("");
    expect(document.querySelector<HTMLInputElement>("#password")!.value).toBe("");
  });

  it("waits for an approved input to become visible before typing", async () => {
    document.body.innerHTML = `<input id="account" autocomplete="username">`;
    const input = document.querySelector<HTMLInputElement>("#account")!;
    let visible = true;
    Object.defineProperty(input, "getClientRects", {
      value: () => visible ? [{ width: 10, height: 10 }] : [],
    });
    const { handles, descriptors } = discoverFields(document);
    visible = false;

    const pending = applyAssignments({
      documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", currentOrigin: "https://example.test", fields: handles,
      message: { kind: "vaultmesh.apply-assignments", requestId: "a5370ec1-4dc7-4c77-a6e0-f2a4f6e37f03", documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03", frameOrigin: "https://example.test", expiresAt: new Date(Date.now() + 10_000).toISOString(), assignments: [{ handle: descriptors[0]!.handle, value: "ab", overwrite: true }] },
    });
    await new Promise((resolve) => setTimeout(resolve, 75));
    expect(input.value).toBe("");

    visible = true;
    const result = await pending;
    expect(result.results).toEqual([{ handle: descriptors[0]!.handle, status: "filled" }]);
    expect(input.value).toBe("ab");
  });

  it("stops a pending assignment when its document identity changes", async () => {
    document.body.innerHTML = `<input id="account" autocomplete="username">`;
    const input = document.querySelector<HTMLInputElement>("#account")!;
    let visible = true;
    Object.defineProperty(input, "getClientRects", { value: () => visible ? [{ width: 10, height: 10 }] : [] });
    const { handles, descriptors } = discoverFields(document);
    visible = false;
    const documentId = "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03";
    let activeDocumentId = documentId;

    const pending = applyAssignments({
      documentId, currentDocumentId: () => activeDocumentId, currentOrigin: "https://example.test", fields: handles,
      message: { kind: "vaultmesh.apply-assignments", requestId: "a5370ec1-4dc7-4c77-a6e0-f2a4f6e37f03", documentId, frameOrigin: "https://example.test", expiresAt: new Date(Date.now() + 10_000).toISOString(), assignments: [{ handle: descriptors[0]!.handle, value: "synthetic-account", overwrite: true }] },
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    activeDocumentId = crypto.randomUUID();
    visible = true;

    const result = await pending;
    expect(result).toEqual({ status: "stale-document", results: [] });
    expect(input.value).toBe("");
  });
});
