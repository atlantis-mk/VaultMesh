import { AutofillScriptGenerator } from "../autofill/services/autofill-script-generator";
import DomElementVisibilityService from "../autofill/services/dom-element-visibility.service";
import { VaultMeshNativeFillContent } from "./native-fill-content";
import { VaultMeshNativeFillBackground, assertAssignment } from "./native-fill-background";
import { VaultMeshRpcClient } from "./rpc";
import { FILL_APPLY, FILL_CANCEL, FILL_COLLECT, FILL_CANDIDATES, FILL_SELECT, FILL_AUTOMATIC, clearAssignment, type Assignment, type CollectedPage } from "./native-fill-contracts";
import { sendSessionMessage } from "./runtime";
import { createVaultMeshUuid } from "./uuid";
import * as passwordGenerator from "./password-generator";
import { GENERATOR_KEY, DEFAULT_GENERATOR_PREFERENCES } from "./generator-preferences";

jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn().mockResolvedValue(true) }));
// Chromium runtime messages use JSON serialization; model that wire boundary.
const structuredClone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

describe("CT-AUTOFILL-001 native Login adapter", () => {
  let content: VaultMeshNativeFillContent;
  let background: VaultMeshNativeFillBackground;
  let page: CollectedPage;
  let wire: Record<string, any>;
  const id = "33333333-3333-4333-8333-333333333333";
  const client = {
    emailCandidates: jest.fn(), emailFill: jest.fn(),
    logins: jest.fn(), candidates: jest.fn(), loginProfile: jest.fn(), nativeLoginFill: jest.fn(), recordFill: jest.fn().mockResolvedValue(undefined),
  };
  beforeEach(() => {
    jest.clearAllMocks();
    (chrome.storage.local.get as jest.Mock).mockImplementation((_key, callback) => callback({}));
    (chrome.storage.local.set as jest.Mock).mockImplementation((_input, callback) => callback?.());
    history.replaceState({}, "", "/login");
    document.body.innerHTML = '<form><input name="username" autocomplete="username"><input name="password" type="password" autocomplete="current-password"></form>';
    jest.spyOn(DomElementVisibilityService.prototype, "isElementViewable").mockResolvedValue(true);
    jest.spyOn(DomElementVisibilityService.prototype, "isElementViewableNow").mockReturnValue(true);
    jest.spyOn(DomElementVisibilityService.prototype, "isElementHiddenByCss").mockReturnValue(false);
    jest.spyOn(HTMLElement.prototype, "getClientRects").mockReturnValue([{}] as unknown as DOMRectList);
    content = new VaultMeshNativeFillContent();
    // Real upstream prototype: planning must not touch account, SDK or secret services.
    const planner = new AutofillScriptGenerator();
    background = new VaultMeshNativeFillBackground(client as unknown as VaultMeshRpcClient, () => planner, async () => true);
    (chrome.tabs.query as jest.Mock).mockImplementation((_query, callback) => callback([{ id: 7, url: location.href }]));
    (chrome.webNavigation.getAllFrames as jest.Mock).mockImplementation((_query, callback) => callback([{ frameId: 0, url: location.href }]));
    (chrome.webNavigation.getFrame as jest.Mock).mockImplementation((_query, callback) => callback({ url: location.href }));
    (chrome.tabs.sendMessage as jest.Mock).mockImplementation((_tab, message, _options, callback) => {
      if (message.kind === FILL_COLLECT) void content.collect(message.requestId, message.targetRef, message.automatic, message.topOrigin, message.expectedUsername).then((result) => { page = result!; callback(result); });
      if (message.kind === FILL_APPLY) void content.apply(structuredClone(message)).then(callback);
      if (message.kind === FILL_CANCEL) { content.invalidate(); callback(null); }
    });
    client.logins.mockResolvedValue([{ id, title: "Synthetic Login", username: "synthetic-user", url: location.origin,
      hasPassword: true, hasTotpSecret: false, hasRecoveryCodes: false, autofillOnPageLoad: false, masterPasswordReprompt: false }]);
    client.loginProfile.mockResolvedValue({ id, customFields: [] });
    client.emailCandidates.mockResolvedValue({ candidates: [] });
    client.candidates.mockResolvedValue({ candidates: [{ id, kind: "login", title: "Synthetic", subtitle: "synthetic-user", matchScope: "origin", autofillOnPageLoad: true, masterPasswordReprompt: false }] });
    client.nativeLoginFill.mockImplementation(async (input) => {
      wire = structuredClone(input);
      const discovery = input.discovery;
      return {
        kind: "vaultmesh.approved-fill", requestId: discovery.requestId, expiresAt: discovery.expiresAt,
        tabId: 7, topOrigin: location.origin, selectedItem: { kind: "login", id, title: "Synthetic Login" },
        frames: [{ frameId: discovery.frames[0].frameId, documentId: discovery.frames[0].documentId, frameOrigin: location.origin,
          assignments: input.nativeLoginPlan.map((entry: { handle: string; source: string; index?: number }) => ({
            handle: entry.handle, value: entry.source === "password" ? "synthetic-password"
              : entry.source === "custom" ? "synthetic-custom" : entry.source === "totpCode"
                ? entry.index === undefined ? "654321" : "654321"[entry.index] : "synthetic-user",
            overwrite: !discovery.frames[0].fields.find((field: { handle: string }) => field.handle === entry.handle).isEmpty,
          })),
        }],
      };
    });
    (sendSessionMessage as jest.Mock).mockResolvedValue(true);
  });
  afterEach(() => { content.invalidate(); background.cancel(); jest.restoreAllMocks(); });

  it.each(["A1b2", "12ab56", "a1234Z78"])("CT-EMAIL-003 uses native OTP planning and execution for %s without audit or nonempty-field overwrites", async (code) => {
    document.body.innerHTML = '<form><input name="otp" autocomplete="one-time-code"><input name="otp2" autocomplete="one-time-code" value="existing"><input name="search" value="query"></form>';
    client.emailCandidates.mockImplementation(async () => ({ candidates: [{ id, code, sourceDomain: "mail.example.test", receivedAt: Math.floor(Date.now() / 1000), expiresAt: Math.floor(Date.now() / 1000) + 60 }] }));
    client.emailFill.mockImplementation(async ({ discovery }) => {
      wire = structuredClone(discovery);
      return { kind: "vaultmesh.approved-fill", requestId: discovery.requestId, expiresAt: discovery.expiresAt, tabId: 7, topOrigin: location.origin,
        frames: discovery.frames.map((frame: any) => ({ ...frame, fields: undefined, assignments: frame.fields.map((field: any) => ({ handle: field.handle, value: code, overwrite: false })) })) };
    });
    expect(await background.fillEmail(id, async () => true, { tabId: 7, url: location.href })).toEqual({ filled: 1 });
    expect(document.querySelector<HTMLInputElement>('[name="otp"]')!.value).toBe(code);
    expect(document.querySelector<HTMLInputElement>('[name="otp2"]')!.value).toBe("existing");
    expect(wire.selectedItem).toBeUndefined(); expect(JSON.stringify(wire)).not.toContain(code); expect(wire.frames[0].fields).toHaveLength(1);
    expect(client.recordFill).not.toHaveBeenCalled(); expect(client.nativeLoginFill).not.toHaveBeenCalled();
  });

  it("CT-EMAIL-003 fills native segmented OTP controls and rejects a changed popup target", async () => {
    const code = "a1B2";
    document.body.innerHTML = `<form>${Array.from({ length: 4 }, (_, index) => `<input name="otp${index}" autocomplete="one-time-code" maxlength="1">`).join("")}</form>`;
    client.emailCandidates.mockImplementation(async () => ({ candidates: [{ id, code, sourceDomain: "mail.example.test", receivedAt: 0, expiresAt: Math.floor(Date.now() / 1000) + 60 }] }));
    client.emailFill.mockImplementation(async ({ discovery }) => ({ kind: "vaultmesh.approved-fill", requestId: discovery.requestId, expiresAt: discovery.expiresAt, tabId: 7, topOrigin: location.origin,
      frames: discovery.frames.map((frame: any) => ({ frameId: frame.frameId, frameOrigin: frame.frameOrigin, documentId: frame.documentId,
        assignments: frame.fields.map((field: any, index: number) => ({ handle: field.handle, value: code[index], overwrite: false })) })) }));
    await expect(background.fillEmail(id, async () => true, { tabId: 8, url: location.href })).rejects.toMatchObject({ code: "operation-expired" });
    expect(client.emailFill).not.toHaveBeenCalled();
    expect(await background.fillEmail(id, async () => true, { tabId: 7, url: location.href })).toEqual({ filled: 4 });
    expect([...document.querySelectorAll("input")].map((input) => input.value).join("")).toBe(code);
  });

  const pageMessage = async (message: unknown, sender = { id: chrome.runtime.id, tab: { id: 7 }, frameId: 0, url: location.href }) => {
    background.start();
    const listener = (chrome.runtime.onMessage.addListener as jest.Mock).mock.calls.at(-1)[0];
    return new Promise<any>((resolve) => listener(message, sender, resolve));
  };

  it("keeps inline selection in its original form and consumes the target once", async () => {
    document.body.innerHTML += '<form id="second"><input name="username" autocomplete="username"><input name="password" type="password" autocomplete="current-password"></form>';
    const target = await content.createTarget(document.querySelector<HTMLInputElement>('#second [name="password"]')!);
    expect(target).not.toBeNull();
    const request = { targetRef: target!.targetRef, context: target!.context };
    expect(await pageMessage({ kind: FILL_CANDIDATES, ...request })).toHaveProperty("candidates");
    expect(await pageMessage({ kind: FILL_SELECT, ...request, id })).toMatchObject({ filled: 2 });
    expect([...document.querySelectorAll("form:first-child input")].every((element) => !(element as HTMLInputElement).value)).toBe(true);
    expect(await pageMessage({ kind: FILL_SELECT, ...request, id })).toBeNull();
    expect(client.nativeLoginFill).toHaveBeenCalledTimes(1);
  });

  it.each(["move", "rename", "readonly", "expire"])("does not broaden an invalid %s target to the page", async (change) => {
    const element = document.querySelector<HTMLInputElement>('[name="password"]')!;
    const target = await content.createTarget(element);
    expect(target).not.toBeNull();
    if (change === "move") document.body.append(element);
    if (change === "rename") element.name = "couponCode";
    if (change === "readonly") element.readOnly = true;
    const now = change === "expire" ? jest.spyOn(Date, "now").mockReturnValue(Date.now() + 31_000) : undefined;
    try { expect(await content.collect(createVaultMeshUuid(), target!.targetRef)).toBeNull(); }
    finally { now?.mockRestore(); }
  });

  it("only automatically discloses empty native-qualified fields in the bound form", async () => {
    const items = await client.logins(); client.logins.mockResolvedValue([{ ...items[0], autofillOnPageLoad: true }]);
    document.querySelector<HTMLInputElement>('[name="username"]')!.value = "synthetic-user";
    const target = await content.createTarget(document.querySelector<HTMLInputElement>('[name="password"]')!);
    expect(target?.automatic).toBe(true);
    expect(await pageMessage({ kind: FILL_AUTOMATIC, targetRef: target!.targetRef, context: target!.context })).toMatchObject({ filled: 1 });
    expect(wire.mode).toBe("automatic"); expect(wire.userGestureId).toBeUndefined();
    expect(wire.discovery.frames[0].fields.every((field: any) => field.isEmpty && field.context === "login")).toBe(true);
    expect(document.querySelector<HTMLInputElement>('[name="username"]')!.value).toBe("synthetic-user");
  });

  it("rejects automatic fill for password changes and ambiguous account candidates", async () => {
    document.querySelector("form")!.insertAdjacentHTML("beforeend", '<input type="password" autocomplete="new-password" name="new-password"><input type="password" autocomplete="new-password" name="confirm-password">');
    const target = await content.createTarget(document.querySelector<HTMLInputElement>('[name="password"]')!);
    expect(target?.automatic ?? false).toBe(false);
    if (target) expect(await content.collect(createVaultMeshUuid(), target.targetRef, true)).toBeNull();
    client.candidates.mockResolvedValue({ candidates: [
      { id, autofillOnPageLoad: true, masterPasswordReprompt: false },
      { id: createVaultMeshUuid(), autofillOnPageLoad: true, masterPasswordReprompt: false },
    ] });
    expect(await pageMessage({ kind: FILL_AUTOMATIC, targetRef: createVaultMeshUuid(), context: "login" })).toBeNull();
    expect(client.nativeLoginFill).not.toHaveBeenCalled();
  });

  it("keeps page account values local and refuses an automatic password for a different existing username", async () => {
    document.querySelector<HTMLInputElement>('[name="username"]')!.value = "other-page-account";
    const target = await content.createTarget(document.querySelector<HTMLInputElement>('[name="password"]')!);
    const items = await client.logins(); client.logins.mockResolvedValue([{ ...items[0], autofillOnPageLoad: true }]);
    expect(await pageMessage({ kind: FILL_AUTOMATIC, targetRef: target!.targetRef, context: target!.context })).toBeNull();
    expect(client.nativeLoginFill).not.toHaveBeenCalled();
    expect(JSON.stringify(client.candidates.mock.calls)).not.toContain("other-page-account");
    expect(document.querySelector<HTMLInputElement>('[name="password"]')!.value).toBe("");
  });

  it("generates once into the empty same-form new/confirmation pair only after a successful explicit current-password fill", async () => {
    document.querySelector("form")!.insertAdjacentHTML("beforeend", '<input type="password" name="new-password" autocomplete="new-password"><input type="password" name="confirm-password" autocomplete="new-password">');
    document.body.insertAdjacentHTML("beforeend", '<form id="adjacent"><input type="password" autocomplete="new-password"></form>');
    expect(await background.fill(id, undefined, async () => true)).toMatchObject({ filled: 2 });
    const next = document.querySelector<HTMLInputElement>('[name="new-password"]')!;
    expect(next.value).toHaveLength(20);
    expect(document.querySelector<HTMLInputElement>('[name="confirm-password"]')!.value).toBe(next.value);
    expect(document.querySelector<HTMLInputElement>('#adjacent input')!.value).toBe("");
    expect(content.wasGenerated(next)).toBe(true);
    expect(wire.nativeLoginPlan.every((entry: any) => ["username", "password"].includes(entry.source))).toBe(true);
    next.value = ""; document.querySelector<HTMLInputElement>('[name="confirm-password"]')!.value = "";
    await background.fill(id, undefined, async () => true);
    expect(next.value).toBe("");
  });

  it.each(["nonempty", "missing-confirmation", "unreliable-current"])("does not generate for %s password maintenance", async (reason) => {
    document.querySelector("form")!.insertAdjacentHTML("beforeend", '<input type="password" name="new-password" autocomplete="new-password">');
    if (reason !== "missing-confirmation") document.querySelector("form")!.insertAdjacentHTML("beforeend", '<input type="password" name="confirm-password" autocomplete="new-password">');
    if (reason === "unreliable-current") document.querySelector('[name="password"]')!.removeAttribute("autocomplete");
    const next = document.querySelector<HTMLInputElement>('[name="new-password"]')!;
    if (reason === "nonempty") next.value = "user-owned-new";
    await background.fill(id, undefined, async () => true);
    expect(next.value).toBe(reason === "nonempty" ? "user-owned-new" : "");
    expect(content.wasGenerated(next)).toBe(false);
  });

  it("uses the saved native generator rules and checks the actual configured length", async () => {
    (chrome.storage.local.get as jest.Mock).mockImplementation((_key, callback) => callback({ [GENERATOR_KEY]: {
      ...DEFAULT_GENERATOR_PREFERENCES, password: { ...DEFAULT_GENERATOR_PREFERENCES.password, length: 10, symbols: false, minimumNumbers: 4 },
    } }));
    document.querySelector("form")!.insertAdjacentHTML("beforeend", '<input type="password" name="new-password" maxlength="12" autocomplete="new-password"><input type="password" name="confirm-password" maxlength="12" autocomplete="new-password">');
    await background.fill(id, undefined, async () => true);
    const value = document.querySelector<HTMLInputElement>('[name="new-password"]')!.value;
    expect(value).toHaveLength(10); expect(value).toMatch(/^[a-zA-Z0-9]+$/); expect(value.replace(/\D/g, "").length).toBeGreaterThanOrEqual(4);
    expect(document.querySelector<HTMLInputElement>('[name="confirm-password"]')!.value).toBe(value);
  });

  it("keeps the completed credential result and never retries failed secondary password generation", async () => {
    document.querySelector("form")!.insertAdjacentHTML("beforeend", '<input type="password" name="new-password" autocomplete="new-password"><input type="password" name="confirm-password" autocomplete="new-password">');
    const generate = jest.spyOn(passwordGenerator, "generateMaintenancePassword").mockRejectedValue(new Error("synthetic-entropy-failure"));
    expect(await background.fill(id, undefined, async () => true)).toMatchObject({ filled: 2, auditRecorded: true });
    expect(document.querySelector<HTMLInputElement>('[name="password"]')!.value).toBe("synthetic-password");
    expect(document.querySelector<HTMLInputElement>('[name="new-password"]')!.value).toBe("");
    await background.fill(id, undefined, async () => true);
    expect(generate).toHaveBeenCalledTimes(1);
  });

  it("aborts generated confirmation writes if page code changes a target during a pre-write event", async () => {
    document.querySelector("form")!.insertAdjacentHTML("beforeend", '<input type="password" name="new-password" autocomplete="new-password"><input type="password" name="confirm-password" autocomplete="new-password">');
    const next = document.querySelector<HTMLInputElement>('[name="new-password"]')!;
    const confirm = document.querySelector<HTMLInputElement>('[name="confirm-password"]')!;
    next.addEventListener("focus", () => { confirm.value = "page-change"; });
    await background.fill(id, undefined, async () => true);
    expect(next.value).toBe(""); expect(confirm.value).toBe("page-change");
  });

  it.each(['<input type="search">', '<input name="couponCode">', '<input name="username" readonly>', '<input name="comment">', '<input name="username" disabled>'])("does not qualify an inline target for %s", async (html) => {
    document.body.innerHTML = `<form>${html}<input type="password" autocomplete="current-password"></form>`;
    expect(await content.createTarget(document.querySelector("input")!)).toBeNull();
  });

  it("runs real collection, native planning and native insertion; discovery contains no existing values", async () => {
    const username = document.querySelector<HTMLInputElement>('[name="username"]')!;
    const password = document.querySelector<HTMLInputElement>('[name="password"]')!;
    username.value = "existing-username-not-for-discovery";
    password.value = "existing-password-not-for-discovery";
    const input = jest.fn(); const change = jest.fn(); const submit = jest.fn();
    password.addEventListener("input", input); password.addEventListener("change", change);
    document.querySelector("form")!.addEventListener("submit", submit);
    const result = await background.fill(id, undefined, async () => true);
    expect(result).toEqual({ filled: 2, auditRecorded: true });
    expect(username.value).toBe("synthetic-user"); expect(password.value).toBe("synthetic-password");
    expect(input).toHaveBeenCalled(); expect(change).toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
    expect(JSON.stringify(wire)).not.toContain("existing-");
    expect(JSON.stringify(page)).not.toContain('"value"');
    expect(wire.nativeLoginPlan.map((entry: { source: string }) => entry.source)).toEqual(["username", "password"]);
    expect(wire.discovery.frames[0].fields.map((field: { autocomplete: string[] }) => field.autocomplete))
      .toEqual([["username"], ["current-password"]]);
    expect(client.recordFill).toHaveBeenCalledWith(expect.objectContaining({ fieldCount: 2, itemId: id }));
  });

  it("does not offer search, coupon, readonly, OTP or new-password fields to the plan", async () => {
    document.body.innerHTML = '<input type="search"><input name="couponCode"><input name="username" readonly><input autocomplete="one-time-code"><input type="password" autocomplete="new-password">';
    await expect(background.fill(id, undefined, async () => true)).rejects.toMatchObject({ code: "no-fillable-fields" });
    expect(client.nativeLoginFill).not.toHaveBeenCalled();
  });

  it("uses the native custom-field matcher with names and symbolic values only", async () => {
    document.body.innerHTML = '<input id="tenant"><input name="couponCode">';
    client.loginProfile.mockResolvedValue({ id, customFields: [{ index: 0, name: "tenant" }, { index: 1, name: "couponCode" }] });
    expect(await background.fill(id, undefined, async () => true)).toEqual({ filled: 1, auditRecorded: true });
    expect(document.querySelector<HTMLInputElement>("#tenant")!.value).toBe("synthetic-custom");
    expect(wire.nativeLoginPlan).toEqual([{ handle: expect.any(String), source: "custom", index: 0, name: "tenant" }]);
    expect(JSON.stringify(wire)).not.toContain("synthetic-custom");
    expect(document.querySelector<HTMLInputElement>('[name="couponCode"]')!.value).toBe("");
  });

  it.each([1, 6])("uses native OTP matching and splitting for %s fields without a TOTP service", async (count) => {
    document.body.innerHTML = `<form>${Array.from({ length: count }, (_, i) => `<input name="otp${i}" autocomplete="one-time-code" ${count === 6 ? 'maxlength="1"' : ''}>`).join("")}</form>`;
    const items = await client.logins();
    client.logins.mockResolvedValue([{ ...items[0], hasTotpSecret: true }]);
    const result = await background.fill(id, undefined, async () => true);
    expect(result.filled).toBe(count);
    expect(Array.from(document.querySelectorAll("input"), (field) => field.value).join("")).toBe("654321");
    expect(wire.nativeLoginPlan.every((entry: { source: string }) => entry.source === "totpCode")).toBe(true);
    if (count === 6) expect(wire.nativeLoginPlan.map((entry: { index: number }) => entry.index)).toEqual([0, 1, 2, 3, 4, 5]);
    expect(JSON.stringify(wire)).not.toContain("654321");
    expect(JSON.stringify(wire)).not.toContain("remote-totp-marker");
  });

  it("does not disclose an OTP into a nonempty field", async () => {
    document.body.innerHTML = '<input autocomplete="one-time-code" value="already-entered">';
    const items = await client.logins();
    client.logins.mockResolvedValue([{ ...items[0], hasTotpSecret: true }]);
    await expect(background.fill(id, undefined, async () => true)).rejects.toMatchObject({ code: "no-fillable-fields" });
    expect(client.nativeLoginFill).not.toHaveBeenCalled();
  });

  it("binds same-origin iframe collection and assignment to its actual frame ID", async () => {
    (chrome.webNavigation.getAllFrames as jest.Mock).mockImplementation((_query, callback) => callback([{ frameId: 4, url: location.href }, { frameId: 5, url: "https://untrusted.test/" }]));
    expect((await background.fill(id, undefined, async () => true)).filled).toBe(2);
    expect(wire.discovery.frames[0].frameId).toBe(4);
    expect((chrome.tabs.sendMessage as jest.Mock).mock.calls.every((call) => call[2].frameId === 4)).toBe(true);
  });

  it("fills a cross-origin frame only after its actual URL is explicitly selected", async () => {
    const topUrl = "https://top.synthetic.test/embed";
    const selected = { frameId: 4, url: location.href };
    (chrome.tabs.query as jest.Mock).mockImplementation((_query, callback) => callback([{ id: 7, url: topUrl }]));
    (chrome.webNavigation.getAllFrames as jest.Mock).mockImplementation((_query, callback) => callback([selected]));
    await expect(background.fill(id, undefined, async () => true)).rejects.toThrow();
    expect(client.nativeLoginFill).not.toHaveBeenCalled();
    const assign = client.nativeLoginFill.getMockImplementation()!;
    client.nativeLoginFill.mockImplementation(async (input) => ({ ...await assign(input), topOrigin: new URL(topUrl).origin }));
    expect(await background.fill(id, undefined, async () => true, selected)).toMatchObject({ filled: 2 });
    expect(wire.confirmedTargetOrigin).toBe(location.origin);
    expect(wire.discovery.topOrigin).toBe(new URL(topUrl).origin);
    expect(wire.discovery.frames[0].frameId).toBe(4);
    expect(document.querySelector<HTMLInputElement>('[name="password"]')!.value).toBe("synthetic-password");
    await expect(background.fill(id, undefined, async () => true, { ...selected, url: "https://forged.test/" })).rejects.toThrow();
    expect(client.nativeLoginFill).toHaveBeenCalledTimes(1);
  });

  it("rejects an iframe navigation before assignment disclosure", async () => {
    (chrome.webNavigation.getAllFrames as jest.Mock).mockImplementation((_query, callback) => callback([{ frameId: 4, url: location.href }]));
    (chrome.webNavigation.getFrame as jest.Mock).mockImplementation((_query, callback) => callback({ url: "https://untrusted.test/" }));
    await expect(background.fill(id, undefined, async () => true)).rejects.toMatchObject({ code: "operation-expired" });
    expect(client.nativeLoginFill).not.toHaveBeenCalled();
  });

  it.each(["replace", "move", "readonly", "reclassify", "navigate", "revoke", "hidden"])("rejects %s during native pre-insert events", async (kind) => {
    const password = document.querySelector<HTMLInputElement>('[name="password"]')!;
    password.addEventListener("keydown", () => {
      if (kind === "replace") password.replaceWith(password.cloneNode());
      if (kind === "move") document.body.append(password);
      if (kind === "readonly") password.readOnly = true;
      if (kind === "reclassify") password.name = "couponCode";
      if (kind === "navigate") history.pushState({}, "", "/other");
      if (kind === "revoke") content.invalidate();
      if (kind === "hidden") jest.mocked(DomElementVisibilityService.prototype.isElementViewableNow).mockReturnValue(false);
    }, { once: true });
    const result = await background.fill(id, undefined, async () => true);
    expect(result.filled).toBe(1);
    expect(password.value).toBe("");
  });

  it("uses the native setter for controlled inputs and rejects replays", async () => {
    const password = document.querySelector<HTMLInputElement>('[name="password"]')!;
    const intercepted = jest.fn();
    Object.defineProperty(password, "value", { configurable: true,
      get() { return Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.get!.call(this); }, set: intercepted });
    await background.fill(id, undefined, async () => true);
    expect(password.value).toBe("synthetic-password");
    expect(intercepted).not.toHaveBeenCalled();
    expect(await content.apply({})).toBeNull();
  });

  it("does not dispatch an assignment after authorization is revoked", async () => {
    const current = jest.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(true).mockResolvedValueOnce(true).mockResolvedValue(false);
    await expect(background.fill(id, undefined, current)).rejects.toMatchObject({ code: "operation-expired" });
    expect((chrome.tabs.sendMessage as jest.Mock).mock.calls.some((call) => call[1].kind === FILL_APPLY)).toBe(false);
  });

  it("revalidates authorization before each native action and reports no writes on refusal", async () => {
    (sendSessionMessage as jest.Mock).mockResolvedValue(false);
    expect((await background.fill(id, undefined, async () => true)).filled).toBe(0);
    expect(client.recordFill).not.toHaveBeenCalled();
  });

  it("rejects an expired local document and does not overwrite text entered after discovery", async () => {
    const execute = client.nativeLoginFill.getMockImplementation()!;
    client.nativeLoginFill.mockImplementationOnce(async (input) => {
      const assignment = await execute(input);
      document.querySelector<HTMLInputElement>('[name="password"]')!.value = "user-typed-after-discovery";
      return assignment;
    });
    expect((await background.fill(id, undefined, async () => true)).filled).toBe(1);
    expect(document.querySelector<HTMLInputElement>('[name="password"]')!.value).toBe("user-typed-after-discovery");
    const collected = await content.collect(createVaultMeshUuid());
    const expired = { kind: "vaultmesh.approved-fill", requestId: collected!.requestId, tabId: 7,
      topOrigin: location.origin, expiresAt: collected!.expiresAt, selectedItem: { kind: "login", id, title: "Synthetic" },
      frames: [{ frameId: 0, frameOrigin: location.origin, documentId: collected!.documentId,
        assignments: [{ handle: collected!.fields[0].handle, value: "must-not-fill", overwrite: false }] }],
    };
    const now = jest.spyOn(Date, "now").mockReturnValue(Date.parse(collected!.expiresAt) + 1);
    try { expect(await content.apply({ assignment: expired, script: [["fill_by_opid", collected!.fields[0].opid, "username"]] })).toBeNull(); }
    finally { now.mockRestore(); }
  });

  it("validates every assignment binding and clears values without caching", async () => {
    await background.fill(id, undefined, async () => true);
    const original = client.nativeLoginFill.mock.results[0].value;
    const consumed = await original as Assignment;
    expect(consumed.frames[0].assignments.every((entry) => entry.value === "")).toBe(true);
    for (const mutate of [
      (a: Assignment) => { a.tabId++; }, (a: Assignment) => { a.requestId = createVaultMeshUuid(); },
      (a: Assignment) => { a.frames[0].documentId = createVaultMeshUuid(); },
      (a: Assignment) => { a.frames[0].frameOrigin = "https://evil.test"; },
      (a: Assignment) => { a.selectedItem.id = createVaultMeshUuid(); },
      (a: Assignment) => { a.frames[0].assignments[0].handle = createVaultMeshUuid(); },
      (a: Assignment) => { a.expiresAt = new Date(0).toISOString(); },
    ]) {
      const bad = structuredClone(consumed); mutate(bad);
      expect(() => assertAssignment(bad, page, 7, id, new Set(page.fields.map((f) => f.handle)))).toThrow();
      clearAssignment(bad);
    }
  });
});
