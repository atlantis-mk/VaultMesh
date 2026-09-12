/** @jest-environment-options {"url":"https://example.test/checkout"} */
import DomElementVisibilityService from "../autofill/services/dom-element-visibility.service";
import { VaultMeshNativeFillContent } from "./native-fill-content";
import { nativePage, FILL_COLLECT, FILL_APPLY, FILL_CANCEL } from "./native-fill-contracts";
import { planNativeItem, formatNativeItem } from "./native-item-planner";
import { VaultMeshNativeFillBackground } from "./native-fill-background";
import { AutofillScriptGenerator } from "../autofill/services/autofill-script-generator";
import { sendSessionMessage } from "./runtime";
import { createVaultMeshUuid as uuid } from "./uuid";
import { VaultMeshRpcClient } from "./rpc";
import { NativeItemCaptureContent } from "./native-item-capture-content";
import { applyCapturedItem } from "./native-item-capture";
import { ManagedDraft } from "./managed-draft";
import { NativeGeneratedContent } from "./native-generated-content";
import { CAPTURE_OPTIONS, CAPTURE_ITEM_SAVE } from "./native-capture-contracts";
import { VaultMeshNativeCaptureBackground } from "./native-capture-background";
import { VaultMeshNativeCaptureContent } from "./native-capture-content";

jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn().mockResolvedValue(true) }));
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
describe("CT-AUTOFILL-001/002 native card/identity and CT-BROWSER-003 generated insertion", () => {
  let content: VaultMeshNativeFillContent;
  beforeEach(() => {
    jest.clearAllMocks(); history.replaceState({}, "", "/checkout");
    jest.spyOn(DomElementVisibilityService.prototype, "isElementViewable").mockResolvedValue(true);
    jest.spyOn(DomElementVisibilityService.prototype, "isElementViewableNow").mockReturnValue(true);
    jest.spyOn(DomElementVisibilityService.prototype, "isElementHiddenByCss").mockReturnValue(false);
    jest.spyOn(HTMLElement.prototype, "getClientRects").mockReturnValue([{}] as unknown as DOMRectList);
    content = new VaultMeshNativeFillContent(); (sendSessionMessage as jest.Mock).mockResolvedValue(true);
    (chrome.tabs.query as jest.Mock).mockImplementation((_q, callback) => callback([{ id: 7, url: location.href }]));
    (chrome.webNavigation.getAllFrames as jest.Mock).mockImplementation((_q, callback) => callback([{ frameId: 0, url: location.href }]));
    (chrome.webNavigation.getFrame as jest.Mock).mockImplementation((_q, callback) => callback({ url: location.href }));
    (chrome.tabs.sendMessage as jest.Mock).mockImplementation((_tab, message, _options, callback) => {
      if (message.kind === FILL_COLLECT) void content.collect(message.requestId, undefined, false, message.topOrigin).then(callback);
      if (message.kind === FILL_APPLY) void content.apply(clone(message)).then(callback);
      if (message.kind === FILL_CANCEL) { content.invalidate(); callback(null); }
    });
  });
  afterEach(() => { content.invalidate(); jest.restoreAllMocks(); });
  it("uses upstream SSH public-key/title matching within the original form only", async () => {
    document.body.innerHTML = '<form><input name="title"><textarea name="public_key" placeholder="ssh-ed25519"></textarea><textarea name="key"></textarea></form><form><input name="title"></form><textarea name="comments"></textarea>';
    const page = nativePage((await content.collect(uuid()))!);
    const plan = await planNativeItem(page, "ssh");
    expect([...plan.values()].sort()).toEqual(["ssh:publicKey", "ssh:title"]);
    expect((await content.createTarget(document.querySelector("textarea")!))?.context).toBe("ssh");
    expect(await content.createTarget(document.querySelector<HTMLTextAreaElement>('[name="key"]')!)).toBeNull();
    expect(await content.createTarget(document.querySelectorAll("input")[1])).toBeNull();
  });
  it.each([
    ["ssh", "sshHost", "ssh:host"], ["ssh", "ssh_password", "ssh:password"],
    ["ssh", "sshPrivateKey", "ssh:privateKey"], ["ssh", "SSH key passphrase", "ssh:keyPassphrase"],
    ["secret", "api_key", "secret:api-key"], ["secret", "accessToken", "secret:access-token"],
    ["secret", "client_secret", "secret:client-secret"], ["secret", "webhook_secret", "secret:webhook-secret"],
    ["secret", "totpSecret", "secret:authenticator-key"], ["secret", "licenseKey", "secret:software-license"],
  ] as const)("adapts %s %s through original custom-field matching without a Login fallback", async (kind, name, source) => {
    document.body.innerHTML = '<form><input type="password"><input name="key"><input name="tokenSearch"><textarea name="comments"></textarea></form>';
    document.querySelector("input")!.name = name;
    const native = nativePage((await content.collect(uuid()))!);
    expect([...await planNativeItem(native, kind)].map(([, value]) => value)).toEqual([source]);
    const target = await content.createTarget(document.querySelector("input")!);
    expect(target).toMatchObject({ context: kind, automatic: false });
  });
  it("refuses ambiguous credential sources and does not offer a generic password fallback", async () => {
    document.body.innerHTML = '<form><input id="sshPassword" name="api_key" type="password"></form>';
    const page = nativePage((await content.collect(uuid()))!);
    expect((await planNativeItem(page, "ssh")).size).toBe(0); expect((await planNativeItem(page, "secret")).size).toBe(0);
    expect(await content.createTarget(document.querySelector("input")!)).toBeNull();
  });
  it("does not capture SSH/service passwords as Login credentials", async () => {
    document.body.innerHTML = '<form><input name="sshPassword" type="password"></form>';
    const capture = new VaultMeshNativeCaptureContent(content);
    try {
      await capture.refresh(); const field = document.querySelector("input")!; field.value = "synthetic-only";
      capture["onEvent"]({ type: "input", isTrusted: true, composedPath: () => [field] } as unknown as Event);
      capture.observe(document.querySelector("form")!);
      expect(sendSessionMessage).not.toHaveBeenCalled();
    } finally { capture.destroy(); }
  });
  it.each(["ssh", "secret"] as const)("executes %s assignments through the actual native executor and preserves unrelated fields", async (kind) => {
    document.body.innerHTML = kind === "ssh"
      ? '<form><textarea name="public_key" placeholder="ssh-ed25519"></textarea><input name="title"><input name="comments" value="keep"></form>'
      : '<form><input type="password" name="api_key"><input name="access_token" value="keep"></form>';
    const id = uuid();
    const client = { managedItem: jest.fn().mockResolvedValue([{ id, title: "Synthetic" }]), recordFill: jest.fn(), nativeLoginFill: jest.fn(async (input) => {
      const d = input.discovery;
      expect(JSON.stringify(d)).not.toContain("synthetic-protected");
      return { kind: "vaultmesh.approved-fill", requestId: d.requestId, expiresAt: d.expiresAt, tabId: 7, topOrigin: location.origin,
        selectedItem: { kind, id, title: "Synthetic" }, frames: [{ frameId: 0, documentId: d.frames[0].documentId, frameOrigin: location.origin,
          assignments: input.nativeItemPlan.map((p: any) => ({ handle: p.handle, value: "synthetic-protected", overwrite: false })) }] };
    }) };
    const bg = new VaultMeshNativeFillBackground(client as unknown as VaultMeshRpcClient, () => new AutofillScriptGenerator());
    try {
      expect(await bg.fill(id, undefined, async () => true, { frameId: 0, url: location.href }, kind)).toMatchObject({ filled: kind === "ssh" ? 2 : 1 });
      expect(document.querySelector<HTMLInputElement>('[value="keep"]')!.value).toBe("keep");
      expect((document.querySelector("textarea") ?? document.querySelector("input"))!.value).toBe("synthetic-protected");
    } finally { bg.cancel(); }
  });
  it("preserves SSH unread keys and Secret metadata, scopes and reprompt on capture updates", () => {
    const ssh = new ManagedDraft("ssh", { id: uuid(), title: "Keep", recordKind: "key", masterPasswordReprompt: true });
    applyCapturedItem(ssh, [{ source: "ssh:publicKey", value: "ssh-ed25519 synthetic-public-only" }]);
    expect(ssh.toInput()).toMatchObject({ recordKind: "key", privateKey: null, keyPassphrase: null, clearPrivateKey: false, masterPasswordReprompt: true });
    const secret = new ManagedDraft("secret", { id: uuid(), title: "Keep", kind: "api-key", provider: "Keep", scopes: ["read", "write"], masterPasswordReprompt: true });
    applyCapturedItem(secret, [{ source: "secret:api-key", value: "synthetic-new" }]);
    expect(secret.toInput()).toMatchObject({ kind: "api-key", provider: "Keep", scopes: ["read", "write"], masterPasswordReprompt: true, secret: "synthetic-new" });
    expect(() => applyCapturedItem(secret, [{ source: "secret:client-secret", value: "wrong-type" }])).toThrow("capture-kind-mismatch");
    expect(() => applyCapturedItem(ssh, [{ source: "ssh:password", value: "wrong-record" }])).toThrow("capture-kind-mismatch");
    ssh.clear(); secret.clear();
  });
  it("creates typed SSH accounts/keys and Secret captures without inventing credentials", () => {
    const account = new ManagedDraft("ssh"); account.data.title = "Synthetic";
    applyCapturedItem(account, [{ source: "ssh:host", value: "host.test" }, { source: "ssh:username", value: "user" }, { source: "ssh:password", value: "synthetic-only" }]);
    expect(account.toInput()).toMatchObject({ recordKind: "account", host: "host.test", username: "user", port: 22 });
    const key = new ManagedDraft("ssh"); key.data.title = "Synthetic";
    applyCapturedItem(key, [{ source: "ssh:publicKey", value: "ssh-ed25519 synthetic-public-only" }]);
    expect(key.toInput()).toMatchObject({ recordKind: "key", privateKey: null });
    const secret = new ManagedDraft("secret"); secret.data.title = "Synthetic";
    applyCapturedItem(secret, [{ source: "secret:webhook-secret", value: "synthetic-only" }]);
    expect(secret.toInput()).toMatchObject({ kind: "webhook-secret", masterPasswordReprompt: false });
    expect(() => applyCapturedItem(new ManagedDraft("secret"), [{ source: "secret:api-key", value: "one" }, { source: "secret:access-token", value: "two" }])).toThrow();
    account.clear(); key.clear(); secret.clear();
  });
  it.each(["ssh", "secret"] as const)("keeps %s capture local until explicit one-use Save and binds its new metadata", async (kind) => {
    document.body.innerHTML = kind === "ssh" ? '<form><textarea name="public_key" placeholder="ssh-ed25519"></textarea></form>' : '<form><input name="api_key" type="password"></form>';
    const capture = new NativeItemCaptureContent(content);
    const saveCalls: any[] = [];
    const client = { managedItem: jest.fn(async (command) => {
      if (command.verb === "list") return [];
      saveCalls.push(clone(command)); return { id: uuid(), title: "Synthetic" };
    }) };
    const bg = new VaultMeshNativeCaptureBackground(client as unknown as VaultMeshRpcClient, async () => true);
    const sender = { id: chrome.runtime.id, tab: { id: 7 }, frameId: 0, url: location.href } as chrome.runtime.MessageSender;
    (sendSessionMessage as jest.Mock).mockImplementation((message) => bg.handle(message, sender));
    try {
      await capture.refresh();
      const field = (document.querySelector("textarea") ?? document.querySelector("input"))!;
      field.value = kind === "ssh" ? "ssh-ed25519 synthetic-public-only" : "synthetic-api-only";
      capture["event"]({ type: "input", isTrusted: true, composedPath: () => [field] } as unknown as Event);
      capture.observe(document.querySelector("form")!);
      const snapshot = capture["snapshot"]!;
      for (let i = 0; i < 12; i++) await Promise.resolve();
      expect(saveCalls).toHaveLength(0);
      expect(JSON.stringify((sendSessionMessage as jest.Mock).mock.calls)).not.toContain(field.value);
      const offer = bg["offers"].get(snapshot.captureId)!;
      const request = { kind: CAPTURE_ITEM_SAVE, captureId: snapshot.captureId, nonce: offer.nonce, itemKind: kind, values: clone(snapshot.values) };
      const replay = clone(request);
      expect(await bg.handle(request, sender)).toEqual({ saved: true });
      expect(saveCalls).toHaveLength(1);
      expect(saveCalls[0].input).toMatchObject(kind === "ssh" ? { recordKind: "key", privateKey: null }
        : { kind: "api-key", website: location.origin, scopes: [], masterPasswordReprompt: false });
      expect(await bg.handle(replay, sender)).toBeNull();
      expect(request.values.every((row) => row.value === "")).toBe(true);
    } finally { bg.cancel(); capture.destroy(); }
  });
  it.each(["ssh", "secret"] as const)("invalidates pending %s Save on navigation or authorization cancellation", async (itemKind) => {
    const client = { managedItem: jest.fn().mockResolvedValue([]) };
    const bg = new VaultMeshNativeCaptureBackground(client as unknown as VaultMeshRpcClient, async () => true);
    const sender = { id: chrome.runtime.id, tab: { id: 7 }, frameId: 0, url: location.href } as chrome.runtime.MessageSender;
    const captureId = uuid();
    const offer: any = await bg.handle({ kind: CAPTURE_OPTIONS, captureId, itemKind }, sender);
    bg.cancel();
    expect(await bg.handle({ kind: CAPTURE_ITEM_SAVE, captureId, nonce: offer.nonce, itemKind,
      values: [{ source: itemKind === "ssh" ? "ssh:publicKey" : "secret:api-key", value: "synthetic-only" }] }, sender)).toBeNull();
    expect(client.managedItem).toHaveBeenCalledTimes(1);
    const nextId = uuid(); const next: any = await bg.handle({ kind: CAPTURE_OPTIONS, captureId: nextId, itemKind }, sender);
    (chrome.webNavigation.getFrame as jest.Mock).mockImplementation((_q, callback) => callback({ url: "https://other.test" }));
    expect(await bg.handle({ kind: CAPTURE_ITEM_SAVE, captureId: nextId, nonce: next.nonce, itemKind,
      values: [{ source: itemKind === "ssh" ? "ssh:publicKey" : "secret:api-key", value: "synthetic-only" }] }, sender)).toBeNull();
    expect(client.managedItem).toHaveBeenCalledTimes(2);
    bg.cancel();
  });
  it("shares concurrent Login and managed observer collection instead of starving either timer", async () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input type="password" autocomplete="current-password"></form>';
    const [login, managed] = await Promise.all([content.captureFields(), content.captureControls()]);
    expect(login).toHaveLength(2); expect(managed).toHaveLength(2);
    expect(login[0].element).toBe(managed[0].element);
  });
  it("plans card controls without values and retains original expiry/select formatting", async () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-exp" placeholder="MM/YY"><select autocomplete="cc-exp-month"><option value="">Month</option>' + Array.from({ length: 12 }, (_, i) => `<option value="m${i + 1}">${i + 1}</option>`).join("") + '</select><input type="search" name="search"><input name="couponCode"></form>';
    const page = (await content.collect(uuid()))!; const native = nativePage(page);
    const plan = await planNativeItem(native, "card");
    expect([...plan.values()]).toEqual(expect.arrayContaining(["card:number", "card:exp", "card:expMonth"]));
    expect(plan.size).toBe(3); expect(JSON.stringify(page)).not.toContain('"value":');
    const expiry = [...plan].find(([, source]) => source === "card:exp")![0];
    expect(await formatNativeItem(native, expiry, "card:exp", "09/2031")).toBe("09/31");
    const month = [...plan].find(([, source]) => source === "card:expMonth")![0];
    expect(await formatNativeItem(native, month, "card:expMonth", "09")).toBe("m9");
  });
  it("plans country select symbolically and resolves only its approved original option", async () => {
    document.body.innerHTML = '<form><input autocomplete="given-name"><select autocomplete="country"><option value="">Select</option><option value="US">United States</option></select><input name="statement"><textarea name="comments"></textarea></form>';
    const native = nativePage((await content.collect(uuid()))!); const plan = await planNativeItem(native, "identity");
    expect([...plan.values()]).toEqual(["identity:firstName", "identity:country"]);
    const opid = [...plan].find(([, source]) => source === "identity:country")![0];
    expect(await formatNativeItem(native, opid, "identity:country", "United States")).toBe("US");
    expect(await formatNativeItem(native, opid, "identity:country", "not-a-country")).toBeNull();
  });
  it("offers only native-qualified empty card/identity inputs, never unrelated payment fields", async () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="given-name"><input name="statement"><input name="couponCode"><input name="comments"></form>';
    expect((await content.createTarget(document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!))?.context).toBe("card");
    expect((await content.createTarget(document.querySelector<HTMLInputElement>('[autocomplete="given-name"]')!))?.context).toBe("identity");
    for (const name of ["statement", "couponCode", "comments"]) expect(await content.createTarget(document.querySelector<HTMLInputElement>(`[name="${name}"]`)!)).toBeNull();
    const card = document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!; card.value = "keep";
    expect(await content.createTarget(card)).toBeNull();
  });
  it("refuses a changed select option list before any native write", async () => {
    document.body.innerHTML = '<form><select autocomplete="country"><option value="">Select</option><option value="US">United States</option></select></form>';
    const page = (await content.collect(uuid()))!; const source = [...await planNativeItem(nativePage(page), "identity")][0];
    const field = page.fields.find((field) => field.opid === source[0])!;
    document.querySelector("select")!.options[1].value = "changed";
    const result = await content.apply({ assignment: { kind: "vaultmesh.approved-fill", requestId: page.requestId, expiresAt: page.expiresAt, tabId: 7, topOrigin: location.origin,
      selectedItem: { kind: "identity", id: uuid(), title: "Synthetic" }, frames: [{ frameId: 0, frameOrigin: location.origin, documentId: page.documentId, assignments: [{ handle: field.handle, value: "US", overwrite: false }] }] },
      script: [["fill_by_opid", source[0], source[1]]] });
    expect(result?.filled ?? 0).toBe(0); expect(document.querySelector("select")!.value).toBe("");
  });
  it.each(["card", "identity"] as const)("executes real native %s collector/planner/executor with a one-use field assignment", async (kind) => {
    document.body.innerHTML = kind === "card" ? '<form><input autocomplete="cc-number"><input autocomplete="cc-csc"><input name="couponCode"></form>' : '<form><input autocomplete="given-name"><input autocomplete="family-name" value="keep"><input type="search"></form>';
    const id = uuid(); let wire: any;
    const client = { managedItem: jest.fn().mockResolvedValue([{ id, title: "Synthetic" }]), recordFill: jest.fn(), nativeLoginFill: jest.fn(async (input) => {
      wire = clone(input); const d = input.discovery;
      return { kind: "vaultmesh.approved-fill", requestId: d.requestId, expiresAt: d.expiresAt, tabId: 7, topOrigin: location.origin, selectedItem: { kind, id, title: "Synthetic" },
        frames: [{ frameId: 0, documentId: d.frames[0].documentId, frameOrigin: location.origin, assignments: input.nativeItemPlan.map((p: any) => ({ handle: p.handle, value: p.source === "card:number" ? "4111111111111111" : p.source === "card:code" ? "123" : "Synthetic", overwrite: false })) }] };
    }) };
    const bg = new VaultMeshNativeFillBackground(client as unknown as VaultMeshRpcClient, () => new AutofillScriptGenerator());
    try {
      expect(await bg.fill(id, kind === "card" ? "synthetic-master" : undefined, async () => true, { frameId: 0, url: location.href }, kind)).toMatchObject({ filled: kind === "card" ? 2 : 1 });
      expect(wire.nativeLoginPlan).toBeUndefined(); expect(JSON.stringify(wire.discovery)).not.toContain("4111111111111111");
      if (kind === "identity") expect(document.querySelector<HTMLInputElement>('[autocomplete="family-name"]')!.value).toBe("keep");
      expect(client.recordFill).toHaveBeenCalledWith(expect.objectContaining({ itemKind: kind }));
    } finally { bg.cancel(); }
  });
  it("captures only edited same-form native sources and keeps values local until Save", async () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><button type="submit">Save</button></form><form id="other"><input autocomplete="cc-number"></form>';
    const capture = new NativeItemCaptureContent(content);
    (sendSessionMessage as jest.Mock).mockResolvedValue({ nonce: uuid(), expiresAt: new Date(Date.now() + 30000).toISOString(), candidates: [] });
    try {
      await capture.refresh(); const input = document.querySelector("input")!; input.value = "4111111111111111";
      capture.observe(document.querySelector("form")!); expect(sendSessionMessage).not.toHaveBeenCalled();
      capture["event"]({ type: "input", isTrusted: true, composedPath: () => [input] } as unknown as Event);
      capture.observe(document.querySelector("#other")!); expect(sendSessionMessage).not.toHaveBeenCalled();
      capture.observe(document.querySelector("form")!);
      expect(sendSessionMessage).toHaveBeenCalledWith({ kind: CAPTURE_OPTIONS, captureId: expect.any(String), itemKind: "card" });
      expect(JSON.stringify((sendSessionMessage as jest.Mock).mock.calls)).not.toContain(input.value);
      const snapshot = capture["snapshot"]!; expect(snapshot.values[0].value).toBe(input.value); capture.destroy(); expect(snapshot.values[0].value).toBe("");
    } finally { capture.destroy(); }
  });
  it("preserves card unread secrets and identity multivalue metadata on partial updates", () => {
    const card = new ManagedDraft("card", { id: uuid(), title: "Keep", expirationMonth: 7, expirationYear: 2030, cardholderName: "Existing", masterPasswordReprompt: true });
    applyCapturedItem(card, [{ source: "card:exp", value: "08/32" }]);
    expect(card.toInput()).toMatchObject({ title: "Keep", cardNumber: null, securityCode: null, pin: null, expirationMonth: 8, expirationYear: 2032 });
    const emails = [{ id: uuid(), label: "primary", value: "old@example.test", preferred: true }, { id: uuid(), label: "secondary", value: "keep@example.test", preferred: false }];
    const identity = new ManagedDraft("identity", { id: uuid(), title: "Keep", firstName: "Keep", emails });
    applyCapturedItem(identity, [{ source: "identity:email", value: "new@example.test" }]);
    expect(identity.toInput()).toMatchObject({ firstName: "Keep", emails: [{ ...emails[0], value: "new@example.test" }, emails[1]] });
    expect(() => applyCapturedItem(identity, [{ source: "card:number", value: "4111111111111111" }])).toThrow();
    card.clear(); identity.clear();
  });
  it("binds capture Save to type/frame/nonce and consumes failed writes without replay", async () => {
    const id = uuid(); const captureId = uuid(); let saved: any;
    const client = { managedItem: jest.fn(async (command) => {
      if (command.verb === "list") return [{ id, title: "Keep" }];
      if (command.verb === "detail") return { id, title: "Keep", firstName: "Keep", emails: [], phones: [], addresses: [] };
      saved = clone(command.input); throw new Error("uncertain-write");
    }) };
    const bg = new VaultMeshNativeCaptureBackground(client as unknown as VaultMeshRpcClient, async () => true);
    const sender = { id: chrome.runtime.id, tab: { id: 7 }, frameId: 0, url: location.href };
    const offer: any = await bg.handle({ kind: CAPTURE_OPTIONS, captureId, itemKind: "identity" }, sender);
    const message = { kind: CAPTURE_ITEM_SAVE, captureId, nonce: offer.nonce, itemKind: "identity", itemId: id, values: [{ source: "identity:firstName", value: "Changed" }] };
    await expect(bg.handle(clone(message), sender)).rejects.toThrow("uncertain-write");
    expect(saved.firstName).toBe("Changed"); expect(saved.title).toBe("Keep");
    expect(await bg.handle(clone(message), sender)).toBeNull();
    expect(client.managedItem.mock.calls.filter(([c]) => c.verb === "save")).toHaveLength(1);
  });
  it.each(["password", "passphrase", "username", "uuid"] as const)("inserts %s through the native executor and consumes focus once", async (mode) => {
    const password = ["password", "passphrase"].includes(mode);
    document.body.innerHTML = password ? '<form><input type="password" autocomplete="new-password"><input type="password" autocomplete="new-password"></form>' : `<form><input type="text" autocomplete="${mode === "username" ? "username" : "off"}"></form>`;
    const generated = new NativeGeneratedContent(content);
    generated["remember"](document.querySelector("input")!);
    const message = { kind: "vaultmesh.native-fill.generated", requestId: uuid(), url: location.href, expiresAt: new Date(Date.now() + 30000).toISOString(), generated: { mode, value: "Synthetic-result-123" } };
    expect(await generated.insert(clone(message))).toEqual({ filled: password ? 2 : 1 });
    expect([...document.querySelectorAll("input")].every((f) => f.value === "Synthetic-result-123")).toBe(true);
    expect(await generated.insert(clone(message))).toBeNull();
  });
  it.each(["nonempty", "readonly", "maxLength", "navigation", "locked", "currentPassword"])("rejects generator %s without overwriting", async (reason) => {
    document.body.innerHTML = '<form><input type="password" autocomplete="new-password"></form>';
    const element = document.querySelector("input")!; const generated = new NativeGeneratedContent(content);
    generated["remember"](element);
    if (reason === "nonempty") element.value = "keep";
    if (reason === "readonly") element.readOnly = true;
    if (reason === "maxLength") element.maxLength = 2;
    if (reason === "currentPassword") element.autocomplete = "current-password";
    if (reason === "navigation") history.replaceState({}, "", "/changed");
    if (reason === "locked") (sendSessionMessage as jest.Mock).mockResolvedValue(false);
    const before = element.value;
    expect(await generated.insert({ kind: "vaultmesh.native-fill.generated", requestId: uuid(), url: location.href, expiresAt: new Date(Date.now() + 30000).toISOString(), generated: { mode: "password", value: "Synthetic-result" } })).toBeNull();
    expect(element.value).toBe(before);
  });
});
