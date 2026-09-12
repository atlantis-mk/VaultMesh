import DomElementVisibilityService from "../autofill/services/dom-element-visibility.service";
import { VaultMeshNativeFillContent } from "./native-fill-content";
import { VaultMeshNativeCaptureContent } from "./native-capture-content";
import { VaultMeshNativeCaptureBackground } from "./native-capture-background";
import { CAPTURE_OPTIONS, CAPTURE_SAVE } from "./native-capture-contracts";
import { sendSessionMessage } from "./runtime";
import { createVaultMeshUuid } from "./uuid";
import { LoginSaveSchema } from "./login-contracts";

jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn() }));
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

describe("CT-AUTOFILL-002 native capture ownership and explicit mutation", () => {
  let content: VaultMeshNativeFillContent;
  let capture: VaultMeshNativeCaptureContent;
  beforeEach(() => {
    jest.clearAllMocks();
    history.replaceState({}, "", "/login");
    document.body.innerHTML = '<form id="login"><input name="username" autocomplete="username"><input name="password" type="password" autocomplete="current-password"><button type="submit">Sign in</button></form>';
    jest.spyOn(DomElementVisibilityService.prototype, "isElementViewable").mockResolvedValue(true);
    jest.spyOn(DomElementVisibilityService.prototype, "isElementViewableNow").mockReturnValue(true);
    jest.spyOn(DomElementVisibilityService.prototype, "isElementHiddenByCss").mockReturnValue(false);
    jest.spyOn(HTMLElement.prototype, "getClientRects").mockReturnValue([{}] as unknown as DOMRectList);
    content = new VaultMeshNativeFillContent(); capture = new VaultMeshNativeCaptureContent(content);
    (sendSessionMessage as jest.Mock).mockResolvedValue({ nonce: createVaultMeshUuid(), expiresAt: new Date(Date.now() + 30000).toISOString(), candidates: [] });
    (chrome.webNavigation.getFrame as jest.Mock).mockImplementation((_args, callback) => callback({ url: location.href }));
  });
  afterEach(() => { capture.destroy(); content.invalidate(); jest.restoreAllMocks(); });
  const typed = (element: HTMLInputElement, value: string) => {
    element.value = value;
    // Only the browser trust bit is supplied by the test. Native collector/roles remain real.
    capture["onEvent"]({ type: "input", isTrusted: true, composedPath: () => [element] } as unknown as Event);
  };

  it("only offers metadata after submission; actual values stay in the content snapshot until Save", async () => {
    await capture.refresh();
    typed(document.querySelector('[name="username"]')!, "synthetic-user");
    typed(document.querySelector('[name="password"]')!, "synthetic-password");
    capture.observe(document.querySelector("form")!);
    expect(sendSessionMessage).toHaveBeenCalledWith({ kind: CAPTURE_OPTIONS, captureId: expect.any(String) });
    expect(JSON.stringify((sendSessionMessage as jest.Mock).mock.calls)).not.toContain("synthetic-password");
    const snapshot = capture["snapshot"]!;
    expect(snapshot.password).toBe("synthetic-password");
    capture.destroy(); expect(snapshot.password).toBe("");
  });

  it("does not capture an untouched autofill or an adjacent form", async () => {
    document.body.insertAdjacentHTML("beforeend", '<form id="other"><input name="username"><input type="password" name="password"></form>');
    await capture.refresh();
    document.querySelector<HTMLInputElement>('[name="password"]')!.value = "untouched-fill";
    capture.observe(document.querySelector("form")!);
    expect(sendSessionMessage).not.toHaveBeenCalled();
    typed(document.querySelector('[name="password"]')!, "actual-user-edit");
    capture.observe(document.querySelector("#other")!);
    expect(sendSessionMessage).not.toHaveBeenCalled();
  });
  it("preserves supported long credentials without truncation and rejects values over the owner limits", async () => {
    await capture.refresh();
    typed(document.querySelector('[name="username"]')!, "u".repeat(2048));
    typed(document.querySelector('[name="password"]')!, "p".repeat(10000));
    capture.observe(document.querySelector("form")!);
    expect(capture["snapshot"]?.username).toHaveLength(2048);
    expect(capture["snapshot"]?.password).toHaveLength(10000);
    capture.destroy();
    capture = new VaultMeshNativeCaptureContent(content);
    await capture.refresh();
    typed(document.querySelector('[name="password"]')!, "p".repeat(10001));
    capture.observe(document.querySelector("form")!);
    expect(capture["snapshot"]).toBeFalsy();
  });

  it.each(["", "different"])("rejects a %s confirmation instead of saving an old or generated password", async (confirmation) => {
    document.querySelector("form")!.insertAdjacentHTML("beforeend", '<input type="password" name="new-password" autocomplete="new-password"><input type="password" name="confirm-password" autocomplete="new-password">');
    await capture.refresh();
    typed(document.querySelector('[name="new-password"]')!, "actual-new-password");
    typed(document.querySelector('[name="confirm-password"]')!, confirmation);
    capture.observe(document.querySelector("form")!);
    expect(sendSessionMessage).not.toHaveBeenCalled();
  });

  it("captures the edited new password and clears it on cancellation", async () => {
    document.querySelector("form")!.insertAdjacentHTML("beforeend", '<input type="password" name="new-password" autocomplete="new-password"><input type="password" name="confirm-password" autocomplete="new-password">');
    await capture.refresh();
    typed(document.querySelector('[name="password"]')!, "old-password");
    typed(document.querySelector('[name="new-password"]')!, "user-edited-new-password");
    typed(document.querySelector('[name="confirm-password"]')!, "user-edited-new-password");
    capture.observe(document.querySelector("form")!);
    expect(capture["snapshot"]?.password).toBe("user-edited-new-password");
    expect(JSON.stringify((sendSessionMessage as jest.Mock).mock.calls)).not.toContain("old-password");
  });

  it("observes non-composed shadow-root submit with native field discovery", async () => {
    document.body.innerHTML = '<div id="host"></div>';
    const root = document.querySelector("#host")!.attachShadow({ mode: "open" });
    root.innerHTML = '<form><input autocomplete="username" name="username"><input autocomplete="current-password" name="password" type="password"></form>';
    await capture.refresh();
    expect(capture["fields"].length).toBe(2);
    expect(capture["roots"].has(root)).toBe(true);
    typed(root.querySelector('[name="username"]')!, "shadow-user");
    typed(root.querySelector('[name="password"]')!, "shadow-password");
    root.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, composed: false }));
    expect(capture["snapshot"]?.password).toBe("shadow-password");
  });

  it("revalidates a one-use Save and preserves untouched Login fields on update", async () => {
    const id = createVaultMeshUuid(); const captureId = createVaultMeshUuid();
    const client = {
      candidates: jest.fn().mockResolvedValue({ candidates: [{ id, title: "Synthetic", subtitle: "user" }] }),
      loginDetail: jest.fn().mockResolvedValue({ id, title: "Keep title", username: "user", url: location.href, notes: "keep-notes", folder: "keep-folder", favorite: true,
        hasTotpSecret: true, hasRecoveryCodes: true, autofillOnPageLoad: false, masterPasswordReprompt: true,
        additionalUrls: ["https://additional.test"], customFields: [{ label: "tenant", value: "synthetic-custom" }] }),
      saveLogin: jest.fn(),
    };
    let saved: any;
    client.saveLogin.mockImplementation(async (input) => { saved = LoginSaveSchema.parse(clone(input)); });
    const background = new VaultMeshNativeCaptureBackground(client as never, async () => true);
    const sender = { id: chrome.runtime.id, tab: { id: 7 }, frameId: 0, url: location.href };
    const options: any = await background.handle({ kind: CAPTURE_OPTIONS, captureId }, sender as chrome.runtime.MessageSender);
    expect(client.loginDetail).not.toHaveBeenCalled();
    const request = { kind: CAPTURE_SAVE, captureId, nonce: options.nonce, username: "actual-user", password: "actual-new-password", itemId: id };
    const replay = clone(request);
    expect(await background.handle(request, sender as chrome.runtime.MessageSender)).toEqual({ saved: true });
    expect(saved).toMatchObject({ id, title: "Keep title", username: "actual-user", password: "actual-new-password", favorite: true,
      masterPasswordReprompt: true, totpSecret: null, clearTotpSecret: false, recoveryCodes: null, clearRecoveryCodes: false,
      customFields: [{ label: "tenant", value: "synthetic-custom" }], additionalUrls: ["https://additional.test"] });
    expect(request.password).toBe("");
    expect(await background.handle(replay, sender as chrome.runtime.MessageSender)).toBeNull();
    expect(client.saveLogin).toHaveBeenCalledTimes(1);
  });

  it.each(["navigation", "same-url-navigation", "lock"])("cancels an in-flight capture update on %s", async (reason) => {
    const id = createVaultMeshUuid(); const captureId = createVaultMeshUuid();
    let finishDetail!: (detail: unknown) => void;
    const client = {
      candidates: jest.fn().mockResolvedValue({ candidates: [{ id, title: "Synthetic", subtitle: "user" }] }),
      loginDetail: jest.fn().mockImplementation(() => new Promise((resolve) => { finishDetail = resolve; })),
      saveLogin: jest.fn(),
    };
    const background = new VaultMeshNativeCaptureBackground(client as never, async () => true);
    background.start();
    const sender = { id: chrome.runtime.id, tab: { id: 7 }, frameId: 0, url: location.href } as chrome.runtime.MessageSender;
    const options: any = await background.handle({ kind: CAPTURE_OPTIONS, captureId }, sender);
    const request = { kind: CAPTURE_SAVE, captureId, nonce: options.nonce, username: "user", password: "synthetic-new", itemId: id };
    const save = background.handle(request, sender);
    for (let tick = 0; !finishDetail && tick < 20; tick++) await Promise.resolve();
    expect(finishDetail).toBeDefined();
    if (reason === "lock") background.cancel();
    else if (reason === "navigation") (chrome.webNavigation.getFrame as jest.Mock).mockImplementation((_args, callback) => callback({ url: "https://other.test" }));
    else (chrome.webNavigation.onCommitted.addListener as jest.Mock).mock.calls.at(-1)![0]({ tabId: 7, frameId: 0 });
    const detail = { id, title: "Synthetic", username: "user", url: location.href, notes: "", folder: "", favorite: false,
      hasTotpSecret: false, hasRecoveryCodes: false, autofillOnPageLoad: false, masterPasswordReprompt: false,
      additionalUrls: [], customFields: [{ label: "tenant", value: "synthetic-custom" }] };
    finishDetail(detail);
    expect(await save).toBeNull();
    expect(client.saveLogin).not.toHaveBeenCalled();
    expect(request.password).toBe("");
    expect(detail.customFields[0].value).toBe("");
  });
});
