import DomElementVisibilityService from "../autofill/services/dom-element-visibility.service";
import { VaultMeshNativeFillContent } from "./native-fill-content";
import { VaultMeshNativePageContent } from "./native-page-content";
import { sendSessionMessage } from "./runtime";
jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn().mockResolvedValue(null) }));

describe("CT-AUTOFILL-001 native-qualified page icon lifecycle", () => {
  let content: VaultMeshNativeFillContent;
  let page: VaultMeshNativePageContent;
  beforeEach(() => {
    jest.clearAllMocks();
    document.body.innerHTML = '<form><input name="username" autocomplete="username"><input type="password" autocomplete="current-password"><input name="couponCode"><input type="search" name="search"><input name="comment" readonly></form>';
    jest.spyOn(DomElementVisibilityService.prototype, "isElementViewable").mockResolvedValue(true);
    jest.spyOn(DomElementVisibilityService.prototype, "isElementViewableNow").mockReturnValue(true);
    jest.spyOn(DomElementVisibilityService.prototype, "isElementHiddenByCss").mockReturnValue(false);
    jest.spyOn(HTMLElement.prototype, "getClientRects").mockReturnValue([{}] as unknown as DOMRectList);
    content = new VaultMeshNativeFillContent(); page = new VaultMeshNativePageContent(content);
  });
  afterEach(() => { page.destroy(); content.invalidate(); jest.restoreAllMocks(); });
  it("collects a multi-field form target once per automatic attempt, not once per input", async () => {
    document.body.innerHTML = Array.from({ length: 5 }, () => '<form><input autocomplete="username"><input type="password" autocomplete="current-password"></form>').join("");
    const collect = jest.spyOn(content, "collect");
    const target = jest.spyOn(content, "createTarget");
    await page["automatic"]();
    expect(target).toHaveBeenCalledTimes(5);
    expect(collect).toHaveBeenCalledTimes(6); // one discovery + one target per form
    expect(sendSessionMessage).toHaveBeenCalledTimes(5);
    await page["automatic"]();
    expect(target).toHaveBeenCalledTimes(5); // existing scopes do not trigger a full re-collection
    expect(sendSessionMessage).toHaveBeenCalledTimes(5); // never repeat a page write
  });
  it("prefetches candidates on offer and does not duplicate the read when clicked", async () => {
    let reply!: (value: unknown) => void;
    (sendSessionMessage as jest.Mock).mockImplementationOnce(() => new Promise(resolve => { reply = resolve; }));
    await page.offer(document.querySelector<HTMLInputElement>('[name="username"]')!);
    expect(sendSessionMessage).toHaveBeenCalledTimes(1);
    const first = page["showCandidates"]();
    expect(page["root"]?.querySelector(".list")?.textContent).toContain("正在读取候选");
    await page["showCandidates"](); await page["showCandidates"]();
    expect(sendSessionMessage).toHaveBeenCalledTimes(1);
    reply({ candidates: [] }); await first;
    expect(page["candidatesPending"]).toBeUndefined();
  });
  it("waits for the startup capture read before qualifying a focused input", async () => {
    const capture = content.captureControls();
    const target = content.createTarget(document.querySelector<HTMLInputElement>('[name="username"]')!);
    await capture;
    expect(await target).toMatchObject({ context: "login" });
  });
  it("reschedules discovery while the collector is busy without starting a page write", async () => {
    jest.spyOn(content, "isCollecting").mockReturnValue(true);
    const scan = jest.spyOn(content, "automaticTargets");
    await page["automatic"]();
    expect(scan).not.toHaveBeenCalled();
    expect(page["scanTimer"]).toBeDefined();
    expect(sendSessionMessage).not.toHaveBeenCalled();
  });
  it("runs a burst scan within 100 ms rather than restarting a 500 ms debounce", async () => {
    jest.useFakeTimers();
    const scan = jest.spyOn(page as any, "automatic").mockResolvedValue(undefined);
    try {
      page["scheduleScan"](); jest.advanceTimersByTime(75);
      page["scheduleScan"](); jest.advanceTimersByTime(25);
      expect(scan).toHaveBeenCalledTimes(1);
      page["scheduleScan"](); page.destroy(); jest.advanceTimersByTime(100);
      expect(scan).toHaveBeenCalledTimes(1);
    } finally { jest.useRealTimers(); }
  });
  it("only mounts the icon for the native-qualified input, not neighboring unfillable controls", async () => {
    await page.offer(document.querySelector('[name="username"]')!);
    expect(page["host"]?.isConnected).toBe(true);
    expect(page["root"]?.querySelector("button")?.getAttribute("aria-label")).toContain("VaultMesh");
    for (const name of ["couponCode", "search", "comment"]) {
      await page.offer(document.querySelector(`[name="${name}"]`)!);
      expect(page["host"]).toBeUndefined();
    }
  });
  it("drops late candidate results when the field becomes readonly", async () => {
    let respond!: (value: unknown) => void;
    (sendSessionMessage as jest.Mock).mockImplementation(() => new Promise((resolve) => { respond = resolve; }));
    const field = document.querySelector<HTMLInputElement>('[name="username"]')!;
    await page.offer(field);
    const candidates = page["showCandidates"]();
    field.readOnly = true;
    respond({ candidates: [{ id: "33333333-3333-4333-8333-333333333333", kind: "login", title: "Late", subtitle: "user", matchScope: "origin", autofillOnPageLoad: false, masterPasswordReprompt: false }] });
    await candidates;
    expect(page["root"]).toBeUndefined();
    page["position"]();
    expect(page["host"]).toBeUndefined();
  });
});
