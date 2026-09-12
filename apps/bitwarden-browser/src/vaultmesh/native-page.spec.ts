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
