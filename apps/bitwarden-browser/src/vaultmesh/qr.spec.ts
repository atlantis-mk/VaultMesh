import { QR_CHECK, QR_SCAN, clearQr, parseTotpQr } from "./qr-contracts";
import { QrAuthorization } from "./qr-authorization";
import { scanVisibleQr } from "./qr-content";
import { collectQr } from "./qr-popup";
const uri = "otpauth://totp/Synthetic:example?secret=JBSWY3DPEHPK3PXP&issuer=Synthetic";
const id = "00000000-0000-4000-8000-000000000033";
describe("CT-AUTHENTICATOR-001 bounded explicit QR capture", () => {
  afterEach(() => { jest.restoreAllMocks(); jest.useRealTimers(); document.body.replaceChildren(); });
  it.each([uri.replace("totp/", "hotp/"), `${uri}&digits=8`, `${uri}&algorithm=SHA256`, `${uri}&period=60`, `${uri}&secret=AAAA`, "https://example.test"])("rejects unsupported or ambiguous profile %s", (raw) => expect(parseTotpQr(raw)).toBeNull());
  it("parses a supported profile without exposing the seed in its label", () => {
    expect(parseTotpQr(uri)).toEqual({ uri, issuer: "Synthetic", account: "example" });
  });
  function expose(element: Element) {
    jest.spyOn(element, "getClientRects").mockReturnValue([{}] as never);
    jest.spyOn(element, "getBoundingClientRect").mockReturnValue({ top: 1, left: 1, bottom: 21, right: 21, width: 20, height: 20 } as DOMRect);
  }
  it("scans once across visible shadow roots without reading existing input values or adding page UI", async () => {
    jest.spyOn(window, "getComputedStyle").mockReturnValue({ display: "block", visibility: "visible", opacity: "1" } as CSSStyleDeclaration);
    const host = document.createElement("div"); document.body.append(host); const root = host.attachShadow({ mode: "open" });
    const source = document.createElement("div"); source.setAttribute("data-qr-value", uri); root.append(source); expose(source);
    const input = document.createElement("input"); Object.defineProperty(input, "value", { get: () => { throw new Error("Discovery must not read field values"); } }); document.body.append(input);
    const before = document.body.innerHTML;
    const result = await scanVisibleQr(() => true); expect(result).toHaveLength(1); expect(document.body.innerHTML).toBe(before);
    source.hidden = true; expect(await scanVisibleQr(() => true)).toEqual([]);
    source.hidden = false; expect(await scanVisibleQr(() => false)).toEqual([]); clearQr(result); expect(result).toEqual([]);
  });
  it("binds a one-use start/finish grant to the active tab, exact frame, expiry and live authorization", async () => {
    const tab = { id: 2, url: "https://example.test/" };
    jest.spyOn(chrome.tabs, "query").mockImplementation((_query: any, cb: any) => cb([tab]));
    jest.spyOn(chrome.webNavigation, "getAllFrames").mockImplementation((_query: any, cb: any) => cb([{ frameId: 0, url: tab.url }]));
    jest.spyOn(chrome.webNavigation, "getFrame").mockImplementation((_query: any, cb: any) => cb({ url: tab.url }));
    const authorization = new QrAuthorization(); const current = jest.fn(async () => true); const grant = await authorization.authorize(current);
    const sender = { id: chrome.runtime.id, tab, frameId: 0, url: tab.url };
    const start = { kind: QR_CHECK, requestId: grant.requestId, phase: "start" };
    expect(await authorization["check"](start, { ...sender, frameId: 1 })).toBe(false);
    expect(await authorization["check"](start, sender)).toBe(true);
    expect(await authorization["check"](start, sender)).toBe(false);
    current.mockResolvedValue(false);
    expect(await authorization["check"]({ ...start, phase: "finish" }, sender)).toBe(false);
    current.mockResolvedValue(true);
    expect(await authorization["check"]({ ...start, phase: "finish" }, sender)).toBe(false);
    authorization.cancel(); expect(await authorization["check"](start, sender)).toBe(false);
  });
  it("receives URI material only in the invoking popup, deduplicates and clears late responses", async () => {
    const raw = { requestId: id, values: [parseTotpQr(uri)!] };
    jest.spyOn(chrome.tabs, "sendMessage").mockImplementation((_tab: any, message: any, _options: any, cb: any) => { expect(message.kind).toBe(QR_SCAN); cb(raw); });
    const grant = { requestId: id, tabId: 2, topUrl: "https://example.test/", expiresAt: Date.now() + 30000, frames: [{ frameId: 0, url: "https://example.test/" }] };
    const values = await collectQr(grant, () => true); expect(values).toEqual([parseTotpQr(uri)]); expect(raw.values[0].uri).toBe(""); clearQr(values);
    let respond!: (value: unknown) => void; let current = true;
    jest.mocked(chrome.tabs.sendMessage).mockImplementation((_tab: any, _message: any, _options: any, cb: any) => { respond = cb; });
    const pending = collectQr(grant, () => current); current = false;
    const late = { requestId: id, values: [parseTotpQr(uri)!] }; respond(late); expect(await pending).toEqual([]); expect(late.values[0].uri).toBe("");
  });
});
