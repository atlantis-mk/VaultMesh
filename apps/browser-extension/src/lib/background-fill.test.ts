import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { applyApprovedFill, startFillForTab } from "./background-fill";
import { backgroundDesktopRpc } from "./desktop-rpc";

vi.mock("./desktop-rpc", () => ({ backgroundDesktopRpc: vi.fn(), DesktopRpcError: class extends Error {} }));
beforeEach(() => {
  vi.spyOn(browser.tabs, "get").mockImplementation(async () => ({ id: 7, url: "https://example.test/login" } as Browser.tabs.Tab));
  vi.spyOn(browser.webNavigation, "getAllFrames").mockImplementation(async () => ([
    { frameId: 0, parentFrameId: -1, url: "https://example.test/login", errorOccurred: false },
    { frameId: 3, parentFrameId: 0, url: "https://example.test/login", errorOccurred: false },
    { frameId: 4, parentFrameId: 0, url: "https://example.test/login", errorOccurred: false },
  ]));
});
afterEach(() => { vi.restoreAllMocks(); vi.mocked(backgroundDesktopRpc).mockReset(); });
describe("CT-AUTOFILL-001 originating frame routing", () => {
  it("limits inline discovery to its source frame and retains its opaque target", async () => {
    const target = { targetId: crypto.randomUUID(), documentId: crypto.randomUUID() };
    const send = vi.spyOn(browser.tabs, "sendMessage").mockImplementation(async () => ({ documentId: target.documentId, frameOrigin: "https://example.test", fields: [] }));
    expect(await startFillForTab(7, undefined, { target, targetFrameId: 3, skipLoginPairWait: true })).toMatchObject({ status: "no-supported-fields" });
    expect(send).toHaveBeenCalledExactlyOnceWith(7, expect.objectContaining({ kind: "vaultmesh.discover-fields", target }), { frameId: 3 });
    expect(backgroundDesktopRpc).not.toHaveBeenCalled();
  });
  it("rejects a target without a frame instead of broadcasting it", async () => {
    const send = vi.spyOn(browser.tabs, "sendMessage");
    expect(await startFillForTab(7, undefined, { target: { targetId: crypto.randomUUID(), documentId: crypto.randomUUID() } })).toEqual({ status: "document-changed" });
    expect(send).not.toHaveBeenCalled();
  });
  it("does not authorize discovery from a replacement document", async () => {
    const target = { targetId: crypto.randomUUID(), documentId: crypto.randomUUID() };
    vi.spyOn(browser.tabs, "sendMessage").mockImplementation(async () => ({ documentId: crypto.randomUUID(), frameOrigin: "https://example.test", fields: [{ handle: crypto.randomUUID(), control: "input", inputType: "text", isEmpty: true, autocomplete: ["username"], label: "Username", name: "username", id: "username", placeholder: "", context: "login" }] }));
    expect(await startFillForTab(7, undefined, { target, targetFrameId: 3, skipLoginPairWait: true })).toMatchObject({ status: "no-supported-fields" });
    expect(backgroundDesktopRpc).not.toHaveBeenCalled();
  });
});
describe("CT-AUTOFILL-001 non-empty preservation", () => {
  it("reports preserved content instead of a changed page when every assignment was skipped", async () => {
    const approval = { requestId: crypto.randomUUID(), tabId: 7, topOrigin: "https://example.test", expiresAt: new Date(Date.now() + 10_000).toISOString(), frames: [{ frameId: 0, documentId: crypto.randomUUID(), frameOrigin: "https://example.test", assignments: [{ handle: crypto.randomUUID(), value: "synthetic", overwrite: false }] }] };
    vi.spyOn(browser.tabs, "sendMessage").mockImplementation(async () => ({ status: "completed", results: [{ handle: "h", status: "skipped-non-empty" }] }));
    expect(await applyApprovedFill(approval as never, 7, "https://example.test")).toEqual({ status: "preserved-existing", filledCount: 0 });
    vi.spyOn(browser.tabs, "sendMessage").mockImplementation(async () => ({ status: "stale-document", results: [] }));
    expect(await applyApprovedFill(approval as never, 7, "https://example.test")).toEqual({ status: "document-changed", filledCount: 0 });
  });
});
