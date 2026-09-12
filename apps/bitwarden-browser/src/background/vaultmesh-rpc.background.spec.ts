import { VaultMeshRpcBackground } from "./vaultmesh-rpc.background";
import { VaultMeshRpcClient } from "../vaultmesh/rpc";
import { SESSION_MESSAGE, VAULTMESH_STATUS_MESSAGE } from "../vaultmesh/contracts";
jest.mock("../vaultmesh/runtime", () => ({ sendSessionMessage: jest.fn().mockResolvedValue(undefined) }));

describe("CT-BROWSER-002 popup bridge", () => {
  const client = {
    start: jest.fn(), onDisconnected: jest.fn(), status: jest.fn(),
    logins: jest.fn(), lock: jest.fn(), unlock: jest.fn(), events: jest.fn().mockResolvedValue({ sequence: 0, events: [] }),
  };
  beforeEach(() => { jest.clearAllMocks(); });
  it("does not accept content-script, other-extension or unrelated extension-page messages", () => {
    new VaultMeshRpcBackground(client as unknown as VaultMeshRpcClient).start();
    const listener = (chrome.runtime.onMessage.addListener as jest.Mock).mock.calls.at(-1)[0];
    const root = chrome.runtime.getURL("popup/index.html");
    for (const sender of [
      { id: chrome.runtime.id, tab: { id: 1 }, url: "https://example.test" },
      { id: "other-extension", url: root },
      { id: chrome.runtime.id, url: chrome.runtime.getURL("overlay/menu.html") },
      { id: chrome.runtime.id, url: root + ".other" },
    ]) expect(listener({ kind: VAULTMESH_STATUS_MESSAGE }, sender, jest.fn())).toBe(false);
    expect(client.status).not.toHaveBeenCalled();
  });
  it("keeps the Chromium response channel open for allowed popup messages", async () => {
    client.status.mockResolvedValue({ unlocked: false, hasVault: true, itemCount: 0 });
    new VaultMeshRpcBackground(client as unknown as VaultMeshRpcClient).start();
    const listener = (chrome.runtime.onMessage.addListener as jest.Mock).mock.calls.at(-1)[0];
    const respond = jest.fn();
    expect(listener({ kind: VAULTMESH_STATUS_MESSAGE }, { id: chrome.runtime.id, url: chrome.runtime.getURL("popup/index.html") + "#/vaultmesh" }, respond)).toBe(true);
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(respond).toHaveBeenCalledWith(expect.objectContaining({ status: "locked" }));
  });
  it("clears the transient password and never sends broker error details to the popup", async () => {
    client.unlock.mockRejectedValue(new Error("contains-input"));
    const message = { kind: SESSION_MESSAGE, action: "unlock", masterPassword: "test-only-password" };
    const result = await new VaultMeshRpcBackground(client as unknown as VaultMeshRpcClient).handle(message);
    expect(message.masterPassword).toBe("");
    expect(result).toEqual({ kind: SESSION_MESSAGE, ok: false, code: "invalid-broker-response" });
  });
});
