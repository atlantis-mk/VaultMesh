import { VaultMeshRpcBackground } from "./vaultmesh-rpc.background";
import { VaultMeshRpcClient, VaultMeshRpcError } from "../vaultmesh/rpc";
import { SESSION_MESSAGE, VAULTMESH_STATUS_MESSAGE } from "../vaultmesh/contracts";
jest.mock("../vaultmesh/runtime", () => ({ sendSessionMessage: jest.fn().mockResolvedValue(undefined) }));

describe("CT-BROWSER-002 popup bridge", () => {
  const client = {
    start: jest.fn(), onDisconnected: jest.fn(), status: jest.fn(),
    logins: jest.fn(), lock: jest.fn(), unlock: jest.fn(), events: jest.fn().mockResolvedValue({ sequence: 0, events: [] }),
  };
  beforeEach(() => { jest.clearAllMocks(); });
  it("coalesces event checks for two unlock status reads but excludes writes and preserves replay checks", async () => {
    client.status.mockResolvedValue({ unlocked: false, hasVault: true, itemCount: 0 });
    const replies: ((value: unknown) => void)[] = [];
    const securityTool = jest.fn(() => new Promise(resolve => replies.push(resolve)));
    const background = new VaultMeshRpcBackground({ ...client, securityTool } as unknown as VaultMeshRpcClient);
    const status = await background.handle({ kind: VAULTMESH_STATUS_MESSAGE }) as any;
    client.events.mockClear();
    const message = (operation: string, id: string) => ({ kind: SESSION_MESSAGE, action: "security-tool", command: { operation, input: {} },
      mutationId: id, expiresAt: new Date(Date.now() + 30000).toISOString(), sessionId: status.sessionId, revision: status.revision });
    const pin = message("pin.status", "00000000-0000-4000-8000-000000000001");
    const first = background.handle(pin);
    const second = background.handle(message("biometric.status", "00000000-0000-4000-8000-000000000002"));
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(replies).toHaveLength(2); expect(client.events).toHaveBeenCalledTimes(1);
    expect(await background.handle(pin)).toMatchObject({ ok: false, code: "duplicate-operation" });
    expect(await background.handle(message("biometric.unlock", "00000000-0000-4000-8000-000000000003"))).toMatchObject({ ok: false, code: "operation-busy" });
    expect(await background.handle(message("pin.status", "00000000-0000-4000-8000-000000000004"))).toMatchObject({ ok: false, code: "operation-busy" });
    replies[0]({ enabled: false }); replies[1]({ available: false });
    expect(await first).toMatchObject({ ok: true }); expect(await second).toMatchObject({ ok: true });
    expect(background["unlockReadsPending"]).toBe(0);
    const expired = message("pin.status", "00000000-0000-4000-8000-000000000005");
    expired.expiresAt = new Date(Date.now() - 1000).toISOString();
    expect(await background.handle(expired)).toMatchObject({ ok: false, code: "operation-expired" });
  });
  it("rejects late unlock status reads after a lock and releases read slots", async () => {
    client.status.mockResolvedValue({ unlocked: false, hasVault: true, itemCount: 0 });
    let reply!: (value: unknown) => void;
    const securityTool = jest.fn(() => new Promise(resolve => { reply = resolve; }));
    const background = new VaultMeshRpcBackground({ ...client, securityTool } as unknown as VaultMeshRpcClient);
    const status = await background.handle({ kind: VAULTMESH_STATUS_MESSAGE }) as any;
    const pending = background.handle({ kind: SESSION_MESSAGE, action: "security-tool", command: { operation: "pin.status", input: {} },
      mutationId: "00000000-0000-4000-8000-000000000011", expiresAt: new Date(Date.now() + 30000).toISOString(), sessionId: status.sessionId, revision: status.revision });
    await new Promise(resolve => setTimeout(resolve, 0));
    await background.handle({ kind: SESSION_MESSAGE, action: "lock" });
    reply({ enabled: true });
    expect(await pending).toMatchObject({ ok: false, code: "operation-expired" });
    expect(background["unlockReadsPending"]).toBe(0);
  });
  it("returns only closed diagnostics for unavailable status, never raw failure text", async () => {
    client.status.mockRejectedValueOnce(new VaultMeshRpcError("native-host-forbidden", "private-path-and-secret"));
    const background = new VaultMeshRpcBackground(client as unknown as VaultMeshRpcClient);
    expect(await background.handle({ kind: VAULTMESH_STATUS_MESSAGE })).toEqual({ kind: VAULTMESH_STATUS_MESSAGE, status: "unavailable", code: "native-host-forbidden" });
    client.status.mockRejectedValueOnce(new VaultMeshRpcError("private-path-and-secret", "private-path-and-secret"));
    expect(await background.handle({ kind: VAULTMESH_STATUS_MESSAGE })).toEqual({ kind: VAULTMESH_STATUS_MESSAGE, status: "unavailable", code: "desktop-unavailable" });
  });
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
