import { VaultMeshRpcBackground } from "../background/vaultmesh-rpc.background";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";
import { VaultMeshRpcClient } from "./rpc";
import { sendSessionMessage } from "./runtime";
import type { NativeRpcRequest } from "./native-connection";
import { GeneratedValueSchema } from "./vendor/browser-generated-value";
import { SESSION_MESSAGE } from "./contracts";

jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn(), requestNativePermission: jest.fn() }));
describe("CT-BROWSER-003 generated desktop copy adapter", () => {
  let service: VaultMeshBrowserRpcService; let bridge: VaultMeshRpcBackground;
  let state: SessionState; let requests: NativeRpcRequest[]; let messages: Record<string, any>[];
  let copied: () => Promise<unknown>;
  beforeEach(async () => {
    jest.clearAllMocks(); requests = []; messages = []; copied = async () => ({ clearsAt: Date.now() + 30000 });
    const client = new VaultMeshRpcClient({ start: jest.fn(), dispose: jest.fn(), onDisconnected: jest.fn(), request: async (request: NativeRpcRequest) => {
      requests.push(JSON.parse(JSON.stringify(request)));
      const result = request.operation === "events.poll" ? { sequence: 0, events: [] }
        : request.operation === "vault.status" ? { unlocked: true, hasVault: true, itemCount: 0 }
        : request.operation === "items.list" ? [] : request.operation === "browser.generated.copy" ? await copied() : {};
      return { kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true, result };
    } } as never);
    bridge = new VaultMeshRpcBackground(client); bridge.start();
    jest.mocked(sendSessionMessage).mockImplementation((message) => { messages.push(message as Record<string, any>); return bridge.handle(message); });
    service = new VaultMeshBrowserRpcService(); service.state$.subscribe((next) => state = next); await service.refresh();
  });
  afterEach(() => service.ngOnDestroy());
  it.each(["password", "passphrase", "username", "uuid"] as const)("copies %s through a fresh gesture without returning or persisting the generated value", async (mode) => {
    expect(await service.generatedValue("copy", { mode, value: "synthetic-generated" })).toMatchObject({ ok: true, value: { clearsAt: expect.any(Number) } });
    const copies = requests.filter((request) => request.operation === "browser.generated.copy");
    expect(copies).toHaveLength(1); expect(copies[0].input).toMatchObject({ mode, value: "synthetic-generated", userGestureId: expect.any(String) });
    const message = messages.find((m) => m.action === "generated-value")!;
    expect(message.generated.value).toBe(""); expect(JSON.stringify(state)).not.toContain("synthetic-generated");
    expect(chrome.storage.local.set).not.toHaveBeenCalled();
    expect(await bridge.handle({ ...message, generated: { mode, value: "synthetic-generated" } })).toMatchObject({ ok: false, code: "duplicate-operation" });
  });
  it("cancels the pending generated operation on popup lifecycle invalidation and drops its late result", async () => {
    let resolve!: (value: unknown) => void; copied = () => new Promise((done) => { resolve = done; });
    const pending = service.generatedValue("copy", { mode: "password", value: "synthetic-pending" });
    for (let tick = 0; tick < 30 && !resolve; tick++) await Promise.resolve();
    expect(resolve).toBeDefined(); service.cancelManaged(); resolve({ clearsAt: Date.now() + 30000 });
    expect(await pending).toMatchObject({ ok: false });
    expect(messages.some((m) => m.kind === SESSION_MESSAGE && m.action === "cancel-fill")).toBe(true);
    expect(messages.find((m) => m.action === "generated-value")!.generated.value).toBe("");
  });
  it("rejects unknown and unbounded generated payloads before privileged dispatch", async () => {
    for (const value of ["", "a".repeat(1025), "a\nb"]) expect(GeneratedValueSchema.safeParse({ mode: "password", value }).success).toBe(false);
    expect(await service.generatedValue("copy", { mode: "password", value: "" })).toMatchObject({ ok: false });
    expect(requests.some((request) => request.operation === "browser.generated.copy")).toBe(false);
  });
});
