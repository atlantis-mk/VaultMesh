import { webcrypto } from "node:crypto";
import { EditorWindows } from "./editor-windows";
import { VaultMeshRpcBackground } from "../background/vaultmesh-rpc.background";
import { VaultMeshRpcClient } from "./rpc";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import { SESSION_MESSAGE } from "./contracts";
import { sendSessionMessage } from "./runtime";
import { LoginDraft } from "./login-draft";
import type { NativeRpcRequest } from "./native-connection";

jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn(), requestNativePermission: jest.fn() }));
const itemId = "11111111-1111-4111-8111-111111111111";
const cleanupId = "22222222-2222-4222-8222-222222222222";
const confirmationToken = "33333333-3333-4333-8333-333333333333";
const summary = { id: itemId, title: "Synthetic", username: "user", url: null, hasPassword: true,
  hasTotpSecret: false, hasRecoveryCodes: true, autofillOnPageLoad: false, masterPasswordReprompt: false };
const prepared = () => ({ codes: ["synthetic-code", " padded-code "], fileName: "synthetic.txt", sourceFileStatus: "kept",
  cleanup: { id: cleanupId, expiresAt: Date.now() + 300000 } });

function browserWindow() {
  (chrome.windows.create as jest.Mock).mockImplementation((_input, callback) => callback({ id: 77, tabs: [{ id: 88, windowId: 77 }] }));
  (chrome.tabs.update as jest.Mock).mockImplementation((_id, _input, callback) => callback({ id: 88, windowId: 77 }));
  (chrome.windows.update as jest.Mock).mockImplementation((_id, _input, callback) => callback({ id: 77 }));
}
const editorSender = (): chrome.runtime.MessageSender => ({ id: chrome.runtime.id, tab: { id: 88, windowId: 77 } as chrome.tabs.Tab,
  frameId: 0, url: (chrome.tabs.update as jest.Mock).mock.calls.at(-1)[1].url });

describe("CT-BROWSER-002 independent editor identity", () => {
  beforeEach(() => { jest.clearAllMocks(); browserWindow(); });
  it("registers only the created tab and does not grant a copied URL or worker restart", async () => {
    const invalidated = jest.fn();
    const windows = new EditorWindows(invalidated); windows.start();
    await windows.open();
    expect(chrome.windows.create).toHaveBeenCalledWith(expect.objectContaining({ url: "about:blank", type: "popup" }), expect.any(Function));
    const sender = editorSender();
    expect(windows.allows(sender)).toBe(true);
    for (const forged of [{ ...sender, tab: { ...sender.tab, id: 89 } }, { ...sender, frameId: 1 },
      { ...sender, id: "other" }, { ...sender, url: sender.url + "#copy" }, { ...sender, tab: undefined }]) {
      expect(windows.allows(forged as chrome.runtime.MessageSender)).toBe(false);
    }
    expect(new EditorWindows(jest.fn()).allows(sender)).toBe(false);
    (chrome.tabs.onUpdated.addListener as jest.Mock).mock.calls.at(-1)[0](88, { url: "https://synthetic.test" });
    expect(windows.allows(sender)).toBe(false); expect(invalidated).toHaveBeenCalledTimes(1);
  });
  it("revokes registration when the owned tab closes", async () => {
    const windows = new EditorWindows(jest.fn()); windows.start(); await windows.open();
    const sender = editorSender();
    (chrome.tabs.onRemoved.addListener as jest.Mock).mock.calls.at(-1)[0](88);
    expect(windows.allows(sender)).toBe(false);
  });
  it("does not transfer registration across a same-URL reload", async () => {
    const windows = new EditorWindows(jest.fn()); windows.start(); await windows.open();
    const sender = editorSender();
    const committed = (chrome.webNavigation.onCommitted.addListener as jest.Mock).mock.calls.at(-1)[0];
    committed({ tabId: 88, frameId: 0, url: sender.url });
    expect(windows.allows(sender)).toBe(true);
    committed({ tabId: 88, frameId: 0, url: sender.url });
    expect(windows.allows(sender)).toBe(false);
  });
});

describe("CT-RECOVERY-CODES-001 popup → background → two-phase native file RPC", () => {
  let service: VaultMeshBrowserRpcService;
  let bridge: VaultMeshRpcBackground;
  let requests: NativeRpcRequest[];
  let reply: (request: NativeRpcRequest) => Promise<unknown>;
  let sender: chrome.runtime.MessageSender;
  const success = (request: NativeRpcRequest, result: unknown) => ({ kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true, result });
  beforeEach(async () => {
    jest.clearAllMocks(); browserWindow();
    Object.defineProperty(crypto, "subtle", { value: webcrypto.subtle, configurable: true });
    requests = [];
    reply = async (request) => success(request, request.operation === "vault.status" ? { unlocked: true, hasVault: true, itemCount: 1 }
      : request.operation === "events.poll" ? { sequence: 0, events: [] }
      : request.operation === "items.list" ? [summary]
      : request.operation === "confirmation.request" ? { confirmationToken, expiresAt: new Date(Date.now() + 30000).toISOString() }
      : request.operation === "items.recovery-codes.import-file" ? request.input.phase === "prepare" ? prepared() : { sourceFileStatus: "kept" }
      : summary);
    const connection = { start: jest.fn(), onDisconnected: jest.fn(), request: async (request: NativeRpcRequest) => {
      requests.push(JSON.parse(JSON.stringify(request))); return reply(request);
    } };
    bridge = new VaultMeshRpcBackground(new VaultMeshRpcClient(connection as never)); bridge.start();
    await bridge.handle({ kind: SESSION_MESSAGE, action: "editor-open" }, { id: chrome.runtime.id, url: chrome.runtime.getURL("popup/index.html") });
    sender = editorSender();
    jest.mocked(sendSessionMessage).mockImplementation((message) => bridge.handle(message, sender));
    service = new VaultMeshBrowserRpcService(); await service.refresh();
  });
  afterEach(() => service.ngOnDestroy());
  const saveInput = () => { const draft = new LoginDraft(); draft.cipher.name = "Synthetic"; draft.cipher.login.password = "synthetic-password";
    draft.recoveryCodes = prepared().codes.join("\n"); return draft.toInput(); };

  it("requires the exact editor and explicit confirmation independently for both phases", async () => {
    expect(await service.editorContext()).toBe(true);
    const imported = await service.prepareRecoveryFile();
    expect(imported).toMatchObject({ ok: true, value: { codes: prepared().codes, sourceFileStatus: "kept", cleanup: { id: cleanupId } } });
    expect((await service.finishRecoveryFile(cleanupId)).ok).toBe(false);
    expect(requests.filter((request) => request.operation === "items.recovery-codes.import-file")).toHaveLength(1);
    expect((await service.saveLogin(saveInput(), cleanupId)).ok).toBe(true);
    expect(await service.finishRecoveryFile(cleanupId)).toEqual({ ok: true, value: { sourceFileStatus: "kept" } });
    expect((await service.finishRecoveryFile(cleanupId)).ok).toBe(false);
    const files = requests.filter((request) => request.operation === "items.recovery-codes.import-file");
    expect(files.map((request) => request.input.phase)).toEqual(["prepare", "finish"]);
    expect(files.every((request) => request.input.confirmationToken === confirmationToken)).toBe(true);
    expect(files[0].input.userGestureId).not.toBe(files[1].input.userGestureId);
  });
  it("does not allow the toolbar popup to start the native file flow", async () => {
    sender = { id: chrome.runtime.id, url: chrome.runtime.getURL("popup/index.html") };
    expect((await service.prepareRecoveryFile()).ok).toBe(false);
    expect(requests.some((request) => request.operation === "items.recovery-codes.import-file")).toBe(false);
  });
  it("rejects changed recovery codes before saving with a cleanup claim", async () => {
    await service.prepareRecoveryFile();
    const input = saveInput(); input.recoveryCodes = ["edited-code"];
    expect((await service.saveLogin(input, cleanupId)).ok).toBe(false);
    expect(requests.some((request) => request.operation === "items.add")).toBe(false);
    expect((await service.finishRecoveryFile(cleanupId)).ok).toBe(false);
  });
  it("never enables cleanup if the save response is lost", async () => {
    await service.prepareRecoveryFile();
    const previous = reply;
    reply = async (request) => { if (request.operation === "items.add") throw new Error("synthetic-lost-response"); return previous(request); };
    expect(await service.saveLogin(saveInput(), cleanupId)).toEqual({ ok: false, code: "execution-unknown" });
    await service.refresh(); expect((await service.finishRecoveryFile(cleanupId)).ok).toBe(false);
    expect(requests.some((request) => request.input.phase === "finish")).toBe(false);
  });
  it("revokes a discarded cleanup claim without issuing a native delete request", async () => {
    await service.prepareRecoveryFile();
    service.discardRecoveryFile(cleanupId);
    expect((await service.saveLogin(saveInput(), cleanupId)).ok).toBe(false);
    expect((await service.finishRecoveryFile(cleanupId)).ok).toBe(false);
    expect(requests.some((request) => request.input.phase === "finish")).toBe(false);
  });
  it("rejects and clears a native result delivered after the editor closes", async () => {
    let finish!: () => void; const raw = prepared(); const previous = reply;
    reply = async (request) => {
      if (request.operation !== "items.recovery-codes.import-file") return previous(request);
      await new Promise<void>((resolve) => { finish = resolve; }); return success(request, raw);
    };
    const pending = service.prepareRecoveryFile();
    for (let tick = 0; !finish && tick < 50; tick++) await Promise.resolve();
    expect(finish).toBeDefined();
    // Two listeners are installed (editor and capture); invoke the owned-tab removal listener.
    for (const [listener] of (chrome.tabs.onRemoved.addListener as jest.Mock).mock.calls) listener(88);
    finish(); expect((await pending).ok).toBe(false); expect(raw.codes).toEqual([]);
    expect(requests.some((request) => request.input.phase === "finish")).toBe(false);
  });
});
