import { VaultMeshRpcBackground } from "../background/vaultmesh-rpc.background";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";
import { VaultMeshRpcClient } from "./rpc";
import { SESSION_MESSAGE } from "./contracts";
import { ManagedDraft } from "./managed-draft";
import { MANAGED_ITEMS, type ManagedKind } from "./managed-items";
import { type NativeRpcRequest } from "./native-connection";
import { sendSessionMessage } from "./runtime";

jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn(), requestNativePermission: jest.fn() }));
const id = "00000000-0000-4000-8000-000000000025";
const token = "00000000-0000-4000-8000-000000000026";
const success = (request: NativeRpcRequest, result: unknown) => ({ kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true, result });
const fixture = (kind: ManagedKind) => {
  const draft = new ManagedDraft(kind); Object.assign(draft.data, { title: "Synthetic", cardholderName: "Example", cardNumber: "4242424242424242", host: "example.test", username: "user", secret: "synthetic-value" });
  return { ...draft.toInput(), id, maskedNumber: "••••4242", hasSecurityCode: true, hasPin: true, displayName: null,
    hasPassword: true, hasPublicKey: true, hasPrivateKey: true, hasKeyPassphrase: true, keyAlgorithm: null, publicKeyFingerprint: null, isPasskey: false, loginId: null };
};
describe("CT-ITEM-002/003/004/005 / CT-RECOVERY-001 full managed adapter chain", () => {
  let service: VaultMeshBrowserRpcService;
  let bridge: VaultMeshRpcBackground;
  let state: SessionState;
  let requests: NativeRpcRequest[];
  let reply: (request: NativeRpcRequest) => Promise<unknown>;
  beforeEach(async () => {
    jest.clearAllMocks(); requests = [];
    reply = async (request) => {
      if (request.operation === "events.poll") return success(request, { sequence: 0, events: [] });
      if (request.operation === "vault.status") return success(request, { unlocked: true, hasVault: true, itemCount: 1 });
      if (request.operation === "items.list") return success(request, []);
      if (request.operation === "confirmation.request") return success(request, { confirmationToken: token, expiresAt: new Date(Date.now() + 30000).toISOString() });
      const kind = (Object.keys(MANAGED_ITEMS) as ManagedKind[]).find((kind) => request.operation.startsWith(`${MANAGED_ITEMS[kind].prefix}.`));
      if (!kind) throw new Error("Unexpected test RPC");
      if (request.operation.includes("copy-")) return success(request, { clearsAt: Date.now() + 30000 });
      if (request.operation.endsWith("delete") || request.operation.endsWith("clear") || request.operation.endsWith("purge") || request.operation.endsWith("empty")) return success(request, {});
      return success(request, request.operation.endsWith("list") ? [fixture(kind)] : fixture(kind));
    };
    const client = new VaultMeshRpcClient({ start: jest.fn(), dispose: jest.fn(), onDisconnected: jest.fn(),
      request: async (request: NativeRpcRequest) => { requests.push(JSON.parse(JSON.stringify(request))); return reply(request); } } as never);
    bridge = new VaultMeshRpcBackground(client); bridge.start();
    jest.mocked(sendSessionMessage).mockImplementation((message) => bridge.handle(message));
    service = new VaultMeshBrowserRpcService(); service.state$.subscribe((value) => state = value); await service.refresh();
  });
  afterEach(() => service.ngOnDestroy());
  it.each<ManagedKind>(["card", "identity", "ssh", "secret"])("%s reads and updates the current model without leaking or overwriting unread secrets", async (kind) => {
    const edited = await service.managedItem({ kind, verb: "detail", id });
    expect(edited.ok).toBe(true);
    if (!edited.ok || !edited.value || Array.isArray(edited.value)) throw new Error("edit-failed");
    const draft = new ManagedDraft(kind, edited.value); draft.data.title = "Renamed";
    const input = draft.toInput(); draft.clear();
    expect(await service.managedItem({ kind, verb: "save", input })).toMatchObject({ ok: true });
    const writes = requests.filter((request) => request.operation === `${MANAGED_ITEMS[kind].prefix}.update`);
    expect(writes).toHaveLength(1); expect(writes[0].input).toMatchObject({ id, title: "Renamed", userGestureId: expect.any(String) });
    if (kind === "card") expect(writes[0].input.cardNumber).toBeNull();
    if (kind === "ssh") expect(writes[0].input.password).toBeNull();
    if (kind === "secret") expect(writes[0].input.secret).toBeNull();
    expect(JSON.stringify(state)).not.toContain("synthetic-value");
  });
  it.each([["card", "number"], ["card", "security-code"], ["card", "pin"], ["ssh", "password"], ["ssh", "public-key"], ["ssh", "private-key"], ["ssh", "key-passphrase"], ["secret", "value"]] as const)("%s copies %s only through the desktop", async (kind, field) => {
    expect(await service.managedItem({ kind, verb: "copy", id, field, masterPassword: "synthetic-master" })).toMatchObject({ ok: true, value: { clearsAt: expect.any(Number) } });
    const copied = requests.filter((request) => request.operation === `${MANAGED_ITEMS[kind].prefix}.copy-${field}`);
    expect(copied).toHaveLength(1); expect(copied[0].input.masterPassword).toBe("synthetic-master");
    expect(JSON.stringify(state)).not.toContain("synthetic-master");
  });
  it.each<ManagedKind>(["card", "identity", "ssh", "secret"])("%s delete binds the exact command and one-use confirmation", async (kind) => {
    expect(await service.managedItem({ kind, verb: "delete", id, confirmed: true })).toEqual({ ok: true, value: null });
    const confirmation = requests.find((request) => request.operation === "confirmation.request")!;
    const deletion = requests.find((request) => request.operation.endsWith(".delete"))!;
    expect(confirmation.input.operation).toBe(deletion.operation);
    expect(deletion.input).toEqual({ id, userGestureId: confirmation.input.userGestureId, confirmationToken: token });
  });
  it.each(["card", "identity", "ssh"] as const)("%s restore history validates target and command", async (kind) => {
    expect(await service.managedItem({ kind, verb: "restore-history", itemId: id, revisionId: token, confirmed: true })).toMatchObject({ ok: true });
    expect(requests.find((request) => request.operation.endsWith("history.restore"))!.input).toMatchObject({ itemId: id, revisionId: token, confirmationToken: token });
  });
  it("does not replay an uncertain write", async () => {
    const previous = reply; reply = async (request) => request.operation === "cards.delete" ? Promise.reject(new Error("lost")) : previous(request);
    expect(await service.managedItem({ kind: "card", verb: "delete", id, confirmed: true })).toEqual({ ok: false, code: "execution-unknown" });
    expect(requests.filter((request) => request.operation === "cards.delete")).toHaveLength(1);
  });
  it("cancels a pending confirmation on teardown before native deletion", async () => {
    let finish!: () => void; const previous = reply;
    reply = async (request) => { if (request.operation === "confirmation.request") await new Promise<void>((resolve) => { finish = resolve; }); return previous(request); };
    const pending = service.managedItem({ kind: "card", verb: "delete", id, confirmed: true });
    for (let tick = 0; !finish && tick < 30; tick++) await Promise.resolve();
    expect(finish).toBeDefined(); service.ngOnDestroy(); finish();
    expect((await pending).ok).toBe(false); expect(requests.some((request) => request.operation === "cards.delete")).toBe(false);
  });
  it("consumes duplicate identities and rejects stale/background-restarted commands", async () => {
    const message = { kind: SESSION_MESSAGE, action: "managed-item", command: { kind: "card", verb: "delete", id, confirmed: true },
      mutationId: token, expiresAt: new Date(Date.now() + 60000).toISOString(), sessionId: state.sessionId, revision: state.revision };
    expect(await bridge.handle(JSON.parse(JSON.stringify(message)))).toMatchObject({ ok: true });
    expect(await bridge.handle(JSON.parse(JSON.stringify(message)))).toMatchObject({ ok: false, code: "duplicate-operation" });
    expect(await bridge.handle({ ...message, sessionId: id })).toMatchObject({ ok: false, code: "operation-expired" });
  });
  it("does not mutate or copy Passkey material through the ordinary Secret editor", async () => {
    const previous = reply; reply = async (request) => request.operation === "secrets.detail" ? success(request, { ...fixture("secret"), isPasskey: true }) : previous(request);
    expect((await service.managedItem({ kind: "secret", verb: "copy", id, field: "value" })).ok).toBe(false);
    expect(requests.some((request) => request.operation === "secrets.copy-value")).toBe(false);
  });
  it("CT-PASSKEY-001 lists only this Login's Passkeys and deletes through one-use confirmation without reading a key", async () => {
    const previous = reply;
    reply = async (request) => request.operation === "secrets.list" ? success(request, [
      { ...fixture("secret"), isPasskey: true, loginId: token },
      { ...fixture("secret"), id: token, isPasskey: false, loginId: token },
    ]) : previous(request);
    const listed = await service.managePasskeys({ verb: "list", loginId: token });
    expect(listed).toMatchObject({ ok: true, value: [{ id, isPasskey: true, loginId: token }] });
    expect(await service.managePasskeys({ verb: "delete", id, loginId: id, confirmed: true })).toMatchObject({ ok: false });
    expect(requests.some((request) => request.operation === "secrets.delete")).toBe(false);
    expect(await service.managePasskeys({ verb: "delete", id, loginId: token, confirmed: true })).toEqual({ ok: true, value: null });
    expect(requests.filter((request) => request.operation === "secrets.delete")).toHaveLength(1);
    expect(requests.find((request) => request.operation === "secrets.delete")!.input).toMatchObject({ id, confirmationToken: token });
    expect(requests.some((request) => request.operation === "secrets.detail" || request.operation.startsWith("secrets.copy"))).toBe(false);
  });
});
