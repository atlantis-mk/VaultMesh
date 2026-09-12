import { VaultMeshRpcBackground } from "../background/vaultmesh-rpc.background";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";
import { VaultMeshRpcClient } from "./rpc";
import { SESSION_MESSAGE } from "./contracts";
import { LoginDraft } from "./login-draft";
import { clearLoginSecrets } from "./login-contracts";
import { type NativeRpcRequest } from "./native-connection";
import { sendSessionMessage } from "./runtime";
import type { LoginRecoveryCommand } from "./recovery-contracts";

jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn(), requestNativePermission: jest.fn() }));
const id = "00000000-0000-4000-8000-000000000005";
const token = "00000000-0000-4000-8000-000000000006";
const summary = { id, title: "Example", username: "alice", url: null, hasPassword: true,
  hasTotpSecret: true, hasRecoveryCodes: true, autofillOnPageLoad: false, masterPasswordReprompt: true };
const detail = () => ({ id, title: "Example", username: "alice", url: null, notes: "note", folder: "Work",
  favorite: true, additionalUrls: ["https://example.test"], hasTotpSecret: true, hasRecoveryCodes: true,
  autofillOnPageLoad: false, masterPasswordReprompt: true,
  customFields: [{ label: "custom-id", value: "synthetic-custom-value" }] });

describe("CT-ITEM-001 / CT-BROWSER-002 popup → background → existing RPC adapters", () => {
  let service: VaultMeshBrowserRpcService;
  let bridge: VaultMeshRpcBackground;
  let client: VaultMeshRpcClient;
  let state: SessionState;
  let requests: NativeRpcRequest[];
  let disconnected: () => void;
  let reply: (request: NativeRpcRequest) => Promise<unknown>;
  const success = (request: NativeRpcRequest, result: unknown) => ({ kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true, result });

  beforeEach(async () => {
    jest.clearAllMocks();
    requests = [];
    reply = async (request) => success(request,
      request.operation === "events.poll" ? { sequence: 0, events: [] }
      : request.operation === "vault.status" ? { unlocked: true, hasVault: true, itemCount: 1 }
      : request.operation === "vault.lock" ? { unlocked: false, hasVault: true, itemCount: 0 }
      : request.operation === "items.list" ? [summary]
      : request.operation === "items.detail" ? detail()
      : request.operation === "items.delete" ? {}
      : request.operation === "confirmation.request" ? { confirmationToken: token, expiresAt: new Date(Date.now() + 30_000).toISOString() }
      : { ...summary, title: request.input.title });
    const connection = {
      start: jest.fn(), dispose: jest.fn(),
      onDisconnected: (listener: () => void) => { disconnected = listener; },
      request: async (request: NativeRpcRequest) => {
        requests.push(JSON.parse(JSON.stringify(request)));
        return reply(request);
      },
    };
    client = new VaultMeshRpcClient(connection as never);
    bridge = new VaultMeshRpcBackground(client);
    bridge.start();
    jest.mocked(sendSessionMessage).mockImplementation(async (message) => bridge.handle(message));
    service = new VaultMeshBrowserRpcService();
    service.state$.subscribe((value) => { state = value; });
    await service.refresh();
  });
  afterEach(() => service.ngOnDestroy());

  it.each(["username", "password", "totp"] as const)("copies %s through desktop privilege without returning its value to the popup", async (field) => {
    const previousReply = reply;
    reply = async (request) => request.operation === `items.copy-${field}`
      ? success(request, { clearsAt: Date.now() + 30_000 }) : previousReply(request);
    const result = await service.copyLogin(id, field, "synthetic-reprompt");
    expect(result).toMatchObject({ ok: true, value: { clearsAt: expect.any(Number) } });
    const copied = requests.filter((request) => request.operation === `items.copy-${field}`);
    expect(copied).toHaveLength(1);
    expect(copied[0].input).toMatchObject({ id, masterPassword: "synthetic-reprompt", userGestureId: expect.any(String) });
    expect(requests.some((request) => request.operation === "items.detail")).toBe(false);
    expect(JSON.stringify(result)).not.toContain("synthetic-reprompt");
  });

  it("never retries a clipboard write whose outcome is unknown", async () => {
    const previousReply = reply;
    reply = async (request) => {
      if (request.operation === "items.copy-password") throw new Error("connection lost");
      return previousReply(request);
    };
    expect(await service.copyLogin(id, "password", "synthetic-reprompt")).toEqual({ ok: false, code: "execution-unknown" });
    expect(requests.filter((request) => request.operation === "items.copy-password")).toHaveLength(1);
  });

  it("uses an explicit edit read and preserves all fields on update without hydrating unread secrets", async () => {
    const edited = await service.editLogin(id);
    expect(edited.ok).toBe(true);
    if (!edited.ok) throw new Error("edit-failed");
    expect(JSON.stringify(state)).not.toContain("synthetic-custom-value");
    const draft = new LoginDraft(edited.value);
    clearLoginSecrets(edited.value);
    draft.cipher.name = "Renamed";
    const input = draft.toInput();
    draft.clear();
    const saved = await service.saveLogin(input);
    expect(saved.ok).toBe(true);
    const request = requests.find((entry) => entry.operation === "items.update")!;
    expect(request.input).toMatchObject({ id, title: "Renamed", password: null, totpSecret: null,
      recoveryCodes: null, clearTotpSecret: false, clearRecoveryCodes: false, favorite: true,
      additionalUrls: ["https://example.test"], customFields: detail().customFields,
      masterPasswordReprompt: true, autofillOnPageLoad: false });
    const read = requests.find((entry) => entry.operation === "items.detail")!;
    expect(read.input.userGestureId).toMatch(/^[0-9a-f-]{36}$/);
    expect(request.input.userGestureId).not.toBe(read.input.userGestureId);
    expect(input.customFields[0].value).toBe("");
  });

  it("CT-RECOVERY-001 reads recovery summaries without privileged historical values", async () => {
    const previous = reply;
    reply = async (request) => request.operation === "items.trash.list"
      ? success(request, [{ trashId: token, itemId: id, title: "Deleted", username: "user", deletedAt: 1, password: "synthetic-hidden" }])
      : request.operation === "items.history.list"
      ? success(request, [{ revisionId: token, itemId: id, title: "Previous", username: "user", savedAt: 2, password: "synthetic-hidden" }]) : previous(request);
    expect(await service.loginTrash()).toEqual({ ok: true, value: [{ trashId: token, itemId: id, title: "Deleted", username: "user", deletedAt: 1 }] });
    expect(await service.loginHistory(id)).toEqual({ ok: true, value: [{ revisionId: token, itemId: id, title: "Previous", username: "user", savedAt: 2 }] });
    expect(requests.some((request) => request.operation === "items.detail")).toBe(false);
    expect(JSON.stringify(state)).not.toContain("synthetic-hidden");
  });

  it("CT-RECOVERY-CODES-001 uses a fresh master-password request for every view/copy and clears transport values", async () => {
    const previous = reply;
    const nativeResult = { codes: ["synthetic-recovery-1", "synthetic-recovery-2"] };
    reply = async (request) => request.operation === "items.recovery-codes" ? success(request, nativeResult)
      : request.operation === "items.copy-recovery-code" ? success(request, { clearsAt: Date.now() + 30000 }) : previous(request);
    const viewed = await service.recoveryCodes(id, "synthetic-master-password");
    expect(viewed).toEqual({ ok: true, value: { codes: ["synthetic-recovery-1", "synthetic-recovery-2"] } });
    expect(nativeResult.codes).toEqual([]);
    expect(JSON.stringify(state)).not.toContain("synthetic-recovery");
    expect(await service.copyRecoveryCode(id, 1, "synthetic-master-password-again")).toMatchObject({ ok: true, value: { clearsAt: expect.any(Number) } });
    const read = requests.find((request) => request.operation === "items.recovery-codes")!;
    const copy = requests.find((request) => request.operation === "items.copy-recovery-code")!;
    expect(read.input).toMatchObject({ id, masterPassword: "synthetic-master-password" });
    expect(copy.input).toEqual({ id, index: 1, masterPassword: "synthetic-master-password-again", userGestureId: expect.any(String) });
    expect(read.input.userGestureId).not.toBe(copy.input.userGestureId);
    if (viewed.ok) { clearLoginSecrets(viewed.value); expect(viewed.value.codes).toEqual([]); }
  });

  it("CT-RECOVERY-CODES-001 clears a late protected read after popup teardown", async () => {
    let finish!: () => void;
    const previous = reply;
    const raw = { codes: ["synthetic-late-recovery"] };
    reply = async (request) => {
      if (request.operation !== "items.recovery-codes") return previous(request);
      await new Promise<void>((resolve) => { finish = resolve; });
      return success(request, raw);
    };
    const pending = service.recoveryCodes(id, "synthetic-master-password");
    for (let tick = 0; !finish && tick < 30; tick++) await Promise.resolve();
    expect(finish).toBeDefined(); service.ngOnDestroy(); finish();
    expect((await pending).ok).toBe(false);
    expect(raw.codes).toEqual([]);
    expect(JSON.stringify(state)).not.toContain("synthetic-late-recovery");
  });

  it("CT-RECOVERY-CODES-001 rejects missing reauthentication and invalid indices before RPC", async () => {
    const before = requests.length;
    const identity = { kind: SESSION_MESSAGE, revision: state.revision, sessionId: state.sessionId,
      mutationId: token, expiresAt: new Date(Date.now() + 60000).toISOString(), id };
    expect(await bridge.handle({ ...identity, action: "recovery-codes-view" })).toMatchObject({ ok: false, code: "invalid-message" });
    expect(await bridge.handle({ ...identity, action: "recovery-code-copy", masterPassword: "synthetic-master", index: 100 })).toMatchObject({ ok: false, code: "invalid-message" });
    expect(requests).toHaveLength(before);
  });

  it.each<LoginRecoveryCommand>([
    { operation: "items.trash.restore", trashId: token, itemId: id },
    { operation: "items.trash.purge", trashId: token },
    { operation: "items.trash.empty" },
    { operation: "items.history.restore", itemId: id, revisionId: token },
    { operation: "items.history.clear", id },
  ])("CT-RECOVERY-001 binds $operation to its exact target and existing confirmation policy", async (command) => {
    const previous = reply;
    reply = async (request) => request.operation === command.operation ? success(request, command.operation.endsWith("restore") ? summary : {}) : previous(request);
    expect(await service.recoverLogin(command)).toEqual({ ok: true, value: null });
    const writes = requests.filter((request) => request.operation === command.operation);
    expect(writes).toHaveLength(1);
    const confirmation = requests.find((request) => request.operation === "confirmation.request");
    if (command.operation === "items.trash.restore") {
      expect(confirmation).toBeUndefined();
      expect(writes[0].input).toEqual({ trashId: token, userGestureId: expect.any(String) });
    } else {
      expect(confirmation!.input.operation).toBe(command.operation);
      const { operation, ...target } = command;
      expect(writes[0].input).toEqual({ ...target, userGestureId: confirmation!.input.userGestureId, confirmationToken: token });
    }
  });

  it("CT-RECOVERY-001 rejects an expired confirmation before cleanup", async () => {
    const previous = reply;
    reply = async (request) => request.operation === "confirmation.request"
      ? success(request, { confirmationToken: token, expiresAt: new Date(Date.now() - 1).toISOString() }) : previous(request);
    expect(await service.recoverLogin({ operation: "items.trash.empty" })).toEqual({ ok: false, code: "operation-expired" });
    expect(requests.some((request) => request.operation === "items.trash.empty")).toBe(false);
  });

  it("CT-RECOVERY-001 discards pending cleanup when the popup closes during confirmation", async () => {
    let finish!: () => void;
    const previous = reply;
    reply = async (request) => {
      if (request.operation === "confirmation.request") await new Promise<void>((resolve) => { finish = resolve; });
      return previous(request);
    };
    const pending = service.recoverLogin({ operation: "items.history.clear", id });
    for (let tick = 0; !finish && tick < 30; tick++) await Promise.resolve();
    expect(finish).toBeDefined();
    service.ngOnDestroy();
    finish();
    expect((await pending).ok).toBe(false);
    expect(requests.some((request) => request.operation === "items.history.clear")).toBe(false);
  });

  it("CT-RECOVERY-001 rejects historical target mismatch and never retries uncertain restoration", async () => {
    const previous = reply;
    reply = async (request) => request.operation === "items.history.list"
      ? success(request, [{ revisionId: token, itemId: token, title: "Wrong", username: "user", savedAt: 2 }])
      : request.operation === "items.history.restore" ? Promise.reject(new Error("lost-after-restore")) : previous(request);
    expect((await service.loginHistory(id)).ok).toBe(false);
    await service.refresh();
    expect(await service.recoverLogin({ operation: "items.history.restore", itemId: id, revisionId: token })).toEqual({ ok: false, code: "execution-unknown" });
    expect(requests.filter((request) => request.operation === "items.history.restore")).toHaveLength(1);
  });

  it("creates a login once and clears password/custom values from outgoing popup objects", async () => {
    const draft = new LoginDraft();
    draft.cipher.name = "New";
    draft.cipher.login.password = "synthetic-new-password";
    const input = draft.toInput();
    draft.clear();
    expect((await service.saveLogin(input)).ok).toBe(true);
    expect(requests.filter((request) => request.operation === "items.add")).toHaveLength(1);
    expect(requests.find((request) => request.operation === "items.add")!.input.password).toBe("synthetic-new-password");
    expect(input.password).toBe("");
    expect(JSON.stringify(state)).not.toContain("synthetic-new-password");
  });

  it("binds delete to the confirmed item and reuses only that confirmation gesture", async () => {
    expect(await service.deleteLogin(id)).toEqual({ ok: true, value: null });
    const confirm = requests.find((request) => request.operation === "confirmation.request")!;
    const deletion = requests.find((request) => request.operation === "items.delete")!;
    expect(confirm.input.operation).toBe("items.delete");
    expect(deletion.input).toEqual({ id, confirmationToken: token, userGestureId: confirm.input.userGestureId });
    expect(deletion.requestId).not.toBe(confirm.requestId);
  });

  it("does not delete if the token has expired or the connection changed during confirmation", async () => {
    const original = reply;
    reply = async (request) => request.operation === "confirmation.request"
      ? success(request, { confirmationToken: token, expiresAt: new Date(Date.now() - 1).toISOString() }) : original(request);
    expect(await service.deleteLogin(id)).toEqual({ ok: false, code: "operation-expired" });
    expect(requests.some((request) => request.operation === "items.delete")).toBe(false);
    reply = async (request) => {
      if (request.operation !== "confirmation.request") return original(request);
      disconnected();
      return success(request, { confirmationToken: token, expiresAt: new Date(Date.now() + 30_000).toISOString() });
    };
    expect((await service.deleteLogin(id)).ok).toBe(false);
    expect(requests.some((request) => request.operation === "items.delete")).toBe(false);
  });

  it("rejects duplicate popup mutations and expired commands before another native write", async () => {
    const message = { kind: SESSION_MESSAGE, action: "login-delete", id, confirmed: true, revision: 0, sessionId: state.sessionId,
      mutationId: "00000000-0000-4000-8000-000000000007", expiresAt: new Date(Date.now() + 60_000).toISOString() };
    expect(await bridge.handle(message)).toMatchObject({ ok: true });
    expect(await bridge.handle(message)).toMatchObject({ ok: false, code: "duplicate-operation" });
    expect(await bridge.handle({ ...message, expiresAt: new Date(Date.now() - 1).toISOString() })).toMatchObject({ ok: false, code: "operation-expired" });
    expect(requests.filter((request) => request.operation === "items.delete")).toHaveLength(1);
  });

  it("does not automatically retry a write whose response was lost", async () => {
    const original = reply;
    reply = async (request) => {
      if (request.operation === "items.update") throw new Error("lost-after-write");
      return original(request);
    };
    expect(await service.saveLogin(new LoginDraft(detail()).toInput())).toEqual({ ok: false, code: "execution-unknown" });
    await service.refresh();
    expect(requests.filter((request) => request.operation === "items.update")).toHaveLength(1);
  });

  it("does not publish protected detail after a lock or popup teardown", async () => {
    let complete!: () => void;
    const original = reply;
    reply = async (request) => {
      if (request.operation === "items.detail") await new Promise<void>((resolve) => { complete = resolve; });
      return original(request);
    };
    const pending = service.editLogin(id);
    await bridge.handle({ kind: SESSION_MESSAGE, action: "lock" });
    service.ngOnDestroy();
    complete();
    expect((await pending).ok).toBe(false);
    expect(JSON.stringify(state)).not.toContain("synthetic-custom-value");
  });

  it("rejects caller-supplied gestures and delete without explicit confirmation", async () => {
    const before = requests.length;
    expect(await bridge.handle({ kind: SESSION_MESSAGE, action: "login-detail", id, userGestureId: token })).toMatchObject({ ok: false });
    expect(await bridge.handle({ kind: SESSION_MESSAGE, action: "login-delete", id })).toMatchObject({ ok: false });
    expect(requests).toHaveLength(before);
  });

  it("does not accept another item's privileged detail", async () => {
    reply = async (request) => success(request, { ...detail(), id: token });
    await expect(client.loginDetail(id)).rejects.toMatchObject({ code: "invalid-broker-response" });
  });

  it("invalidates an edit when broker events advance even if status is already unlocked again", async () => {
    const original = reply;
    reply = async (request) => request.operation === "events.poll"
      ? success(request, { sequence: 2, events: [{ sequence: 2, type: "vault-locked", occurredAt: new Date().toISOString() }] })
      : original(request);
    expect((await service.editLogin(id)).ok).toBe(false);
    await service.refresh();
    expect(state.status).toBe("ready");
    expect(state.revision).toBe(1);
  });

  it("rejects a stale edit before writing when a broker event was not yet seen by the popup", async () => {
    const original = reply;
    reply = async (request) => request.operation === "events.poll"
      ? success(request, { sequence: 1, events: [{ sequence: 1, type: "vault-changed", occurredAt: new Date().toISOString() }] })
      : original(request);
    expect(await service.saveLogin(new LoginDraft(detail()).toInput())).toEqual({ ok: false, code: "operation-expired" });
    expect(requests.some((request) => request.operation === "items.update")).toBe(false);
  });

  it("does not save an old popup draft after a background-worker restart", async () => {
    bridge = new VaultMeshRpcBackground(client);
    bridge.start();
    expect(await service.saveLogin(new LoginDraft(detail()).toInput())).toEqual({ ok: false, code: "operation-expired" });
    expect(requests.some((request) => request.operation === "items.update")).toBe(false);
  });

  it("serializes writes across popup instances without keeping the rejected draft", async () => {
    let complete!: () => void;
    const original = reply;
    reply = async (request) => {
      if (request.operation === "items.update") await new Promise<void>((resolve) => { complete = resolve; });
      return original(request);
    };
    const message = (mutationId: string) => ({ kind: SESSION_MESSAGE, action: "login-save", mutationId,
      expiresAt: new Date(Date.now() + 60_000).toISOString(), revision: state.revision,
      sessionId: state.sessionId, input: new LoginDraft(detail()).toInput() });
    const first = bridge.handle(message("00000000-0000-4000-8000-000000000011"));
    const second = message("00000000-0000-4000-8000-000000000012");
    expect(await bridge.handle(second)).toMatchObject({ ok: false, code: "operation-busy" });
    expect(second.input.customFields[0].value).toBe("");
    // Let the first call finish its event check and reach the native write.
    for (let index = 0; index < 20 && !complete; index++) await Promise.resolve();
    expect(complete).toBeDefined();
    complete();
    expect(await first).toMatchObject({ ok: true });
    expect(requests.filter((request) => request.operation === "items.update")).toHaveLength(1);
  });
});
