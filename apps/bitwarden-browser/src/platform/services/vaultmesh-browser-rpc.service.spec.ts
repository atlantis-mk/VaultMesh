import { VaultMeshBrowserRpcService, SessionState } from "./vaultmesh-browser-rpc.service";
import { sendSessionMessage, requestNativePermission } from "../../vaultmesh/runtime";
import { SESSION_MESSAGE, SESSION_INVALIDATED, VAULTMESH_STATUS_MESSAGE } from "../../vaultmesh/contracts";
jest.mock("../../vaultmesh/runtime", () => ({ sendSessionMessage: jest.fn(), requestNativePermission: jest.fn() }));

const status = (unlocked: boolean) => ({ kind: VAULTMESH_STATUS_MESSAGE, status: unlocked ? "ready" : "locked", vault: { unlocked, hasVault: true, itemCount: 1 } });
const summary = { id: "00000000-0000-4000-8000-000000000005", title: "Example", username: "alice", url: null, hasPassword: true, hasTotpSecret: false, hasRecoveryCodes: false, autofillOnPageLoad: true, masterPasswordReprompt: false };
const ok = (result: unknown) => ({ kind: SESSION_MESSAGE, ok: true, result });

describe("CT-BROWSER-001 remote session lifecycle", () => {
  let service: VaultMeshBrowserRpcService;
  let state: SessionState;
  const send = jest.mocked(sendSessionMessage);
  beforeEach(() => {
    jest.clearAllMocks();
    service = new VaultMeshBrowserRpcService();
    service.state$.subscribe((value) => state = value);
  });
  afterEach(() => service.ngOnDestroy());
  it("reuses visible summaries only after unchanged fresh status; manual refresh still reads", async () => {
    const same = { ...status(true), sessionId: summary.id, revision: 1 };
    send.mockResolvedValueOnce(same).mockResolvedValueOnce(ok([summary]));
    await service.refresh(); const rows = state.logins;
    send.mockResolvedValueOnce(same);
    await service.refresh(false, false);
    expect(send).toHaveBeenCalledTimes(3); expect(state.logins).toBe(rows);
    send.mockResolvedValueOnce(same).mockResolvedValueOnce(ok([summary]));
    await service.refresh(); expect(send).toHaveBeenCalledTimes(5);
  });
  it.each(["revision", "sessionId", "itemCount", "legacy"])("rereads summaries when %s changes", async field => {
    const same = { ...status(true), sessionId: summary.id, revision: 1 };
    send.mockResolvedValueOnce(same).mockResolvedValueOnce(ok([summary])); await service.refresh();
    const changed = field === "revision" ? { ...same, revision: 2 } : field === "sessionId" ? { ...same, sessionId: "00000000-0000-4000-8000-000000000006" }
      : field === "itemCount" ? { ...same, vault: { ...same.vault, itemCount: 2 } } : status(true);
    send.mockResolvedValueOnce(changed).mockResolvedValueOnce(ok([]));
    await service.refresh(false, false); expect(send).toHaveBeenCalledTimes(4); expect(state.logins).toEqual([]);
  });
  it("does not reuse summaries after a locked poll or teardown", async () => {
    const same = { ...status(true), sessionId: summary.id, revision: 1 };
    send.mockResolvedValueOnce(same).mockResolvedValueOnce(ok([summary])); await service.refresh();
    send.mockResolvedValueOnce(status(false)); await service.refresh(false, false); expect(state.logins).toEqual([]);
    send.mockResolvedValueOnce(same).mockResolvedValueOnce(ok([summary])); await service.refresh(false, false);
    service.ngOnDestroy(); expect(state.logins).toEqual([]);
    send.mockResolvedValueOnce(same).mockResolvedValueOnce(ok([summary])); await service.refresh(false, false);
    expect(send).toHaveBeenCalledTimes(7);
  });
  it("reads both unlock methods concurrently with one busy lifecycle and no authentication", async () => {
    send.mockResolvedValueOnce(status(false)); await service.refresh();
    const replies: ((value: unknown) => void)[] = [];
    send.mockImplementation(() => new Promise(resolve => replies.push(resolve)));
    const pending = service.readUnlockMethods();
    expect(replies).toHaveLength(2); expect(state.busy).toBe(true);
    await service.unlock("synthetic-password"); expect(replies).toHaveLength(2);
    replies[0](ok({ enabled: true, locked: false, remainingAttempts: 5, failedAttempts: 0, failureLimit: 5 }));
    await Promise.resolve(); expect(state.busy).toBe(true);
    replies[1](ok({ available: false, enabled: false, kind: null }));
    expect((await pending).every(result => result.ok)).toBe(true); expect(state.busy).toBe(false);
  });
  it("discards both unlock status replies after authorization invalidation", async () => {
    send.mockResolvedValueOnce(status(false)); await service.refresh();
    const replies: ((value: unknown) => void)[] = [];
    send.mockImplementation(() => new Promise(resolve => replies.push(resolve)));
    const pending = service.readUnlockMethods();
    service["invalidate"]({ kind: SESSION_INVALIDATED }, { id: chrome.runtime.id });
    for (const reply of replies) reply(ok({}));
    expect((await pending).every(result => !result.ok)).toBe(true);
    expect(state).toMatchObject({ status: "unavailable", vault: null, logins: [], busy: false });
  });
  it("coalesces repeated refresh clicks and polling into one initialization", async () => {
    let reply!: (value: unknown) => void;
    send.mockImplementationOnce(() => new Promise(resolve => { reply = resolve; }));
    const initial = service.refresh();
    const repeated = Array.from({ length: 20 }, () => service.refresh());
    await service.connect();
    expect(send).toHaveBeenCalledTimes(1);
    expect(requestNativePermission).not.toHaveBeenCalled();
    for (const pending of repeated) expect(pending).toBe(initial);
    reply(status(false));
    await Promise.all([initial, ...repeated]);
    expect(state.status).toBe("locked");
    send.mockResolvedValueOnce(status(false));
    await service.refresh();
    expect(send).toHaveBeenCalledTimes(2);
  });
  it("distinguishes successful status from a slow login list and clears a timed-out read", async () => {
    let rejectList!: (error: Error) => void;
    send.mockResolvedValueOnce(status(true)).mockImplementationOnce(() => new Promise((_, reject) => { rejectList = reject; }));
    const pending = service.refresh();
    await Promise.resolve(); await Promise.resolve();
    expect(state).toMatchObject({ status: "loading", loadingStage: "logins" });
    rejectList(new Error("login-list-timeout")); await pending;
    expect(state).toMatchObject({ status: "unavailable", logins: [], vault: null });
    expect(state.error).toContain("login-list-timeout");
  });
  it("shows connecting immediately, rejects duplicate clicks and suppresses polling during permission", async () => {
    let grant!: (value: boolean) => void;
    jest.mocked(requestNativePermission).mockImplementationOnce(() => new Promise(resolve => { grant = resolve; }));
    const pending = service.connect();
    expect(state).toMatchObject({ status: "loading", busy: true, error: null });
    await service.connect(); await service.refresh();
    expect(requestNativePermission).toHaveBeenCalledTimes(1);
    expect(send).not.toHaveBeenCalled();
    send.mockResolvedValueOnce({ kind: VAULTMESH_STATUS_MESSAGE, status: "unavailable", code: "native-host-forbidden" });
    grant(true); await pending;
    expect(state.status).toBe("unavailable");
    expect(state.error).toContain("native-host-forbidden");
  });
  it("keeps a visible reason when disconnect invalidates an in-flight status reply", async () => {
    let reply!: (value: unknown) => void;
    send.mockImplementationOnce(() => new Promise(resolve => { reply = resolve; }));
    service.start();
    const listener = (chrome.runtime.onMessage.addListener as jest.Mock).mock.calls.at(-1)[0];
    listener({ kind: SESSION_INVALIDATED, code: "native-host-not-found" }, { id: chrome.runtime.id });
    reply(status(true));
    await Promise.resolve(); await Promise.resolve();
    expect(state.status).toBe("unavailable");
    expect(state.error).toContain("native-host-not-found");
    expect(state.logins).toEqual([]);
  });
  it("CT-AUTOFILL-001 cancels a pending fill on teardown and discards its late response", async () => {
    send.mockResolvedValueOnce(status(true)).mockResolvedValueOnce(ok([summary]));
    await service.refresh();
    let complete!: (value: unknown) => void;
    send.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
    const filling = service.fillLogin(summary.id, "synthetic-reprompt");
    send.mockResolvedValueOnce(ok(null));
    service.ngOnDestroy();
    expect(send).toHaveBeenLastCalledWith({ kind: SESSION_MESSAGE, action: "cancel-fill" });
    complete(ok({ filled: 1, auditRecorded: true }));
    expect(await filling).toEqual({ ok: false, code: "execution-unknown" });
    const message = send.mock.calls.find(([message]) => (message as { action?: string }).action === "login-fill")![0];
    expect(message).toMatchObject({ masterPassword: "" });
  });
  it("reads actual login summaries then clears them on a locked refresh", async () => {
    send.mockResolvedValueOnce(status(true)).mockResolvedValueOnce(ok([summary]));
    await service.refresh();
    expect(state.logins).toEqual([summary]);
    send.mockResolvedValueOnce(status(false));
    await service.refresh();
    expect(state.status).toBe("locked");
    expect(state.logins).toEqual([]);
  });
  it("drops a late login response after the popup is destroyed", async () => {
    let complete!: (value: unknown) => void;
    send.mockResolvedValueOnce(status(true)).mockImplementationOnce(() => new Promise((resolve) => complete = resolve));
    const pending = service.refresh();
    await Promise.resolve(); await Promise.resolve();
    service.ngOnDestroy();
    complete(ok([summary]));
    await pending;
    expect(state.logins).toEqual([]);
    expect(state.status).toBe("unavailable");
  });
  it("prevents an older successful refresh from overwriting a newer locked result", async () => {
    let complete!: (value: unknown) => void;
    send.mockImplementationOnce(() => new Promise((resolve) => complete = resolve));
    const old = service.refresh();
    // An authorization invalidation, not another click, supersedes an in-flight read.
    service["invalidate"]({ kind: SESSION_INVALIDATED }, { id: chrome.runtime.id });
    send.mockResolvedValueOnce(status(false));
    await service.refresh();
    complete(status(true));
    await old;
    expect(state.status).toBe("locked");
    expect(send).toHaveBeenCalledTimes(2);
  });
  it("handles an unlock-required status without vault metadata", async () => {
    send.mockResolvedValueOnce({ kind: VAULTMESH_STATUS_MESSAGE, status: "locked" });
    await service.refresh();
    expect(state.status).toBe("locked");
    expect(state.logins).toEqual([]);
  });
  it("does not call the broker when optional permission is denied", async () => {
    jest.mocked(requestNativePermission).mockResolvedValueOnce(false);
    await service.connect();
    expect(send).not.toHaveBeenCalled();
    expect(state.error).not.toBeNull();
  });
  it("does not retain the password in service state or outgoing message after completion", async () => {
    send.mockResolvedValueOnce(ok(null)).mockResolvedValueOnce(status(false));
    await service.unlock("test-only-password");
    expect(send.mock.calls[0][0]).toEqual({ kind: SESSION_MESSAGE, action: "unlock", masterPassword: "" });
    expect(JSON.stringify(state)).not.toContain("test-only-password");
  });
  it("does not resume a closed session after a delayed permission grant", async () => {
    let complete!: (value: boolean) => void;
    jest.mocked(requestNativePermission).mockImplementationOnce(() => new Promise((resolve) => complete = resolve));
    const pending = service.connect();
    service.ngOnDestroy();
    complete(true);
    await pending;
    expect(send).not.toHaveBeenCalled();
    expect(state.status).toBe("unavailable");
    expect(state.logins).toEqual([]);
  });
  it("clears immediately on background disconnect while a popup is open", async () => {
    send.mockResolvedValueOnce(status(true)).mockResolvedValueOnce(ok([summary]));
    service.start();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(state.logins).toHaveLength(1);
    const listener = (chrome.runtime.onMessage.addListener as jest.Mock).mock.calls.at(-1)[0];
    listener({ kind: SESSION_INVALIDATED }, { id: chrome.runtime.id });
    expect(state.logins).toEqual([]);
    expect(state.status).toBe("unavailable");
  });
  it("does not send a second unlock while an attempt is pending", async () => {
    let complete!: (value: unknown) => void;
    send.mockImplementationOnce(() => new Promise((resolve) => complete = resolve));
    const pending = service.unlock("test-only-password");
    await service.unlock("test-only-password-again");
    expect(send).toHaveBeenCalledTimes(1);
    expect(state.busy).toBe(true);
    send.mockResolvedValueOnce(status(false));
    complete(ok(null));
    await pending;
    expect(state.busy).toBe(false);
  });
  it("keeps the locked vault retryable after a rejected password", async () => {
    send.mockResolvedValueOnce(status(false));
    await service.refresh();
    send.mockResolvedValueOnce({ kind: SESSION_MESSAGE, ok: false, code: "operation-failed" });
    await service.unlock("test-only-wrong-password");
    expect(state.status).toBe("locked");
    expect(state.vault?.hasVault).toBe(true);
    expect(state.busy).toBe(false);
    expect(state.error).not.toBeNull();
    expect(state.logins).toEqual([]);
    send.mockResolvedValueOnce(ok(null)).mockResolvedValueOnce(status(true)).mockResolvedValueOnce(ok([summary]));
    await service.unlock("test-only-correct-password");
    expect(state.status).toBe("ready");
    expect(state.logins).toEqual([summary]);
  });
  it("does not restart an old polling loop after page restoration", async () => {
    jest.useFakeTimers();
    try {
      let complete!: (value: unknown) => void;
      send.mockImplementationOnce(() => new Promise((resolve) => complete = resolve));
      service.start();
      service.ngOnDestroy();
      send.mockResolvedValue(status(false));
      service.start();
      await Promise.resolve(); await Promise.resolve();
      complete(status(true));
      await Promise.resolve(); await Promise.resolve();
      expect(jest.getTimerCount()).toBe(1);
      expect(state.status).toBe("locked");
    } finally {
      service.ngOnDestroy();
      jest.useRealTimers();
    }
  });
});
