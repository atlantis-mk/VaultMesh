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
