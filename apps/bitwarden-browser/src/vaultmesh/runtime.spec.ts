import { sendSessionMessage, requestNativePermission } from "./runtime";
import { SESSION_MESSAGE, VAULTMESH_STATUS_MESSAGE } from "./contracts";
describe("CT-BROWSER-001 callback runtime", () => {
  beforeEach(() => jest.clearAllMocks());
  afterEach(() => { jest.restoreAllMocks(); jest.useRealTimers(); });
  it.each(["pin.status", "biometric.status"])("bounds %s discovery without retrying or accepting late replies", async operation => {
    jest.useFakeTimers();
    let reply!: (value: unknown) => void;
    const send = jest.spyOn(chrome.runtime, "sendMessage").mockImplementation((_message: unknown, callback: any) => { reply = callback; });
    const pending = sendSessionMessage({ kind: SESSION_MESSAGE, action: "security-tool", command: { operation, input: {} } });
    const rejected = expect(pending).rejects.toThrow("connection-timeout");
    jest.advanceTimersByTime(10000); await rejected;
    reply({ ok: true }); expect(send).toHaveBeenCalledTimes(1);
  });
  it.each(["pin.unlock", "biometric.unlock"])("does not apply discovery timeouts to %s", async operation => {
    jest.useFakeTimers();
    let reply!: (value: unknown) => void;
    jest.spyOn(chrome.runtime, "sendMessage").mockImplementation((_message: unknown, callback: any) => { reply = callback; });
    const pending = sendSessionMessage({ kind: SESSION_MESSAGE, action: "security-tool", command: { operation, input: {} } });
    expect(jest.getTimerCount()).toBe(0);
    reply({ ok: false }); await pending;
  });
  it("bounds the login-list stage as well as status without retrying", async () => {
    jest.useFakeTimers();
    let reply!: (value: unknown) => void;
    const send = jest.spyOn(chrome.runtime, "sendMessage").mockImplementation((message: unknown, callback: any) => { reply = callback; });
    const pending = sendSessionMessage({ kind: SESSION_MESSAGE, action: "logins" });
    const rejected = expect(pending).rejects.toThrow("login-list-timeout");
    jest.advanceTimersByTime(10_000); await rejected;
    reply({ kind: SESSION_MESSAGE, ok: true, result: [] });
    expect(send).toHaveBeenCalledTimes(1);
    expect(jest.getTimerCount()).toBe(0);
  });
  it("does not apply initialization timeouts to mutations", async () => {
    jest.useFakeTimers();
    let reply!: (value: unknown) => void;
    jest.spyOn(chrome.runtime, "sendMessage").mockImplementation((message: unknown, callback: any) => { reply = callback; });
    const pending = sendSessionMessage({ kind: SESSION_MESSAGE, action: "login-save" });
    expect(jest.getTimerCount()).toBe(0);
    jest.advanceTimersByTime(10_000);
    reply({ ok: false, code: "execution-unknown" });
    await expect(pending).resolves.toEqual({ ok: false, code: "execution-unknown" });
  });
  it("bounds a missing status callback and ignores late replies", async () => {
    jest.useFakeTimers();
    let reply!: (value: unknown) => void;
    jest.spyOn(chrome.runtime, "sendMessage").mockImplementation((message: unknown, callback: any) => { reply = callback; });
    const pending = sendSessionMessage({ kind: VAULTMESH_STATUS_MESSAGE });
    const rejected = expect(pending).rejects.toThrow("connection-timeout");
    jest.advanceTimersByTime(10_000);
    await rejected;
    reply({ status: "ready" });
    expect(jest.getTimerCount()).toBe(0);
  });
  it("reports a missing background response without exposing runtime details", async () => {
    jest.spyOn(chrome.runtime, "sendMessage").mockImplementation((message: unknown, callback: any) => callback(undefined));
    await expect(sendSessionMessage({ kind: VAULTMESH_STATUS_MESSAGE })).rejects.toThrow("background-unavailable");
  });
  it("bounds a missing permission callback", async () => {
    jest.useFakeTimers();
    const original = chrome.permissions.request;
    chrome.permissions.request = jest.fn();
    const pending = requestNativePermission();
    jest.advanceTimersByTime(30_000);
    await expect(pending).resolves.toBe(false);
    chrome.permissions.request = original;
  });
  it("works with the Chromium callback transport", async () => {
    jest.spyOn(chrome.runtime, "sendMessage").mockImplementation((message: unknown, callback: any) => { callback({ received: true }); });
    await expect(sendSessionMessage({ kind: "test" })).resolves.toEqual({ received: true });
  });
  it("rejects runtime errors instead of treating an absent response as success", async () => {
    jest.spyOn(chrome.runtime, "sendMessage").mockImplementation((message: unknown, callback: any) => {
      Object.defineProperty(chrome.runtime, "lastError", { configurable: true, value: { message: "native-host-detail" } });
      callback(undefined);
      Object.defineProperty(chrome.runtime, "lastError", { configurable: true, value: undefined });
    });
    await expect(sendSessionMessage({})).rejects.toThrow("desktop-unavailable");
  });
  it("requests permission synchronously in the click stack", async () => {
    const original = chrome.permissions.request;
    const request = jest.fn((permissions: any, callback: any) => callback(false));
    chrome.permissions.request = request;
    const pending = requestNativePermission();
    expect(request).toHaveBeenCalledWith({ permissions: ["nativeMessaging"] }, expect.any(Function));
    await expect(pending).resolves.toBe(false);
    chrome.permissions.request = original;
  });
});
