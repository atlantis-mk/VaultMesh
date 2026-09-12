import { connectionCode, connectionMessage, nativeConnectionCode } from "./connection-diagnostics";
import { PersistentNativeConnection } from "./native-connection";

describe("CT-BROWSER-001 safe connection diagnostics", () => {
  afterEach(() => { jest.useRealTimers(); Object.defineProperty(chrome.runtime, "lastError", { configurable: true, value: undefined }); });
  it.each([
    ["Specified native messaging host not found.", "native-host-not-found"],
    ["Access to the specified native messaging host is forbidden.", "native-host-forbidden"],
    ["Native host has exited.", "native-host-exited"],
    ["Missing nativeMessaging permission", "native-permission-required"],
  ])("maps %s to a closed code", (raw, code) => expect(nativeConnectionCode(raw)).toBe(code));
  it("never reflects unknown details or inherited property names", () => {
    for (const raw of ["private-path-and-secret", "constructor", "__proto__"]) {
      expect(connectionCode(raw)).toBe("desktop-unavailable");
      expect(connectionMessage(raw)).not.toContain(raw);
    }
  });
  it("classifies a synchronous missing-permission failure without opening a native port", async () => {
    jest.useFakeTimers();
    const connection = new PersistentNativeConnection(() => { throw new Error("Missing nativeMessaging permission /private-path"); });
    await expect(connection.request({ kind: "vaultmesh.rpc", version: 2, requestId: "test", issuedAt: "", expiresAt: "", operation: "vault.status", input: {} })).rejects.toThrow("native-permission-required");
    connection.dispose();
  });
  it("delivers a sanitized disconnect reason to invalidation and the pending request", async () => {
    jest.useFakeTimers();
    let disconnect!: () => void;
    const port = { onMessage: { addListener: jest.fn() }, onDisconnect: { addListener: (fn: () => void) => { disconnect = fn; } }, postMessage: jest.fn(), disconnect: jest.fn() };
    const connection = new PersistentNativeConnection(() => port as never);
    const invalidated = jest.fn(); connection.onDisconnected(invalidated);
    const pending = connection.request({ kind: "vaultmesh.rpc", version: 2, requestId: "test", issuedAt: "", expiresAt: "", operation: "vault.status", input: {} });
    const rejected = expect(pending).rejects.toThrow("native-host-not-found");
    Object.defineProperty(chrome.runtime, "lastError", { configurable: true, value: { message: "Specified native messaging host not found. /private-path" } });
    disconnect();
    await rejected;
    expect(invalidated).toHaveBeenCalledWith("native-host-not-found");
    connection.dispose();
  });
});
