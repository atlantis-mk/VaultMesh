import { sendSessionMessage, requestNativePermission } from "./runtime";
describe("CT-BROWSER-001 callback runtime", () => {
  afterEach(() => jest.restoreAllMocks());
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
