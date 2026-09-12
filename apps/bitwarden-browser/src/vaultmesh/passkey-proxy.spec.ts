import { VaultMeshPasskeyProxy, defaultPasskeyLogin } from "./passkey-proxy";
const loginId = "00000000-0000-4000-8000-000000000025";
const json = JSON.stringify({ extensions: { remoteDesktopClientOverride: { origin: "https://example.test" } } });
const tick = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
describe("CT-PASSKEY-001 independent desktop-owned proxy", () => {
  let listeners: Record<string, (...args: any[]) => any>;
  let api: any;
  let client: any;
  let current: jest.Mock;
  let proxy: VaultMeshPasskeyProxy;
  beforeEach(() => {
    jest.useFakeTimers(); listeners = {};
    const event = (name: string) => ({ addListener: (callback: (...args: any[]) => any) => { listeners[name] = callback; } });
    api = { attach: jest.fn().mockResolvedValue(undefined), detach: jest.fn().mockResolvedValue(undefined),
      onRequestCanceled: event("cancel"), onIsUvpaaRequest: event("uvpaa"), onCreateRequest: event("create"), onGetRequest: event("get"),
      completeIsUvpaaRequest: jest.fn().mockResolvedValue(undefined), completeCreateRequest: jest.fn().mockResolvedValue(undefined), completeGetRequest: jest.fn().mockResolvedValue(undefined) };
    current = jest.fn().mockResolvedValue(true);
    client = { passkey: jest.fn().mockResolvedValue({ responseJson: '{"id":"synthetic-public-response"}' }) };
    proxy = new VaultMeshPasskeyProxy(client, current, api); proxy.start();
  });
  afterEach(async () => { await proxy.detach(); jest.useRealTimers(); });
  it("does not attach while locked or displace an existing proxy", async () => {
    await proxy.sync(false); expect(api.attach).not.toHaveBeenCalled();
    api.attach.mockResolvedValue("another extension is attached"); await proxy.sync(true);
    listeners.get({ requestId: 1, requestDetailsJson: json }); await tick();
    expect(client.passkey).not.toHaveBeenCalled(); expect(api.detach).not.toHaveBeenCalled();
    expect(api.completeGetRequest).toHaveBeenCalledWith(expect.objectContaining({ error: expect.any(Object) }));
  });
  it("forwards only a browser request to native signing and returns a public response", async () => {
    await proxy.sync(true); listeners.get({ requestId: 2, requestDetailsJson: json }); await tick();
    expect(client.passkey).toHaveBeenCalledWith("get", json, undefined);
    expect(api.completeGetRequest).toHaveBeenCalledWith({ requestId: 2, responseJson: '{"id":"synthetic-public-response"}' });
  });
  it("suppresses cancelled requests without retaining arbitrary cancelled IDs", async () => {
    let finish!: (value: any) => void; client.passkey.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    await proxy.sync(true); listeners.get({ requestId: 3, requestDetailsJson: json }); await tick();
    listeners.cancel(3); listeners.cancel(1000); finish({ responseJson: "{}" }); await tick();
    expect(api.completeGetRequest).not.toHaveBeenCalled();
  });
  it("detaches and ignores a late response on lock or disconnect", async () => {
    let finish!: (value: any) => void; client.passkey.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    await proxy.sync(true); listeners.get({ requestId: 4, requestDetailsJson: json }); await tick();
    await proxy.detach(); const raw = { responseJson: "{}" }; finish(raw); await tick();
    expect(api.detach).toHaveBeenCalledTimes(1); expect(api.completeGetRequest).not.toHaveBeenCalled(); expect(raw.responseJson).toBe("");
  });
  it("undoes an in-flight attach if authorization changed before attach completed", async () => {
    let finish!: () => void; api.attach.mockImplementation(() => new Promise<void>((resolve) => { finish = resolve; }));
    const attaching = proxy.sync(true); await proxy.detach(); finish(); await attaching;
    expect(api.detach).toHaveBeenCalledTimes(1);
    listeners.uvpaa({ requestId: 5 }); await tick(); expect(api.completeIsUvpaaRequest).toHaveBeenCalledWith({ requestId: 5, isUvpaa: false });
  });
  it("checks authorization while attached even after the popup closes", async () => {
    await proxy.sync(true); current.mockResolvedValue(false); jest.advanceTimersByTime(3000); await tick();
    expect(api.detach).toHaveBeenCalledTimes(1);
  });
  it("rejects a second simultaneous request and a malformed or oversized request", async () => {
    let finish!: (value: any) => void; client.passkey.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    await proxy.sync(true); listeners.get({ requestId: 6, requestDetailsJson: json }); await tick();
    listeners.get({ requestId: 7, requestDetailsJson: json }); await tick(); expect(client.passkey).toHaveBeenCalledTimes(1);
    expect(api.completeGetRequest).toHaveBeenCalledWith(expect.objectContaining({ requestId: 7, error: expect.any(Object) }));
    finish({ responseJson: "{}" }); await tick();
    listeners.get({ requestId: 8, requestDetailsJson: "x".repeat(128 * 1024 + 1) }); await tick(); expect(client.passkey).toHaveBeenCalledTimes(1);
  });
  it("derives only an exact-origin opaque Login hint", async () => {
    const preferences = { remembered: jest.fn().mockResolvedValue(loginId) };
    expect(await defaultPasskeyLogin(json, preferences)).toBe(loginId);
    expect(preferences.remembered).toHaveBeenCalledWith("https://example.test");
    for (const origin of ["file:///tmp/example", "https://example.test/path", "not-a-url"]) expect(await defaultPasskeyLogin(JSON.stringify({ extensions: { remoteDesktopClientOverride: { origin } } }), preferences)).toBeUndefined();
    expect(preferences.remembered).toHaveBeenCalledTimes(1);
  });
});
