import { EmailWatch, startEmailWatchContent } from "./email-watch";
import { VaultMeshRpcClient } from "./rpc";
import { EmailCandidatesSchema } from "./email-otp";
import { sendSessionMessage } from "./runtime";
jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn() }));
describe("CT-EMAIL-002 bounded trusted-click watch", () => {
  const client = { emailWatch: jest.fn(), emailPoll: jest.fn() };
  let watch: EmailWatch;
  let authorized: jest.Mock;
  const sender = { id: chrome.runtime.id, tab: { id: 2 }, frameId: 0, url: "https://example.test/" };
  beforeEach(() => {
    jest.clearAllMocks(); jest.useFakeTimers(); authorized = jest.fn(async () => true);
    client.emailWatch.mockResolvedValue({ watching: true, boostExpiresAt: Math.floor(Date.now() / 1000) + 90 }); client.emailPoll.mockResolvedValue(undefined);
    jest.spyOn(chrome.tabs, "query").mockImplementation((_query: any, cb: any) => cb([{ id: 2, url: sender.url }]));
    jest.spyOn(chrome.tabs, "get").mockImplementation((_id: any, cb: any) => cb({ id: 2, url: sender.url }));
    jest.spyOn(chrome.webNavigation, "getFrame").mockImplementation((_query: any, cb: any) => cb({ url: sender.url }));
    watch = new EmailWatch(client as unknown as VaultMeshRpcClient, authorized);
  });
  afterEach(() => { watch.cancel(); jest.restoreAllMocks(); jest.useRealTimers(); document.body.replaceChildren(); });
  it("polls at three seconds and stops by ninety seconds without starting a new watch", async () => {
    expect(await watch["watch"](sender)).toBe(true);
    expect(client.emailWatch).toHaveBeenCalledWith("https://example.test", true);
    await jest.advanceTimersByTimeAsync(90001);
    expect(client.emailPoll).toHaveBeenCalledTimes(29);
    expect(client.emailWatch).toHaveBeenLastCalledWith("https://example.test", false);
    await jest.advanceTimersByTimeAsync(12000); expect(client.emailPoll).toHaveBeenCalledTimes(29);
  });
  it("fails closed for foreign frames, stale URLs, lock and synthetic page clicks", async () => {
    expect(await watch["watch"]({ ...sender, url: "https://evil.test/" })).toBe(false);
    expect(await watch["watch"]({ ...sender, url: `${sender.url}old` })).toBe(false);
    expect(client.emailWatch).not.toHaveBeenCalled();
    expect(await watch["watch"](sender)).toBe(true); authorized.mockResolvedValue(false);
    await jest.advanceTimersByTimeAsync(3001); expect(client.emailPoll).not.toHaveBeenCalled();
    startEmailWatchContent(); const button = document.createElement("button"); button.textContent = "发送验证码"; document.body.append(button); button.click();
    expect(sendSessionMessage).not.toHaveBeenCalled();
  });
  it("serializes cancellation behind an in-flight native start", async () => {
    let finish!: () => void;
    client.emailWatch.mockImplementation((_origin, active) => active ? new Promise<void>((resolve) => { finish = resolve; }) : Promise.resolve());
    const pending = watch["watch"](sender);
    for (let i = 0; !finish && i < 30; i++) await Promise.resolve(); expect(finish).toBeDefined();
    watch.cancel(); finish(); expect(await pending).toBe(false);
    await jest.advanceTimersByTimeAsync(3001);
    expect(client.emailWatch.mock.calls.map((call) => call[1])).toEqual([true, false]); expect(client.emailPoll).not.toHaveBeenCalled();
  });
  it("rejects a navigation occurring while authorization is pending", async () => {
    watch.start(); let finish!: (value: boolean) => void;
    authorized.mockImplementation(() => new Promise<boolean>((resolve) => { finish = resolve; }));
    const pending = watch["watch"](sender);
    for (let i = 0; !finish && i < 30; i++) await Promise.resolve(); expect(finish).toBeDefined();
    const navigation = jest.mocked(chrome.webNavigation.onCommitted.addListener).mock.calls.at(-1)![0];
    navigation({ tabId: 2, frameId: 0 } as never); finish(true);
    expect(await pending).toBe(false); expect(client.emailWatch).not.toHaveBeenCalled();
  });
  it("accepts the actual desktop response while rejecting mail content or credentials", () => {
    const value = { candidates: [{ id: "00000000-0000-4000-8000-000000000001", code: "A1b2", sourceDomain: "mail.test", receivedAt: 1, expiresAt: 2 }], boostExpiresAt: 0 };
    expect(EmailCandidatesSchema.safeParse(value).success).toBe(true);
    expect(EmailCandidatesSchema.safeParse({ ...value, subject: "forbidden" }).success).toBe(false);
    expect(EmailCandidatesSchema.safeParse({ ...value, candidates: [{ ...value.candidates[0], accountAddress: "forbidden" }] }).success).toBe(false);
  });
});
