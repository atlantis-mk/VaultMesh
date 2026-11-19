import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type MessageListener = (message: unknown, sender: Browser.runtime.MessageSender) => Promise<unknown>;

function ensureBrowserStubs() {
  const b = browser as unknown as Record<string, unknown>;
  const noop = () => undefined;
  const spy = (obj: unknown, key: string, impl: () => unknown = noop) => {
    if (!obj || typeof obj !== "object") return;
    const target = obj as Record<string, unknown>;
    if (typeof target[key] === "function") vi.spyOn(target as Record<string, () => unknown>, key).mockImplementation(impl);
    else target[key] = vi.fn(impl);
  };
  spy(browser.runtime.onStartup, "addListener");
  spy(browser.runtime.onInstalled, "addListener");
  spy(browser.alarms, "create", async () => undefined);
  spy(browser.alarms.onAlarm, "addListener");
  spy(browser.idle, "setDetectionInterval");
  spy(browser.idle.onStateChanged, "addListener");
  spy(browser.tabs.onActivated, "addListener");
  spy(browser.tabs.onRemoved, "addListener");
  spy(browser.webNavigation.onCommitted, "addListener");
  spy(browser.webNavigation.onHistoryStateUpdated, "addListener");
  spy(browser.webNavigation.onCompleted, "addListener");
  spy(browser.windows.onRemoved, "addListener");
  spy(browser.notifications.onButtonClicked, "addListener");
  spy(browser.notifications.onClicked, "addListener");
  spy(browser.commands.onCommand, "addListener");
  spy(browser.contextMenus.onClicked, "addListener");
  b.action ??= { openPopup: vi.fn(async () => undefined) };
  spy(b.action, "openPopup", async () => undefined);
}

const origin = "https://example.test";
const pageUrl = `${origin}/login`;
const cardId = "11111111-1111-4111-8111-111111111111";
const loginId = "22222222-2222-4222-8222-222222222222";
const assistId = "a".repeat(32);

const workspaceSnapshot = {
  status: { unlocked: true, hasVault: true, itemCount: 1 },
  items: [{
    id: loginId,
    title: "Example",
    username: "ada@example.test",
    url: origin,
    notes: null,
    hasPassword: true,
    hasTotpSecret: false,
    hasRecoveryCodes: false,
    autofillOnPageLoad: true,
    masterPasswordReprompt: false,
  }],
  cards: [],
  identities: [],
  sshCredentials: [],
  secrets: [],
};

function rpcOk(requestId: string, result: unknown) {
  return { kind: "vaultmesh.rpc-result", version: 2, requestId, ok: true, result };
}

function rpcErr(requestId: string, code: string, message: string) {
  return { kind: "vaultmesh.rpc-result", version: 2, requestId, ok: false, error: { code, message } };
}

function makeRpcRuntimeMessage(operation: string, input: Record<string, unknown> = {}) {
  const requestId = crypto.randomUUID();
  const now = new Date();
  return {
    kind: "vaultmesh.desktop-rpc" as const,
    request: {
      kind: "vaultmesh.rpc" as const,
      version: 2 as const,
      requestId,
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 60_000).toISOString(),
      operation,
      input: { ...input, userGestureId: crypto.randomUUID() },
    },
  };
}

async function flushMicrotasks() {
  for (let index = 0; index < 16; index += 1) await Promise.resolve();
}

describe("background AC-2 RPC session-cleanup transitions", () => {
  let listener: MessageListener;
  let extensionSender: Browser.runtime.MessageSender;
  let pageSender: Browser.runtime.MessageSender;
  let rpcCalls: Array<{ operation: string; requestId: string; input: Record<string, unknown> }>;
  let vaultUnlocked: boolean;
  let nextPinOrPasswordResponse: ((requestId: string) => unknown) | null;
  let backgroundDesktopRpc: typeof import("@/lib/desktop-rpc").backgroundDesktopRpc;
  let docId: string;

  beforeEach(async () => {
    vi.resetModules();
    vi.useFakeTimers();
    ensureBrowserStubs();

    rpcCalls = [];
    vaultUnlocked = false;
    nextPinOrPasswordResponse = null;
    docId = crypto.randomUUID();

    const { persistentNativeConnection } = await import("@/lib/native-connection");
    ({ backgroundDesktopRpc } = await import("@/lib/desktop-rpc"));

    vi.spyOn(persistentNativeConnection, "start").mockImplementation(() => undefined);
    vi.spyOn(persistentNativeConnection, "ensureConnected").mockImplementation(() => undefined);
    vi.spyOn(persistentNativeConnection, "request").mockImplementation(async (request) => {
      rpcCalls.push({ operation: request.operation, requestId: request.requestId, input: request.input });
      if (["vault.change-password", "pin.enable", "pin.disable"].includes(request.operation) && nextPinOrPasswordResponse) {
        return nextPinOrPasswordResponse(request.requestId);
      }
      if (request.operation === "vault.status") {
        return rpcOk(request.requestId, { unlocked: vaultUnlocked, hasVault: true, itemCount: 1, passkeyCancellation: true });
      }
      if (request.operation === "browser.unlock.request") {
        vaultUnlocked = true;
        return rpcOk(request.requestId, { unlocked: true, status: { unlocked: true, hasVault: true, itemCount: 1 } });
      }
      if (request.operation === "vault.workspace") {
        return rpcOk(request.requestId, workspaceSnapshot);
      }
      if (request.operation === "email.otp.poll") {
        return rpcOk(request.requestId, { polled: true, boosted: false });
      }
      if (request.operation === "device.assist.capabilities") {
        return rpcOk(request.requestId, { version: 1 });
      }
      if (request.operation === "device.assist.start") {
        return rpcOk(request.requestId, { id: assistId });
      }
      if (request.operation === "device.assist.poll") {
        return rpcOk(request.requestId, { busy: false, ready: false, failed: false, candidates: [] });
      }
      if (request.operation === "device.assist.cancel") {
        return rpcOk(request.requestId, { cancelled: true });
      }
      if (request.operation === "browser.autofill.execute") {
        return rpcErr(request.requestId, "re-prompt-required", "请输入主密码确认填充。");
      }
      if (request.operation === "passkeys.get") {
        return rpcOk(request.requestId, { responseJson: '{"id":"pk"}' });
      }
      throw new Error(`Unexpected RPC operation in background test: ${request.operation}`);
    });

    vi.spyOn(browser.tabs, "get").mockImplementation(async () => ({ id: 7, active: true, windowId: 1, url: pageUrl } as Browser.tabs.Tab));
    vi.spyOn(browser.webNavigation, "getAllFrames").mockImplementation(async () => [
      { frameId: 0, parentFrameId: -1, url: pageUrl, errorOccurred: false },
    ]);
    const fieldHandle = crypto.randomUUID();
    vi.spyOn(browser.tabs, "sendMessage").mockImplementation(async () => ({
      documentId: docId,
      frameOrigin: origin,
      fields: [{
        handle: fieldHandle,
        control: "input",
        inputType: "tel",
        isEmpty: true,
        autocomplete: ["tel"],
        label: "Phone",
        name: "phone",
        id: "phone",
        placeholder: "",
        context: "unknown",
      }],
    }));

    let capturedListener: MessageListener | undefined;
    vi.spyOn(browser.runtime.onMessage, "addListener").mockImplementation((cb) => {
      capturedListener = cb as MessageListener;
    });

    const bg = (await import("@/entrypoints/background")).default as unknown as { main(): void };
    bg.main();
    await flushMicrotasks();
    listener = capturedListener!;
    expect(listener).toBeTypeOf("function");

    extensionSender = {
      id: browser.runtime.id,
      url: browser.runtime.getURL("/popup.html"),
    } as Browser.runtime.MessageSender;
    pageSender = {
      id: browser.runtime.id,
      origin,
      url: pageUrl,
      frameId: 0,
      tab: { id: 7, active: true, windowId: 1, url: pageUrl } as Browser.tabs.Tab,
    } as Browser.runtime.MessageSender;
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  async function seedUnlockedSession() {
    // 1. Unlock via browser.unlock.request -> sets desktopUnlockedHint = true, warms popupWorkspaceCache, starts email OTP polling.
    const unlockOutcome = await listener({ kind: "vaultmesh.browser-unlock.request", automatic: false }, extensionSender);
    expect(unlockOutcome).toEqual({ status: "unlocked" });
    await flushMicrotasks();

    // 2. Populate pendingPluginFill via re-prompt-required autofill selection.
    const fillOutcome = await listener({
      kind: "vaultmesh.autofill-select",
      selectedItem: { kind: "card", id: cardId, title: "Corp Card" },
    }, pageSender);
    expect(fillOutcome).toEqual({ status: "confirmation-required" });

    // 3. Start an active device assist session.
    const assistOutcome = await listener({
      kind: "vaultmesh.device-assist-start",
      assistKind: "phone",
      target: { targetId: crypto.randomUUID(), documentId: docId },
    }, pageSender);
    expect(assistOutcome).toEqual({ status: "ready", id: assistId });

    // Verify all 5 states are actively populated prior to credential mutation.
    expect(await listener({ kind: "vaultmesh.popup-workspace-cache.get" }, extensionSender)).toMatchObject({
      status: "ready",
      snapshot: workspaceSnapshot,
    });
    expect(await listener({ kind: "vaultmesh.fill-confirmation.get" }, extensionSender)).toMatchObject({
      fillConfirmationToken: expect.any(String),
      selectedItem: { kind: "card", id: cardId, title: "Corp Card" },
      requiresPassword: true,
    });
    expect(await listener({ kind: "vaultmesh.device-assist-action", action: "poll", id: assistId }, pageSender)).toMatchObject({
      status: "ready",
    });

    const pollsBefore = rpcCalls.filter((call) => call.operation === "email.otp.poll").length;
    await vi.advanceTimersByTimeAsync(3_000);
    expect(rpcCalls.filter((call) => call.operation === "email.otp.poll").length).toBeGreaterThan(pollsBefore);

    const statusCallsBefore = rpcCalls.filter((call) => call.operation === "vault.status").length;
    await backgroundDesktopRpc("passkeys.get", {});
    await flushMicrotasks();
    // desktopUnlockedHint is true, so possibleUnlockObserver skips vault.status warm-up check.
    expect(rpcCalls.filter((call) => call.operation === "vault.status")).toHaveLength(statusCallsBefore);
  }

  it.each(["vault.change-password", "pin.enable", "pin.disable"] as const)(
    "clears cache, hint, pendingPluginFill, OTP polling and device assists when %s returns ok: true",
    async (operation) => {
      await seedUnlockedSession();

      vaultUnlocked = false;
      nextPinOrPasswordResponse = (requestId) => rpcOk(requestId, { ok: true });
      const rpcMsg = makeRpcRuntimeMessage(operation, operation === "pin.enable" ? { pin: "123456", failureLimit: 5 } : {});
      const response = await listener(rpcMsg, extensionSender);
      expect(response).toMatchObject({ kind: "vaultmesh.rpc-result", ok: true });
      await flushMicrotasks();

      // 1. popupWorkspaceCache cleared.
      expect(await listener({ kind: "vaultmesh.popup-workspace-cache.get" }, extensionSender)).toEqual({ status: "empty" });
      // 2. pendingPluginFill cleared.
      expect(await listener({ kind: "vaultmesh.fill-confirmation.get" }, extensionSender)).toBeNull();
      // 3. cancelDeviceAssists invoked and active device assist invalidated.
      expect(rpcCalls.filter((call) => call.operation === "device.assist.cancel").map((call) => call.input)).toContainEqual(
        expect.objectContaining({ id: assistId }),
      );
      expect(await listener({ kind: "vaultmesh.device-assist-action", action: "poll", id: assistId }, pageSender)).toEqual({
        status: "request-expired",
      });
      // 4. email OTP polling stopped.
      const pollsAfter = rpcCalls.filter((call) => call.operation === "email.otp.poll").length;
      await vi.advanceTimersByTimeAsync(6_000);
      expect(rpcCalls.filter((call) => call.operation === "email.otp.poll")).toHaveLength(pollsAfter);
      // 5. desktopUnlockedHint reset to false -> possibleUnlockObserver queries vault.status again.
      const statusCallsBefore = rpcCalls.filter((call) => call.operation === "vault.status").length;
      await backgroundDesktopRpc("passkeys.get", {});
      await flushMicrotasks();
      expect(rpcCalls.filter((call) => call.operation === "vault.status").length).toBeGreaterThan(statusCallsBefore);
    },
  );

  it.each(["vault.change-password", "pin.enable", "pin.disable"] as const)(
    "keeps all unlocked session state intact when %s fails or returns non-ok host status/malformed response",
    async (operation) => {
      await seedUnlockedSession();

      for (const failureResponse of [
        (requestId: string) => rpcErr(requestId, "invalid-input", "PIN 更新失败"),
        (requestId: string) => ({ kind: "vaultmesh.host-status", status: "desktop-unavailable", requestId }),
        () => null,
      ]) {
        nextPinOrPasswordResponse = failureResponse;
        const rpcMsg = makeRpcRuntimeMessage(operation);
        await listener(rpcMsg, extensionSender);
        await flushMicrotasks();

        expect(await listener({ kind: "vaultmesh.popup-workspace-cache.get" }, extensionSender)).toMatchObject({
          status: "ready",
          snapshot: workspaceSnapshot,
        });
        expect(await listener({ kind: "vaultmesh.fill-confirmation.get" }, extensionSender)).toMatchObject({
          selectedItem: { kind: "card", id: cardId, title: "Corp Card" },
        });
        expect(rpcCalls.filter((call) => call.operation === "device.assist.cancel")).toHaveLength(0);
        expect(await listener({ kind: "vaultmesh.device-assist-action", action: "poll", id: assistId }, pageSender)).toMatchObject({
          status: "ready",
        });

        const pollsBefore = rpcCalls.filter((call) => call.operation === "email.otp.poll").length;
        await vi.advanceTimersByTimeAsync(3_000);
        expect(rpcCalls.filter((call) => call.operation === "email.otp.poll").length).toBeGreaterThan(pollsBefore);

        const statusCallsBefore = rpcCalls.filter((call) => call.operation === "vault.status").length;
        await backgroundDesktopRpc("passkeys.get", {});
        await flushMicrotasks();
        expect(rpcCalls.filter((call) => call.operation === "vault.status")).toHaveLength(statusCallsBefore);
      }
    },
  );
});
