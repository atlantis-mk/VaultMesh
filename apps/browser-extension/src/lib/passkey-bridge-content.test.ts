import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import bridgeScript from "@/entrypoints/passkey-bridge.content";
import { PASSKEY_CHANNEL } from "@/lib/passkey-shim";

describe("passkey-bridge content script permissions policy guard", () => {
  const originalTop = window.top;
  let sendMessage: ReturnType<typeof vi.fn>;
  let invalidators: Array<() => void> = [];
  const invalidateAll = () => {
    for (const cb of invalidators.splice(0)) cb();
  };

  beforeEach(() => {
    invalidators = [];
    sendMessage = vi.fn(async () => ({ status: "fallback" }));
    vi.spyOn(browser.runtime, "sendMessage").mockImplementation(sendMessage as never);
    vi.spyOn(browser.runtime.onMessage, "addListener").mockImplementation(() => undefined);
    Object.defineProperty(window, "top", { value: {}, configurable: true });
    (bridgeScript as unknown as { main(ctx: { abort(reason: string): void; onInvalidated(cb: () => void): void }): void }).main({
      abort: () => undefined,
      onInvalidated: (cb) => { invalidators.push(cb); },
    });
  });

  afterEach(() => {
    invalidateAll();
    Object.defineProperty(window, "top", { value: originalTop, configurable: true });
    delete (document as unknown as { permissionsPolicy?: unknown }).permissionsPolicy;
    vi.restoreAllMocks();
  });

  it("immediately returns fallback and notes permissions-policy-denied in a disallowed cross-origin subframe", async () => {
    Object.defineProperty(document, "permissionsPolicy", {
      value: { allowsFeature: () => false },
      configurable: true,
    });
    const posted: unknown[] = [];
    const postSpy = vi.spyOn(window, "postMessage").mockImplementation((msg) => posted.push(msg));
    const requestId = crypto.randomUUID();

    window.dispatchEvent(new MessageEvent("message", {
      source: window,
      data: {
        channel: PASSKEY_CHANNEL,
        direction: "request",
        id: requestId,
        operation: "get",
        options: { challenge: "AQ" },
      },
    }));
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith({
      kind: "vaultmesh.passkey.note",
      reason: "permissions-policy-denied",
    });
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({ kind: "vaultmesh.passkey.request" }));
    expect(posted).toContainEqual({
      channel: PASSKEY_CHANNEL,
      direction: "response",
      id: requestId,
      result: { status: "fallback" },
    });
    postSpy.mockRestore();
  });

  it("forwards requests when subframe Permissions Policy grants the operation", async () => {
    Object.defineProperty(document, "permissionsPolicy", {
      value: { allowsFeature: (feature: string) => feature === "publickey-credentials-create" },
      configurable: true,
    });
    const requestId = crypto.randomUUID();

    window.dispatchEvent(new MessageEvent("message", {
      source: window,
      data: {
        channel: PASSKEY_CHANNEL,
        direction: "request",
        id: requestId,
        operation: "create",
        options: { rp: { name: "Ex" }, challenge: "AQ" },
      },
    }));
    await Promise.resolve();

    expect(sendMessage).toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.passkey.request",
      id: requestId,
      operation: "create",
    }));
  });

  it("ignores legacy hasLoginCandidates on no-match prompt in the top frame", async () => {
    invalidateAll();
    Object.defineProperty(window, "top", { value: window, configurable: true });
    let listener: ((message: unknown, sender: { id?: string; tab?: unknown }) => unknown) | undefined;
    vi.spyOn(browser.runtime.onMessage, "addListener").mockImplementation((cb) => {
      listener = cb as typeof listener;
    });
    (bridgeScript as unknown as { main(ctx: { abort(reason: string): void; onInvalidated(cb: () => void): void }): void }).main({
      abort: () => undefined,
      onInvalidated: (cb) => { invalidators.push(cb); },
    });

    const token = crypto.randomUUID();
    const res = await listener?.(
      {
        kind: "vaultmesh.passkey-prompt.show",
        prompt: { token, operation: "get", origin: "https://example.test", stage: "no-match", hasLoginCandidates: true },
      },
      { id: browser.runtime.id },
    );
    expect(res).toEqual({ status: "shown" });
    const host = document.documentElement.querySelector("[data-vaultmesh-passkey]");
    expect(host).not.toBeNull();
    // Closed shadow root; cleanup on invalidate removes host cleanly.
    invalidateAll();
    expect(document.documentElement.querySelector("[data-vaultmesh-passkey]")).toBeNull();
  });
});
