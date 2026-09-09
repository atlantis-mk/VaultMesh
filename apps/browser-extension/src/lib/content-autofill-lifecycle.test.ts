import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import content from "../entrypoints/vaultmesh.content";
import type { AutofillTarget, DiscoveryFrame } from "./protocol";

let receive: (message: unknown) => unknown;
let dispose: () => void;
beforeEach(() => {
  vi.useFakeTimers();
  document.body.innerHTML = '<input id="username" autocomplete="username">';
  const input = document.querySelector("input")!;
  Object.defineProperty(input, "getClientRects", { value: () => [{ width: 240, height: 32 }] });
  vi.spyOn(browser.runtime, "sendMessage").mockResolvedValue(undefined);
  vi.spyOn(browser.runtime.onMessage, "addListener").mockImplementation((listener) => { receive = listener as (message: unknown) => unknown; });
  (content as unknown as { main(ctx: { onInvalidated(callback: () => void): void; abort(): void }): void }).main({
    onInvalidated: (callback) => { dispose = callback; }, abort: () => {},
  });
});
afterEach(() => {
  dispose?.();
  vi.restoreAllMocks();
  vi.useRealTimers();
  window.history.replaceState(null, "", "/");
  document.body.innerHTML = "";
});

async function discover() {
  return await receive({ kind: "vaultmesh.discover-fields", requestId: crypto.randomUUID() }) as DiscoveryFrame;
}
function assignment(frame: DiscoveryFrame) {
  return { kind: "vaultmesh.apply-assignments", requestId: crypto.randomUUID(), documentId: frame.documentId, frameOrigin: frame.frameOrigin,
    expiresAt: new Date(Date.now() + 10_000).toISOString(), assignments: [{ handle: frame.fields[0]!.handle, value: "test-account", overwrite: true }] };
}

describe("CT-AUTOFILL-001 content assignment lifecycle", () => {
  it("scopes discovery to the originating form and rejects a moved target before assignment", async () => {
    document.body.innerHTML = '<form id="one"><input autocomplete="username"><input type="password"></form><form id="two"><input autocomplete="username"><input type="password"></form>';
    document.querySelectorAll("input").forEach((input) => Object.defineProperty(input, "getClientRects", { value: () => [{ width: 240, height: 32 }] }));
    await vi.advanceTimersByTimeAsync(500);
    const ready = vi.mocked(browser.runtime.sendMessage).mock.calls.map(([message]) => message as { kind?: string; target?: AutofillTarget }).find((message) => message.kind === "vaultmesh.autofill-page-ready" && message.target);
    expect(ready?.target).toBeDefined();
    const scoped = await receive({ kind: "vaultmesh.discover-fields", requestId: crypto.randomUUID(), target: ready!.target }) as DiscoveryFrame;
    expect(scoped.fields).toHaveLength(2);
    document.querySelector("#two")!.append(document.querySelector("#one input")!);
    expect(await receive(assignment(scoped))).toMatchObject({ status: "stale-document", results: [] });
    expect([...document.querySelectorAll("input")].every((input) => input.value === "")).toBe(true);
    const stale = await receive({ kind: "vaultmesh.discover-fields", requestId: crypto.randomUUID(), target: ready!.target }) as DiscoveryFrame;
    expect(stale.fields).toEqual([]);
  });
  it("consumes handles before asynchronous typing so a concurrent replay cannot fill twice", async () => {
    const message = assignment(await discover());
    const first = receive(message);
    const second = await receive(message) as { results: { status: string }[] };
    expect(second.results.map((result) => result.status)).toEqual(["missing"]);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await first).toMatchObject({ status: "completed", results: [{ status: "filled" }] });
  });

  it("does not erase a new discovery when an earlier asynchronous fill completes", async () => {
    const first = receive(assignment(await discover()));
    const next = await discover();
    await vi.advanceTimersByTimeAsync(1_000);
    await first;
    const second = receive(assignment(next));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await second).toMatchObject({ status: "completed", results: [{ status: "filled" }] });
  });

  it("rejects a stale route even before the background navigation notification arrives", async () => {
    const message = assignment(await discover());
    window.history.pushState(null, "", "/different-route");
    expect(await receive(message)).toMatchObject({ status: "stale-document", results: [] });
    expect(document.querySelector("input")!.value).toBe("");
  });

  it("retires assignments while entering BFCache", async () => {
    const message = assignment(await discover());
    window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true }));
    expect(await receive(message)).toMatchObject({ status: "stale-document", results: [] });
  });
});
