import { afterEach, describe, expect, it, vi } from "vitest";
import { ShadowHostTracker } from "./shadow-host-tracker";

afterEach(() => { document.body.innerHTML = ""; vi.useRealTimers(); });
describe("CT-AUTOFILL-003 custom element lifecycle", () => {
  it("waits for late definition, then independently waits for hydration", async () => {
    vi.useFakeTimers(); const onRoot = vi.fn(); const tracker = new ShadowHostTracker(onRoot);
    const tag = `late-${crypto.randomUUID()}`; const host = document.createElement(tag); document.body.append(host); tracker.watch(host);
    await vi.advanceTimersByTimeAsync(45_000);
    customElements.define(tag, class extends HTMLElement {});
    await vi.advanceTimersByTimeAsync(20_000);
    const root = host.attachShadow({ mode: "open" });
    await vi.advanceTimersByTimeAsync(2_000);
    expect(onRoot).toHaveBeenCalledExactlyOnceWith(root); tracker.reset();
  });
  it("rotates batches so early unhydrated hosts do not starve later controls", async () => {
    vi.useFakeTimers(); const onRoot = vi.fn(); const tracker = new ShadowHostTracker(onRoot);
    for (let i = 0; i < 128; i++) { const host = document.createElement("pending-control"); document.body.append(host); tracker.watch(host); }
    const host = document.createElement("login-control"); document.body.append(host); tracker.watch(host);
    const root = host.attachShadow({ mode: "open" });
    await vi.advanceTimersByTimeAsync(2_000);
    expect(onRoot).toHaveBeenCalledExactlyOnceWith(root); tracker.reset();
  });
  it("does not restart expired hosts on rescan and clears all timers on reset", async () => {
    vi.useFakeTimers(); const onRoot = vi.fn(); const tracker = new ShadowHostTracker(onRoot);
    const host = document.createElement("never-defined"); document.body.append(host); tracker.watch(host);
    await vi.advanceTimersByTimeAsync(63_000); tracker.watch(host); host.attachShadow({ mode: "open" });
    await vi.advanceTimersByTimeAsync(2_000); expect(onRoot).not.toHaveBeenCalled();
    tracker.reset(); tracker.watch(host); tracker.reset();
    expect(vi.getTimerCount()).toBe(0);
  });
});
