import { afterEach, describe, expect, it, vi } from "vitest";
import { AutofillTargets } from "./autofill-targets";

function fixture() {
  document.body.innerHTML = '<form id="first"><input autocomplete="username"><input type="password"></form><form id="second"><input autocomplete="username"><input type="password"></form><input form="first" autocomplete="email">';
  document.querySelectorAll("input").forEach((input) => Object.defineProperty(input, "getClientRects", { value: () => [{ width: 200, height: 30 }] }));
  return document.querySelector("input")!;
}
afterEach(() => { document.body.innerHTML = ""; vi.useRealTimers(); });
describe("CT-AUTOFILL-001 precise local targets", () => {
  it("binds the selected form including external form-associated fields, not adjacent forms", () => {
    const input = fixture(); const registry = new AutofillTargets(); const documentId = crypto.randomUUID();
    const target = registry.capture(input, documentId)!;
    expect(registry.resolve(target, documentId)).toEqual(new Set(document.querySelectorAll('#first input, input[form="first"]')));
    expect(JSON.stringify(target)).not.toContain("username");
    expect(registry.resolve(target, crypto.randomUUID())).toBeNull();
  });
  it("rejects moved controls, changed qualification and cleared references", () => {
    const input = fixture(); const registry = new AutofillTargets(); const id = crypto.randomUUID();
    const target = registry.capture(input, id)!;
    document.querySelector("#second")!.append(input);
    expect(registry.resolve(target, id)).toBeNull();
    const next = registry.capture(input, id)!;
    input.readOnly = true;
    expect(registry.resolve(next, id)).toBeNull();
    input.readOnly = false; registry.clear();
    expect(registry.resolve(next, id)).toBeNull();
  });
  it("expires after one minute and never falls back to a wider scope", () => {
    vi.useFakeTimers(); const input = fixture(); const registry = new AutofillTargets(); const id = crypto.randomUUID();
    const target = registry.capture(input, id)!;
    vi.advanceTimersByTime(60_000);
    expect(registry.resolve(target, id)).toBeNull();
  });
});
