import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("CT-BROWSER-003 generator lifecycle", () => {
  it("expires generated values and delegates copying to the desktop clipboard", () => {
    const source = readFileSync(resolve(process.cwd(), "src/entrypoints/popup/generator-panel.tsx"), "utf8");
    expect(source).toContain("GENERATED_VALUE_LIFETIME_MS = 60_000");
    expect(source).toContain('desktopRpc("browser.generated.copy", { mode: valueMode, value })');
    expect(source).toContain('document.addEventListener("visibilitychange", hide)');
    expect(source).not.toContain("navigator.clipboard.writeText");
  });
});
