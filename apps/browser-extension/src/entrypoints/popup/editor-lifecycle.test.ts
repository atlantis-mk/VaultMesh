import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("popup editor secret lifecycle", () => {
  for (const file of ["add-item-panel.tsx", "edit-login-panel.tsx"]) {
    it(`${file} clears its draft when hidden or five minutes old`, () => {
      const source = readFileSync(resolve(process.cwd(), "src/entrypoints/popup", file), "utf8");
      expect(source).toContain("5 * 60_000");
      expect(source).toContain('document.addEventListener("visibilitychange", hidden)');
      expect(source).toContain("document.hidden");
      expect(source).toMatch(/setTimeout\((expire|expireEditor), EDIT_SESSION_LIFETIME_MS\)/);
      expect(source).toContain("onCancelRef.current()");
    });
  }

  it("bounds the recovery-code native file-dialog exception to 45 seconds", () => {
    const source = readFileSync(resolve(process.cwd(), "src/entrypoints/popup/edit-login-panel.tsx"), "utf8");
    expect(source).toContain("NATIVE_FILE_DIALOG_GRACE_MS = 45_000");
    expect(source).toContain("nativeFileDialogUntil.current = Date.now() + NATIVE_FILE_DIALOG_GRACE_MS");
    expect(source).toContain("if (document.hidden) expireEditor()");
  });
});
