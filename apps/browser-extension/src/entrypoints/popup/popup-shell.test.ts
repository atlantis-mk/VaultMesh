import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

describe("popup shell", () => {
  it("reserves the final popup dimensions before React mounts", () => {
    const styles = readFileSync(resolve(process.cwd(), "src/assets/tailwind.css"), "utf8");

    expect(styles).toContain("--vaultmesh-popup-width: 22rem;");
    expect(styles).toContain("--vaultmesh-popup-height: 37.5rem;");
    expect(styles).toMatch(/html,\s*body,\s*#root\s*{[^}]*width: var\(--vaultmesh-popup-width\);[^}]*height: var\(--vaultmesh-popup-height\);/s);
  });

  it("resolves the unlock adapter through PopupUnlockFactory and keeps the manual-lock suppression in memory only", () => {
    const app = readFileSync(resolve(process.cwd(), "src/entrypoints/popup/popup-app.tsx"), "utf8");

    expect(app).toContain("PopupUnlockFactory.resolve({ hasVault, suppressAutoUnlock })");
    expect(app).toContain("onManualUnlockRequest={() => setSuppressAutoUnlock(false)}");
    expect(app).toContain("onVaultDetected={setHasVault}");
    expect(app).toMatch(/onLocked=\{\(\) => \{ setSuppressAutoUnlock\(true\);/);
    expect(app).not.toMatch(/(localStorage|sessionStorage|storage\.(local|session))[^\n]*suppressAutoUnlock/);
  });

  it("never cancels the desktop unlock from popup pagehide or visibilitychange", () => {
    const page = readFileSync(resolve(process.cwd(), "src/entrypoints/popup/popup-unlock-page.tsx"), "utf8");

    expect(page).not.toMatch(/pagehide|visibilitychange|beforeunload|authentication\.cancel/);
    expect(page).not.toMatch(/type="password"|<input|biometric\.authentication|pin\.unlock|vault\.unlock/);
  });

  it("owns browser.unlock.request in the background worker through a single in-flight promise", () => {
    const background = readFileSync(resolve(process.cwd(), "src/entrypoints/background.ts"), "utf8");

    expect(background).toContain("inFlightBrowserUnlock");
    expect(background).toContain('backgroundDesktopRpc("browser.unlock.request")');
    expect(background).toMatch(/\.finally\(\(\) => \{\s*inFlightBrowserUnlock = null;/);
    expect(background).toMatch(/vaultmesh\.browser-unlock\.request[\s\S]{0,400}requestBrowserUnlock\(\)/);
    expect(background).toMatch(/vaultmesh\.open-unlock[\s\S]{0,300}return requestBrowserUnlock\(\);/);
  });

  it("handles vaultmesh.open-popup behind trustedPage without standalone window fallback", () => {
    const background = readFileSync(resolve(process.cwd(), "src/entrypoints/background.ts"), "utf8");
    const openPopupBlock = background.match(/if \(parsed\.data\.kind === "vaultmesh\.open-popup"\) \{[\s\S]*?\n    \}/)?.[0] ?? "";

    expect(openPopupBlock).not.toBe("");
    expect(background.indexOf("const page = trustedPage(sender);")).toBeLessThan(background.indexOf('parsed.data.kind === "vaultmesh.open-popup"'));
    expect(openPopupBlock).toContain('PasskeyBrowserFactory.currentTarget() === "firefox"');
    expect(openPopupBlock).toContain("extensionAction?.openPopup");
    expect(openPopupBlock).toContain('"unsupported"');
    expect(openPopupBlock).toContain('"opened"');
    expect(openPopupBlock).toContain('"unavailable"');
    expect(openPopupBlock).not.toContain("windows.create");
  });
});
