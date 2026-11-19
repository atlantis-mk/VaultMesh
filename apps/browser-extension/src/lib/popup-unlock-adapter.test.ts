import { describe, expect, it } from "vitest";

import {
  AutoOpenPopupUnlockAdapter,
  ManualLockedPopupUnlockAdapter,
  PopupUnlockFactory,
  VaultMissingPopupUnlockAdapter,
  type PopupUnlockEntryMode,
} from "./popup-unlock-adapter";

describe("PopupUnlockFactory and adapters", () => {
  it("instantiates all three entry mode adapters unconditionally with distinct capabilities", () => {
    const autoOpen = PopupUnlockFactory.createFor("auto-open");
    const manualLocked = PopupUnlockFactory.createFor("manual-locked");
    const vaultMissing = PopupUnlockFactory.createFor("vault-missing");

    expect(autoOpen).toBeInstanceOf(AutoOpenPopupUnlockAdapter);
    expect(autoOpen.mode).toBe("auto-open");
    expect(autoOpen.shouldAutoRequestDesktopUnlock).toBe(true);
    expect(autoOpen.canTriggerDesktopUnlock).toBe(true);
    expect(autoOpen.title).toBe("解锁 VaultMesh 浏览器插件");
    expect(autoOpen.description).toContain("桌面端");
    expect(autoOpen.actionLabel).toBe("解锁 VaultMesh 浏览器插件");

    expect(manualLocked).toBeInstanceOf(ManualLockedPopupUnlockAdapter);
    expect(manualLocked.mode).toBe("manual-locked");
    expect(manualLocked.shouldAutoRequestDesktopUnlock).toBe(false);
    expect(manualLocked.canTriggerDesktopUnlock).toBe(true);
    expect(manualLocked.title).toContain("已锁定");
    expect(manualLocked.description).toContain("不会自动");
    expect(manualLocked.actionLabel).toBe("解锁 VaultMesh 浏览器插件");

    expect(vaultMissing).toBeInstanceOf(VaultMissingPopupUnlockAdapter);
    expect(vaultMissing.mode).toBe("vault-missing");
    expect(vaultMissing.shouldAutoRequestDesktopUnlock).toBe(false);
    expect(vaultMissing.canTriggerDesktopUnlock).toBe(false);
    expect(vaultMissing.title).toContain("VaultMesh");
    expect(vaultMissing.description).toContain("桌面端创建");
    expect(vaultMissing.actionLabel).toBe("");
  });

  it("returns every adapter variant in PopupUnlockFactory.all()", () => {
    const modes: PopupUnlockEntryMode[] = PopupUnlockFactory.all().map((adapter) => adapter.mode);
    expect(modes).toEqual(["auto-open", "manual-locked", "vault-missing"]);
  });

  it.each([
    { hasVault: true, suppressAutoUnlock: false, expectedMode: "auto-open", expectedClass: AutoOpenPopupUnlockAdapter },
    { hasVault: true, suppressAutoUnlock: true, expectedMode: "manual-locked", expectedClass: ManualLockedPopupUnlockAdapter },
    { hasVault: false, suppressAutoUnlock: false, expectedMode: "vault-missing", expectedClass: VaultMissingPopupUnlockAdapter },
    { hasVault: false, suppressAutoUnlock: true, expectedMode: "vault-missing", expectedClass: VaultMissingPopupUnlockAdapter },
  ] as const)(
    "resolves $expectedMode when hasVault=$hasVault and suppressAutoUnlock=$suppressAutoUnlock",
    ({ hasVault, suppressAutoUnlock, expectedMode, expectedClass }) => {
      const adapter = PopupUnlockFactory.resolve({ hasVault, suppressAutoUnlock });
      expect(adapter).toBeInstanceOf(expectedClass);
      expect(adapter.mode).toBe(expectedMode);
    },
  );
});
