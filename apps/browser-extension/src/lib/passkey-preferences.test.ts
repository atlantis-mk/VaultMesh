import { beforeEach, describe, expect, it } from "vitest";

import {
  clearPasskeyChoices,
  getSitePasskeyMode,
  rememberedPasskeyChoice,
  rememberPasskeyChoice,
  resolveEffectivePasskeyPreference,
  setSitePasskeyMode,
} from "./passkey-preferences";

const topOrigin = "https://shop.example.test";
const iframeOrigin = "https://auth.partner.test";

describe("passkey preferences & site modes", () => {
  beforeEach(async () => {
    await browser.storage.local.clear();
  });

  it("supports SitePasskeyMode (default | ask | vaultmesh | native), keeps ask distinct from default, and clears per-operation choices when changed", async () => {
    await rememberPasskeyChoice("get", topOrigin, "native");
    await expect(getSitePasskeyMode(topOrigin)).resolves.toBe("default");

    await setSitePasskeyMode(topOrigin, "vaultmesh");
    await expect(getSitePasskeyMode(topOrigin)).resolves.toBe("vaultmesh");
    await expect(rememberedPasskeyChoice("get", topOrigin)).resolves.toBeNull();
    await expect(resolveEffectivePasskeyPreference("get", { origin: topOrigin }, "ask")).resolves.toEqual({
      choice: "vaultmesh",
      reason: "site-mode-vaultmesh",
    });

    await setSitePasskeyMode(topOrigin, "native");
    await expect(resolveEffectivePasskeyPreference("create", { origin: topOrigin })).resolves.toEqual({
      choice: "native",
      reason: "site-mode-native",
    });

    // Explicit "ask" is stored and blocks global default "vaultmesh".
    await setSitePasskeyMode(topOrigin, "ask");
    await expect(getSitePasskeyMode(topOrigin)).resolves.toBe("ask");
    await expect(resolveEffectivePasskeyPreference("get", { origin: topOrigin }, "vaultmesh")).resolves.toEqual({
      choice: "ask",
      reason: "site-mode-ask",
    });

    // Setting back to "default" removes override and follows globalDefault.
    await setSitePasskeyMode(topOrigin, "default");
    await expect(getSitePasskeyMode(topOrigin)).resolves.toBe("default");
    await expect(resolveEffectivePasskeyPreference("get", { origin: topOrigin }, "vaultmesh")).resolves.toEqual({
      choice: "vaultmesh",
      reason: "default-vaultmesh",
    });
    await expect(resolveEffectivePasskeyPreference("get", { origin: topOrigin }, "ask")).resolves.toEqual({
      choice: null,
      reason: null,
    });
  });

  it("uses composite (topOrigin, origin) keys for cross-origin get without leaking across origins or top frames", async () => {
    const crossScope = { origin: iframeOrigin, topOrigin, sameOriginWithAncestors: false };
    const otherTopScope = { origin: iframeOrigin, topOrigin: "https://other-shop.test", sameOriginWithAncestors: false };

    await rememberPasskeyChoice("get", crossScope, "vaultmesh");
    await expect(rememberedPasskeyChoice("get", crossScope)).resolves.toBe("vaultmesh");
    await expect(rememberedPasskeyChoice("get", otherTopScope)).resolves.toBeNull();
    await expect(rememberedPasskeyChoice("get", iframeOrigin)).resolves.toBeNull();

    // Even A -> B -> A (same topOrigin and origin, sameOriginWithAncestors: false) stays isolated from top-level A.
    const nestedSame = { origin: topOrigin, topOrigin, sameOriginWithAncestors: false };
    await rememberPasskeyChoice("get", nestedSame, "native");
    await expect(rememberedPasskeyChoice("get", topOrigin)).resolves.toBeNull();
  });

  it("never auto-remembers or auto-approves create choices across cross-origin frames even with global vaultmesh default", async () => {
    const crossScope = { origin: iframeOrigin, topOrigin, sameOriginWithAncestors: false };
    await rememberPasskeyChoice("create", crossScope, "vaultmesh");
    await expect(rememberedPasskeyChoice("create", crossScope)).resolves.toBeNull();

    await setSitePasskeyMode(crossScope, "vaultmesh");
    await expect(resolveEffectivePasskeyPreference("create", crossScope, "vaultmesh")).resolves.toEqual({
      choice: null,
      reason: null,
    });

    // Top-level ask mode suppresses global vaultmesh default in cross-origin frames too.
    await setSitePasskeyMode(crossScope, "default");
    await setSitePasskeyMode(topOrigin, "ask");
    await expect(resolveEffectivePasskeyPreference("get", crossScope, "vaultmesh")).resolves.toEqual({
      choice: "ask",
      reason: "site-mode-ask",
    });

    // Top-level native mode still suppresses cross-origin frames in that tab.
    await setSitePasskeyMode(topOrigin, "native");
    await expect(resolveEffectivePasskeyPreference("create", crossScope)).resolves.toEqual({
      choice: "native",
      reason: "site-mode-native",
    });
  });

  it("clears both per-operation choices and site modes back to default", async () => {
    await rememberPasskeyChoice("get", topOrigin, "vaultmesh");
    await setSitePasskeyMode(iframeOrigin, "native");
    await clearPasskeyChoices();
    await expect(rememberedPasskeyChoice("get", topOrigin)).resolves.toBeNull();
    await expect(getSitePasskeyMode(iframeOrigin)).resolves.toBe("default");
  });
});
