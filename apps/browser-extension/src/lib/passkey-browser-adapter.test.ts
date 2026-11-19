import { afterEach, describe, expect, it, vi } from "vitest";

import bridgeScript from "../entrypoints/passkey-bridge.content";
import shimScript from "../entrypoints/passkey-shim.content";
import {
  ChromiumPasskeyAdapter,
  FirefoxPasskeyAdapter,
  PasskeyBrowserFactory,
} from "./passkey-browser-adapter";

function mockFrameDocument(options: {
  top?: boolean;
  permissionsPolicy?: { allowsFeature: (feature: string) => boolean };
  featurePolicy?: { allowsFeature: (feature: string) => boolean };
}): Document {
  const topWindow = {} as Window;
  const currentWindow = options.top === false ? ({ top: topWindow } as unknown as Window) : topWindow;
  if (options.top !== false) {
    Object.defineProperty(topWindow, "top", { value: topWindow, configurable: true });
  }
  return {
    defaultView: currentWindow,
    ...(options.permissionsPolicy ? { permissionsPolicy: options.permissionsPolicy } : {}),
    ...(options.featurePolicy ? { featurePolicy: options.featurePolicy } : {}),
  } as unknown as Document;
}

describe("PasskeyBrowserFactory and adapters", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("compiles both adapters unconditionally and resolves target from env", () => {
    expect(PasskeyBrowserFactory.currentTarget({ browser: "chrome" })).toBe("chromium");
    expect(PasskeyBrowserFactory.currentTarget({ browser: "edge" })).toBe("chromium");
    expect(PasskeyBrowserFactory.currentTarget({ browser: "firefox" })).toBe("firefox");
    expect(PasskeyBrowserFactory.currentTarget({ userAgent: "Mozilla/5.0 (Macintosh; rv:128.0) Gecko/20100101 Firefox/128.0" })).toBe("firefox");
    expect(PasskeyBrowserFactory.currentTarget({ userAgent: "Mozilla/5.0 Chrome/127.0.0.0 Safari/537.36" })).toBe("chromium");

    const chromium = PasskeyBrowserFactory.create({ browser: "chrome" });
    const firefox = PasskeyBrowserFactory.create({ browser: "firefox" });
    expect(chromium).toBeInstanceOf(ChromiumPasskeyAdapter);
    expect(firefox).toBeInstanceOf(FirefoxPasskeyAdapter);
    expect(chromium.target).toBe("chromium");
    expect(chromium.isSupported).toBe(true);
    expect(chromium.disabledReason).toBeNull();
    expect(firefox.target).toBe("firefox");
    expect(firefox.isSupported).toBe(false);
    expect(firefox.disabledReason).toBe("firefox-unsupported");
  });

  it("keeps FirefoxPasskeyAdapter explicitly disabled across frame policy and prompt window", async () => {
    const firefox = PasskeyBrowserFactory.createFor("firefox");
    const openPopup = vi.spyOn(browser.action, "openPopup").mockResolvedValue(undefined);
    const createWindow = vi.spyOn(browser.windows, "create").mockResolvedValue({ id: 1 } as never);
    const allowedDoc = mockFrameDocument({
      top: false,
      permissionsPolicy: { allowsFeature: () => true },
    });

    expect(firefox.allowsFrameWebAuthn(mockFrameDocument({ top: true }), "get")).toBe(false);
    expect(firefox.allowsFrameWebAuthn(allowedDoc, "create")).toBe(false);
    await firefox.openPromptWindow();
    expect(openPopup).not.toHaveBeenCalled();
    expect(createWindow).not.toHaveBeenCalled();
  });

  it("checks WebAuthn Permissions Policy in Chromium subframes and fails closed when unavailable", () => {
    const chromium = PasskeyBrowserFactory.createFor("chromium");

    expect(chromium.allowsFrameWebAuthn(mockFrameDocument({ top: true }), "get")).toBe(true);
    expect(chromium.allowsFrameWebAuthn(mockFrameDocument({ top: true }), "create")).toBe(true);
    expect(chromium.allowsFrameWebAuthn(mockFrameDocument({ top: false }), "get")).toBe(false);
    expect(chromium.allowsFrameWebAuthn(mockFrameDocument({ top: false }), "create")).toBe(false);

    const getOnlyDoc = mockFrameDocument({
      top: false,
      permissionsPolicy: { allowsFeature: (feature) => feature === "publickey-credentials-get" },
    });
    expect(chromium.allowsFrameWebAuthn(getOnlyDoc, "get")).toBe(true);
    expect(chromium.allowsFrameWebAuthn(getOnlyDoc, "create")).toBe(false);
    expect(chromium.allowsFrameWebAuthn(getOnlyDoc, "availability")).toBe(true);

    const featurePolicyDoc = mockFrameDocument({
      top: false,
      featurePolicy: { allowsFeature: (feature) => feature === "publickey-credentials-create" },
    });
    expect(chromium.allowsFrameWebAuthn(featurePolicyDoc, "create")).toBe(true);
    expect(chromium.allowsFrameWebAuthn(featurePolicyDoc, "get")).toBe(false);
  });

  it("opens the extension popup first on Chromium and falls back to a standalone popup window", async () => {
    const chromium = PasskeyBrowserFactory.createFor("chromium");
    const openPopup = vi.spyOn(browser.action, "openPopup").mockResolvedValueOnce(undefined);
    const createWindow = vi.spyOn(browser.windows, "create").mockResolvedValue({ id: 42 } as never);

    await chromium.openPromptWindow();
    expect(openPopup).toHaveBeenCalledTimes(1);
    expect(createWindow).not.toHaveBeenCalled();

    openPopup.mockRejectedValueOnce(new Error("no focused browser window"));
    await chromium.openPromptWindow();
    expect(createWindow).toHaveBeenCalledWith(expect.objectContaining({
      type: "popup",
      focused: true,
    }));
  });

  it("excludes Firefox from passkey-shim and passkey-bridge content scripts", () => {
    expect((shimScript as unknown as { exclude?: string[] }).exclude).toEqual(["firefox"]);
    expect((bridgeScript as unknown as { exclude?: string[] }).exclude).toEqual(["firefox"]);
  });
});
