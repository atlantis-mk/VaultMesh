import { act, createElement, StrictMode, useState, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const getDesktopStatus = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-rpc", () => ({ getDesktopStatus }));

import { PopupUnlockFactory } from "@/lib/popup-unlock-adapter";
import { PopupUnlockPage } from "./popup-unlock-page";

vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });

let container: HTMLDivElement;
let root: Root;
const onUnlocked = vi.fn();
let sendMessage: ReturnType<typeof vi.spyOn>;

function unlockButton() {
  return Array.from(container.querySelectorAll("button")).find((button) =>
    button.textContent?.includes("解锁 VaultMesh 浏览器插件") || button.textContent?.includes("正在打开桌面解锁窗口"),
  );
}

async function renderPage(
  adapter = PopupUnlockFactory.createFor("auto-open"),
  options: {
    strict?: boolean;
    onManualUnlockRequest?: () => void;
    onVaultDetected?: (hasVault: boolean) => void;
    notice?: (busy: boolean) => ReactNode;
  } = {},
) {
  await act(async () => {
    const element = createElement(PopupUnlockPage, {
      adapter,
      onUnlocked,
      onManualUnlockRequest: options.onManualUnlockRequest,
      onVaultDetected: options.onVaultDetected,
      notice: options.notice,
    });
    root.render(options.strict ? createElement(StrictMode, null, element) : element);
  });
}

describe("CT-SEC-002/CT-BROWSER-001 streamlined popup unlock page", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    onUnlocked.mockReset().mockResolvedValue(true);
    getDesktopStatus.mockReset().mockResolvedValue({ unlocked: false, hasVault: true, itemCount: 0 });
    sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(
      () => new Promise(() => undefined) as never,
    );
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    sendMessage.mockRestore();
    vi.useRealTimers();
  });

  it("removes local PIN/password/Touch ID forms and auto-requests desktop unlock once even in StrictMode", async () => {
    let seenBusy: boolean | null = null;
    await renderPage(PopupUnlockFactory.createFor("auto-open"), {
      strict: true,
      notice: (busy) => {
        seenBusy = busy;
        return createElement("div", { "data-testid": "passkey-notice" }, busy ? "busy" : "idle");
      },
    });

    expect(container.querySelector('input[type="password"]')).toBeNull();
    expect(container.querySelector('[aria-label="6 位插件 PIN"]')).toBeNull();
    expect(container.textContent).not.toContain("改用主密码");
    expect(container.textContent).not.toContain("改用 PIN");
    expect(container.textContent).not.toContain("使用 Touch ID");

    expect(container.textContent).toContain("解锁 VaultMesh 浏览器插件");
    expect(container.querySelector('[data-testid="passkey-notice"]')).not.toBeNull();
    expect(seenBusy).toBe(true);
    expect(unlockButton()).toBeDefined();
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.browser-unlock.request", automatic: true });
  });

  it("calls onUnlocked when desktop unlock request resolves unlocked", async () => {
    let resolveUnlock!: (value: unknown) => void;
    sendMessage.mockImplementation(
      () => new Promise((resolve) => { resolveUnlock = resolve; }) as never,
    );

    await renderPage(PopupUnlockFactory.createFor("auto-open"));
    expect(onUnlocked).not.toHaveBeenCalled();

    await act(async () => {
      resolveUnlock({ status: "unlocked" });
    });

    expect(onUnlocked).toHaveBeenCalledTimes(1);
  });

  it("suppresses auto unlock in manual-locked mode and requests once when the user clicks unlock", async () => {
    sendMessage.mockResolvedValue({ status: "cancelled", errorMessage: "已取消解锁" } as never);

    function Harness() {
      const [suppressAutoUnlock, setSuppressAutoUnlock] = useState(true);
      const adapter = PopupUnlockFactory.resolve({ hasVault: true, suppressAutoUnlock });
      return createElement(PopupUnlockPage, {
        adapter,
        onUnlocked,
        onManualUnlockRequest: () => setSuppressAutoUnlock(false),
      });
    }

    await act(async () => {
      root.render(createElement(Harness));
    });

    expect(sendMessage).not.toHaveBeenCalled();
    const btn = unlockButton();
    expect(btn).toBeDefined();
    expect(btn!.textContent).toBe("解锁 VaultMesh 浏览器插件");

    await act(async () => {
      btn!.click();
    });

    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.browser-unlock.request" });
    expect(container.textContent).toContain("已取消解锁");
    expect(unlockButton()!.disabled).toBe(false);
  });

  it("hides the unlock button and skips auto request when vault is missing, then detects vault creation via status polling", async () => {
    const onVaultDetected = vi.fn();
    getDesktopStatus.mockResolvedValue({ unlocked: false, hasVault: true, itemCount: 0 });

    await renderPage(PopupUnlockFactory.createFor("vault-missing"), { onVaultDetected });

    expect(sendMessage).not.toHaveBeenCalled();
    expect(unlockButton()).toBeUndefined();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });

    expect(getDesktopStatus).toHaveBeenCalledTimes(1);
    expect(onVaultDetected).toHaveBeenCalledWith(true);
  });

  it("does not cancel desktop unlock on pagehide or visibilitychange and switches to workspace on vault.status poll", async () => {
    let resolveUnlock!: (value: unknown) => void;
    sendMessage.mockImplementation(
      () => new Promise((resolve) => { resolveUnlock = resolve; }) as never,
    );

    await renderPage(PopupUnlockFactory.createFor("auto-open"));

    await act(async () => {
      window.dispatchEvent(new Event("pagehide"));
      Object.defineProperty(document, "hidden", { value: true, configurable: true });
      document.dispatchEvent(new Event("visibilitychange"));
    });

    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage).not.toHaveBeenCalledWith(expect.objectContaining({
      kind: "vaultmesh.desktop-rpc",
      request: expect.objectContaining({ operation: "biometric.authentication.cancel" }),
    }));

    getDesktopStatus.mockResolvedValue({ unlocked: true, hasVault: true, itemCount: 3 });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });

    expect(onUnlocked).toHaveBeenCalledTimes(1);

    await act(async () => {
      resolveUnlock({ status: "unlocked" });
    });

    expect(onUnlocked).toHaveBeenCalledTimes(1);
    delete (document as unknown as { hidden?: boolean }).hidden;
  });
});
