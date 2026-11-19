import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { beforeEach, describe, expect, it, vi } from "vitest";

const desktopRpc = vi.hoisted(() => vi.fn());
const pollDesktopEvents = vi.hoisted(() => vi.fn());
const getDesktopStatus = vi.hoisted(() => vi.fn());
const getEmailOtpCandidates = vi.hoisted(() => vi.fn());

vi.mock("@/lib/desktop-rpc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/desktop-rpc")>();
  return {
    ...actual,
    desktopRpc,
    confirmedDesktopRpc: vi.fn(),
    pollDesktopEvents,
    getDesktopStatus,
    getEmailOtpCandidates,
  };
});

import { getSitePasskeyMode, setSitePasskeyMode } from "@/lib/passkey-preferences";
import { PopupApp } from "./popup-app";
import { SettingsPanel } from "./settings-panel";

const workspace = {
  hasVault: true,
  snapshot: {
    items: [],
    identities: [],
    cards: [],
    sshCredentials: [],
    secrets: [],
  },
};

describe("site Passkey rule migration from PopupApp to SettingsPanel", () => {
  beforeEach(async () => {
    await browser.storage.local.clear();
    desktopRpc.mockReset().mockImplementation(async (operation: string) => {
      if (operation === "pin.status") return { enabled: false, locked: false, failureLimit: 5, remainingAttempts: 5 };
      if (operation === "biometric.status") return { available: false, enabled: false };
      if (operation === "browser.pairing.status") return { paired: true };
      if (operation === "security.settings.get") {
        return { lockOnBlur: true, idleTimeoutMs: 300_000, lockOnSleep: true, clipboardClearTimeoutMs: 30_000, copySshPasswordOnLaunch: true };
      }
      return { supported: false };
    });
    getDesktopStatus.mockReset().mockResolvedValue({ hasVault: true, unlocked: true });
    pollDesktopEvents.mockReset().mockResolvedValue({ sequence: 0, events: [] });
    getEmailOtpCandidates.mockReset().mockResolvedValue({ candidates: [], boostExpiresAt: 0 });
  });

  it("removes the site Passkey bar from PopupApp vault view", async () => {
    const origin = "https://passkeys.example.test";
    await setSitePasskeyMode(origin, "vaultmesh");

    const querySpy = vi.spyOn(browser.tabs, "query").mockResolvedValue([{ id: 1, url: `${origin}/login` }] as never);
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message: unknown) => {
      const msg = message as { kind?: string };
      if (msg.kind === "vaultmesh.popup-workspace-cache.get") return { status: "empty" };
      if (msg.kind === "vaultmesh.popup-suggestions.get") return { status: "ready", candidateIds: [] };
      if (msg.kind === "vaultmesh.save-capture-popup.get") return { status: "none" };
      if (msg.kind === "vaultmesh.fill-confirmation.get") return null;
      if (msg.kind === "vaultmesh.passkey-unlock.get") return null;
      if (msg.kind === "vaultmesh.device-assist-capabilities") return { supported: false };
      return {};
    });

    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(PopupApp, { initialWorkspace: workspace as never })));
      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
      });

      expect(container.querySelector('[aria-label="当前网站 Passkey 设置"]')).toBeNull();
      expect(container.querySelector('[role="group"][aria-label="当前网站 Passkey 模式"]')).toBeNull();
    } finally {
      await act(async () => root.unmount());
      container.remove();
      querySpy.mockRestore();
      sendMessage.mockRestore();
    }
  });

  it("manages the current tab site Passkey rule (跟随默认 / 询问 / VaultMesh / 系统) in SettingsPanel security section and resets on clear", async () => {
    const origin = "https://passkeys.example.test";
    await setSitePasskeyMode(origin, "vaultmesh");

    const querySpy = vi.spyOn(browser.tabs, "query").mockResolvedValue([{ id: 1, url: `${origin}/login` }] as never);
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message: unknown) => {
      const msg = message as { kind?: string };
      if (msg.kind === "vaultmesh.passkey-site-mode.updated") return { status: "updated" };
      return {};
    });

    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice: vi.fn(), onLocked: vi.fn(),
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("安全策略"))!.click());
      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
      });

      const group = container.querySelector('[role="group"][aria-labelledby="passkey-site-mode-label"]');
      expect(group).not.toBeNull();
      expect(container.querySelector("#passkey-site-mode-label")?.textContent).toContain("passkeys.example.test");
      expect(Array.from(group!.querySelectorAll("button"), (b) => b.textContent)).toEqual(["跟随默认", "询问", "VaultMesh", "系统"]);
      expect(group!.querySelector('[aria-pressed="true"]')?.textContent).toBe("VaultMesh");

      const systemButton = Array.from(group!.querySelectorAll("button")).find((b) => b.textContent === "系统")!;
      await act(async () => systemButton.click());
      await act(async () => {
        await Promise.resolve();
      });

      expect(group!.querySelector('[aria-pressed="true"]')?.textContent).toBe("系统");
      await expect(getSitePasskeyMode(origin)).resolves.toBe("native");
      expect(sendMessage).toHaveBeenCalledWith({
        kind: "vaultmesh.passkey-site-mode.updated",
        origin,
        mode: "native",
      });

      const clearButton = Array.from(container.querySelectorAll("button")).find((b) => b.textContent === "清除网站通行密钥选择")!;
      await act(async () => clearButton.click());
      await act(async () => {
        await Promise.resolve();
      });

      expect(group!.querySelector('[aria-pressed="true"]')?.textContent).toBe("跟随默认");
      await expect(getSitePasskeyMode(origin)).resolves.toBe("default");
    } finally {
      await act(async () => root.unmount());
      container.remove();
      querySpy.mockRestore();
      sendMessage.mockRestore();
    }
  });
});
