import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { beforeEach, describe, expect, it, vi } from "vitest";

const desktopRpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-rpc", () => ({ desktopRpc, confirmedDesktopRpc: vi.fn() }));

import { loadPluginSecurityPolicy } from "@/lib/plugin-security-policy";
import { SettingsPanel } from "./settings-panel";

const desktopSettings = {
  lockOnBlur: true,
  idleTimeoutMs: 300_000,
  lockOnSleep: true,
  clipboardClearTimeoutMs: 30_000,
  copySshPasswordOnLaunch: true,
};

describe("CT-BROWSER-003 popup plugin security settings", () => {
  beforeEach(async () => {
    await browser.storage.local.clear();
    desktopRpc.mockReset().mockImplementation(async (operation: string) => {
      if (operation === "pin.status") return { enabled: false, locked: false, failureLimit: 5, remainingAttempts: 5 };
      if (operation === "biometric.status") return { available: false, enabled: false };
      if (operation === "browser.pairing.status") return { paired: true };
      if (operation === "security.settings.get") return desktopSettings;
      if (operation === "security.settings.update") return desktopSettings;
      throw new Error(`Unexpected operation: ${operation}`);
    });
  });

  it("lets the user choose an idle timeout and saves it without submitting unchanged desktop settings", async () => {
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockResolvedValue({ status: "updated" } as never);
    const onNotice = vi.fn();
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice, onLocked: vi.fn(),
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("安全策略"))!.click());

      const idleGroup = container.querySelector('[role="group"][aria-labelledby="plugin-idle-timeout-label"]');
      expect(Array.from(idleGroup!.querySelectorAll("button"), (button) => button.textContent)).toEqual(["关闭", "1 分钟", "5 分钟（默认）", "10 分钟", "15 分钟", "30 分钟"]);
      expect(idleGroup?.querySelector('[aria-pressed="true"]')?.textContent).toBe("5 分钟（默认）");

      await act(async () => Array.from(idleGroup!.querySelectorAll("button")).find((button) => button.textContent === "15 分钟")!.click());
      expect(container.querySelector('[role="group"][aria-labelledby="plugin-idle-timeout-label"] [aria-pressed="true"]')?.textContent).toBe("15 分钟");

      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("保存安全策略"))!.click());
      expect((await loadPluginSecurityPolicy()).idleTimeoutMinutes).toBe(15);
      expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.security-policy.updated" });
      expect(desktopRpc).not.toHaveBeenCalledWith("security.settings.update", expect.anything());
      expect(onNotice).toHaveBeenCalledWith("插件安全策略已更新。", "success");
    } finally {
      await act(async () => root.unmount());
      container.remove();
      sendMessage.mockRestore();
    }
  });

  it("keeps plugin idle locking editable when desktop settings cannot load", async () => {
    desktopRpc.mockImplementation(async (operation: string) => {
      if (operation === "security.settings.get") throw new Error("桌面端暂不可用");
      if (operation === "pin.status") return { enabled: false, locked: false, failureLimit: 5, remainingAttempts: 5 };
      if (operation === "biometric.status") return { available: false, enabled: false };
      if (operation === "browser.pairing.status") return { paired: true };
      throw new Error(`Unexpected operation: ${operation}`);
    });
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockResolvedValue({ status: "updated" } as never);
    const onNotice = vi.fn();
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice, onLocked: vi.fn(),
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("安全策略"))!.click());
      expect(container.textContent).toContain("桌面端剪贴板设置暂不可用");
      const idleGroup = container.querySelector('[role="group"][aria-labelledby="plugin-idle-timeout-label"]');
      await act(async () => Array.from(idleGroup!.querySelectorAll("button")).find((button) => button.textContent === "关闭")!.click());
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("保存安全策略"))!.click());

      expect((await loadPluginSecurityPolicy()).idleTimeoutMinutes).toBe(0);
      expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.security-policy.updated" });
      expect(desktopRpc).not.toHaveBeenCalledWith("security.settings.update", expect.anything());
      expect(onNotice).toHaveBeenCalledWith("插件安全策略已更新。", "success");
    } finally {
      await act(async () => root.unmount());
      container.remove();
      sendMessage.mockRestore();
    }
  });

  it("lets the user choose a clipboard timeout and saves the changed desktop setting once", async () => {
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockResolvedValue({ status: "updated" } as never);
    const onNotice = vi.fn();
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice, onLocked: vi.fn(),
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("安全策略"))!.click());

      const clipboardGroup = container.querySelector('[role="group"][aria-labelledby="clipboard-timeout-label"]');
      expect(Array.from(clipboardGroup!.querySelectorAll("button"), (button) => button.textContent)).toEqual(["10 秒", "30 秒", "1 分钟", "2 分钟"]);
      expect(clipboardGroup?.querySelector('[aria-pressed="true"]')?.textContent).toBe("30 秒");
      await act(async () => Array.from(clipboardGroup!.querySelectorAll("button")).find((button) => button.textContent === "1 分钟")!.click());
      expect(container.querySelector('[role="group"][aria-labelledby="clipboard-timeout-label"] [aria-pressed="true"]')?.textContent).toBe("1 分钟");

      const saveButton = Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("保存安全策略"))!;
      await act(async () => saveButton.click());
      expect(desktopRpc).toHaveBeenCalledWith("security.settings.update", { ...desktopSettings, clipboardClearTimeoutMs: 60_000 });
      expect(desktopRpc.mock.calls.filter(([operation]) => operation === "security.settings.update")).toHaveLength(1);
      expect(onNotice).toHaveBeenCalledWith("插件安全策略已更新。", "success");

      await act(async () => saveButton.click());
      expect(desktopRpc.mock.calls.filter(([operation]) => operation === "security.settings.update")).toHaveLength(1);
      expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.security-policy.updated" });
    } finally {
      await act(async () => root.unmount());
      container.remove();
      sendMessage.mockRestore();
    }
  });

  it("keeps clipboard choices available when an unrelated desktop status fails", async () => {
    desktopRpc.mockImplementation(async (operation: string) => {
      if (operation === "pin.status") throw new Error("PIN 状态暂不可用");
      if (operation === "biometric.status") return { available: false, enabled: false };
      if (operation === "browser.pairing.status") return { paired: true };
      if (operation === "security.settings.get") return desktopSettings;
      if (operation === "security.settings.update") return desktopSettings;
      throw new Error(`Unexpected operation: ${operation}`);
    });
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockResolvedValue({ status: "updated" } as never);
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice: vi.fn(), onLocked: vi.fn(),
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("安全策略"))!.click());
      const clipboardGroup = container.querySelector('[role="group"][aria-labelledby="clipboard-timeout-label"]');
      expect(clipboardGroup).not.toBeNull();
      await act(async () => Array.from(clipboardGroup!.querySelectorAll("button")).find((button) => button.textContent === "2 分钟")!.click());
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("保存安全策略"))!.click());
      expect(desktopRpc).toHaveBeenCalledWith("security.settings.update", { ...desktopSettings, clipboardClearTimeoutMs: 120_000 });
    } finally {
      await act(async () => root.unmount());
      container.remove();
      sendMessage.mockRestore();
    }
  });

  it("lets the user choose the PIN failure limit without a popup dropdown", async () => {
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice: vi.fn(), onLocked: vi.fn(),
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("插件 PIN 解锁"))!.click());
      const pinGroup = container.querySelector('[role="group"][aria-labelledby="pin-failure-limit-label"]');
      expect(pinGroup?.querySelectorAll("button")).toHaveLength(8);
      expect(pinGroup?.querySelector('[aria-pressed="true"]')?.textContent).toContain("5 次");
      await act(async () => Array.from(pinGroup!.querySelectorAll("button")).find((button) => button.textContent === "7 次")!.click());
      expect(container.querySelector('[role="group"][aria-labelledby="pin-failure-limit-label"] [aria-pressed="true"]')?.textContent).toBe("7 次");
    } finally {
      await act(async () => root.unmount());
      container.remove();
    }
  });
});
