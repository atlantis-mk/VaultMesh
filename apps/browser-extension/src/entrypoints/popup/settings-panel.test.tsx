import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { beforeEach, describe, expect, it, vi } from "vitest";

const desktopRpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-rpc", () => ({ desktopRpc, confirmedDesktopRpc: vi.fn() }));

import { loadPluginSecurityPolicy } from "@/lib/plugin-security-policy";
import { PasskeyBrowserFactory } from "@/lib/passkey-browser-adapter";
import { SettingsPanel } from "./settings-panel";

const desktopSettings = {
  lockOnBlur: true,
  idleTimeoutMs: 300_000,
  lockOnSleep: true,
  clipboardClearTimeoutMs: 30_000,
  copySshPasswordOnLaunch: true,
  sshSessionDurationMinutes: 15,
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

  it("explains that plugin PIN is independent while pointing to the desktop security center for unified management", async () => {
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice: vi.fn(), onLocked: vi.fn(),
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("插件 PIN 解锁"))!.click());
      const text = container.textContent ?? "";
      expect(text).toContain("与桌面端、Agent PIN 相互独立");
      expect(text).toContain("VaultMesh 桌面端「安全中心 → PIN 快速解锁」中统一管理三端 PIN");
      expect(container.querySelectorAll('input[type="password"]')).toHaveLength(2);
    } finally {
      await act(async () => root.unmount());
      container.remove();
    }
  });

  it("configures global passkeyGetDefault and passkeyCreateDefault, disables sub-options when takeover is off, and persists via saveSecurityPolicy", async () => {
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockResolvedValue({ status: "updated" } as never);
    const querySpy = vi.spyOn(browser.tabs, "query").mockResolvedValue([{ id: 1, url: "https://example.test/login" }] as never);
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice: vi.fn(), onLocked: vi.fn(),
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("安全策略"))!.click());

      const getGroup = container.querySelector('[role="group"][aria-labelledby="passkey-get-default-label"]');
      const createGroup = container.querySelector('[role="group"][aria-labelledby="passkey-create-default-label"]');
      expect(getGroup).not.toBeNull();
      expect(createGroup).not.toBeNull();
      expect(Array.from(getGroup!.querySelectorAll("button"), (b) => b.textContent)).toEqual(["VaultMesh（默认）", "每次询问"]);
      expect(getGroup!.querySelector('[aria-pressed="true"]')?.textContent).toBe("VaultMesh（默认）");
      expect(Array.from(createGroup!.querySelectorAll("button"), (b) => b.textContent)).toEqual(["每次询问（默认）", "VaultMesh"]);
      expect(createGroup!.querySelector('[aria-pressed="true"]')?.textContent).toBe("每次询问（默认）");

      await act(async () => Array.from(getGroup!.querySelectorAll("button")).find((b) => b.textContent === "每次询问")!.click());
      await act(async () => Array.from(createGroup!.querySelectorAll("button")).find((b) => b.textContent === "VaultMesh")!.click());
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("保存安全策略"))!.click());

      const saved = await loadPluginSecurityPolicy();
      expect(saved.passkeyGetDefault).toBe("ask");
      expect(saved.passkeyCreateDefault).toBe("vaultmesh");

      const takeoverCheckbox = Array.from(container.querySelectorAll("label"))
        .find((label) => label.textContent?.includes("接管网页通行密钥请求"))!
        .querySelector("input[type=checkbox]") as HTMLInputElement;
      await act(async () => takeoverCheckbox.click());

      expect(Array.from(getGroup!.querySelectorAll("button")).every((b) => b.disabled)).toBe(true);
      expect(Array.from(createGroup!.querySelectorAll("button")).every((b) => b.disabled)).toBe(true);
    } finally {
      await act(async () => root.unmount());
      container.remove();
      sendMessage.mockRestore();
      querySpy.mockRestore();
    }
  });

  it("hides full Passkey options when PasskeyBrowserFactory reports unsupported (Firefox)", async () => {
    const createSpy = vi.spyOn(PasskeyBrowserFactory, "create").mockReturnValue({
      target: "firefox",
      isSupported: false,
      disabledReason: "firefox-unsupported",
      allowsFrameWebAuthn: () => false,
      openPromptWindow: async () => undefined,
    });
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice: vi.fn(), onLocked: vi.fn(),
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("安全策略"))!.click());
      expect(container.querySelector('[aria-labelledby="passkey-get-default-label"]')).toBeNull();
      expect(container.querySelector('[aria-labelledby="passkey-create-default-label"]')).toBeNull();
      expect(container.textContent).not.toContain("接管网页通行密钥请求 (Passkey)");
    } finally {
      await act(async () => root.unmount());
      container.remove();
      createSpy.mockRestore();
    }
  });

  it("calls onLocked without reloading settings when enabling or disabling plugin PIN succeeds, and keeps session on failure", async () => {
    let pinEnabled = false;
    let rejectPinMutation = false;
    desktopRpc.mockImplementation(async (operation: string) => {
      if (operation === "pin.status") return { enabled: pinEnabled, locked: false, failureLimit: 5, remainingAttempts: 5 };
      if (operation === "biometric.status") return { available: false, enabled: false };
      if (operation === "browser.pairing.status") return { paired: true };
      if (operation === "security.settings.get") return desktopSettings;
      if (operation === "pin.enable") {
        if (rejectPinMutation) throw new Error("启用 PIN 失败");
        pinEnabled = true;
        return { enabled: true, locked: false, failureLimit: 5, remainingAttempts: 5 };
      }
      if (operation === "pin.disable") {
        if (rejectPinMutation) throw new Error("关闭 PIN 失败");
        pinEnabled = false;
        return { enabled: false, locked: false, failureLimit: 5, remainingAttempts: 5 };
      }
      throw new Error(`Unexpected operation: ${operation}`);
    });

    const onNotice = vi.fn();
    const onLocked = vi.fn();
    const container = document.createElement("div");
    document.body.append(container);
    let root = createRoot(container);

    try {
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice, onLocked,
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("插件 PIN 解锁"))!.click());

      const setInputValue = (input: HTMLInputElement, value: string) => {
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
        setter.call(input, value);
        input.dispatchEvent(new Event("input", { bubbles: true }));
      };

      const inputs = Array.from(container.querySelectorAll('input[type="password"]')) as HTMLInputElement[];
      await act(async () => {
        setInputValue(inputs[0]!, "123456");
        setInputValue(inputs[1]!, "123456");
      });

      // Failed pin.enable keeps session open without calling onLocked or reloading.
      rejectPinMutation = true;
      const callsBeforeFailedEnable = desktopRpc.mock.calls.length;
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent === "启用 PIN")!.click());
      expect(desktopRpc.mock.calls.slice(callsBeforeFailedEnable).map(([op]) => op)).toEqual(["pin.enable"]);
      expect(onNotice).toHaveBeenCalledWith("启用 PIN 失败", "error");
      expect(onLocked).not.toHaveBeenCalled();

      // Successful pin.enable skips reload and immediately calls onLocked.
      rejectPinMutation = false;
      onNotice.mockClear();
      await act(async () => {
        setInputValue(inputs[0]!, "123456");
        setInputValue(inputs[1]!, "123456");
      });
      const callsBeforeEnable = desktopRpc.mock.calls.length;
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent === "启用 PIN")!.click());
      expect(desktopRpc).toHaveBeenCalledWith("pin.enable", { pin: "123456", failureLimit: 5 });
      expect(desktopRpc.mock.calls.slice(callsBeforeEnable).map(([op]) => op)).toEqual(["pin.enable"]);
      expect(onNotice).toHaveBeenCalledWith("插件 PIN 解锁已启用。", "success");
      expect(onLocked).toHaveBeenCalledTimes(1);

      // Re-mount with PIN enabled to test update PIN + disable PIN success and failure paths.
      onNotice.mockClear();
      onLocked.mockClear();
      desktopRpc.mockClear();
      await act(async () => root.unmount());
      root = createRoot(container);
      await act(async () => root.render(createElement(SettingsPanel, {
        fillHistory: [], recoveryTargets: [], onRecoveryChanged: vi.fn(), onNotice, onLocked,
      })));
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("插件 PIN 解锁"))!.click());

      const enabledInputs = Array.from(container.querySelectorAll('input[type="password"]')) as HTMLInputElement[];
      await act(async () => {
        setInputValue(enabledInputs[0]!, "654321");
        setInputValue(enabledInputs[1]!, "654321");
      });
      const callsBeforeUpdate = desktopRpc.mock.calls.length;
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent === "更新 PIN")!.click());
      expect(desktopRpc.mock.calls.slice(callsBeforeUpdate).map(([op]) => op)).toEqual(["pin.enable"]);
      expect(onNotice).toHaveBeenCalledWith("插件 PIN 已更新。", "success");
      expect(onLocked).toHaveBeenCalledTimes(1);

      onNotice.mockClear();
      onLocked.mockClear();
      rejectPinMutation = true;
      const callsBeforeFailedDisable = desktopRpc.mock.calls.length;
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent === "关闭 PIN")!.click());
      expect(desktopRpc.mock.calls.slice(callsBeforeFailedDisable).map(([op]) => op)).toEqual(["pin.disable"]);
      expect(onNotice).toHaveBeenCalledWith("关闭 PIN 失败", "error");
      expect(onLocked).not.toHaveBeenCalled();

      rejectPinMutation = false;
      const callsBeforeDisable = desktopRpc.mock.calls.length;
      await act(async () => Array.from(container.querySelectorAll("button")).find((button) => button.textContent === "关闭 PIN")!.click());
      expect(desktopRpc.mock.calls.slice(callsBeforeDisable).map(([op]) => op)).toEqual(["pin.disable"]);
      expect(onNotice).toHaveBeenCalledWith("插件 PIN 解锁已关闭。", "success");
      expect(onLocked).toHaveBeenCalledTimes(1);
    } finally {
      await act(async () => root.unmount());
      container.remove();
    }
  });
});
