import { beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_PLUGIN_SECURITY_POLICY,
  idleDetectionIntervalSeconds,
  loadPluginSecurityPolicy,
  savePluginSecurityPolicy,
  shouldLockForIdleState,
} from "./plugin-security-policy";

describe("plugin security policy", () => {
  beforeEach(async () => browser.storage.local.clear());

  it("uses secure defaults", async () => {
    await expect(loadPluginSecurityPolicy()).resolves.toEqual({
      lockOnBrowserRestart: true,
      lockOnSystemLock: true,
      idleTimeoutMinutes: 5,
      passkeyProxyEnabled: true,
      passkeyGetDefault: "vaultmesh",
      passkeyCreateDefault: "ask",
    });
  });

  it("persists a valid policy", async () => {
    const policy = {
      lockOnBrowserRestart: false,
      lockOnSystemLock: true,
      idleTimeoutMinutes: 15 as const,
      passkeyProxyEnabled: false,
      passkeyGetDefault: "ask" as const,
      passkeyCreateDefault: "vaultmesh" as const,
    };
    await expect(savePluginSecurityPolicy(policy)).resolves.toBe(true);
    await expect(loadPluginSecurityPolicy()).resolves.toEqual(policy);
  });

  it("fills backward-compatible Passkey defaults for legacy stored policies", async () => {
    await browser.storage.local.set({
      "vaultmesh.plugin-security-policy.v1": {
        lockOnBrowserRestart: false,
        lockOnSystemLock: false,
        idleTimeoutMinutes: 10,
        passkeyProxyEnabled: true,
      },
    });
    await expect(loadPluginSecurityPolicy()).resolves.toEqual({
      lockOnBrowserRestart: false,
      lockOnSystemLock: false,
      idleTimeoutMinutes: 10,
      passkeyProxyEnabled: true,
      passkeyGetDefault: "vaultmesh",
      passkeyCreateDefault: "ask",
    });
  });

  it("rejects invalid idle timeouts and Passkey default modes", async () => {
    await expect(savePluginSecurityPolicy({ ...DEFAULT_PLUGIN_SECURITY_POLICY, idleTimeoutMinutes: 2 as 5 })).resolves.toBe(false);
    await expect(savePluginSecurityPolicy({ ...DEFAULT_PLUGIN_SECURITY_POLICY, passkeyGetDefault: "native" as "ask" })).resolves.toBe(false);
    await expect(savePluginSecurityPolicy({ ...DEFAULT_PLUGIN_SECURITY_POLICY, passkeyCreateDefault: "native" as "ask" })).resolves.toBe(false);
    await expect(loadPluginSecurityPolicy()).resolves.toEqual(DEFAULT_PLUGIN_SECURITY_POLICY);
  });

  it("maps browser states to lock actions", () => {
    expect(shouldLockForIdleState(DEFAULT_PLUGIN_SECURITY_POLICY, "active")).toBe(false);
    expect(shouldLockForIdleState(DEFAULT_PLUGIN_SECURITY_POLICY, "idle")).toBe(true);
    expect(shouldLockForIdleState(DEFAULT_PLUGIN_SECURITY_POLICY, "locked")).toBe(true);
    expect(shouldLockForIdleState({ ...DEFAULT_PLUGIN_SECURITY_POLICY, idleTimeoutMinutes: 0 }, "idle")).toBe(false);
    expect(shouldLockForIdleState({ ...DEFAULT_PLUGIN_SECURITY_POLICY, lockOnSystemLock: false }, "locked")).toBe(false);
  });

  it("uses seconds for the browser idle API", () => {
    expect(idleDetectionIntervalSeconds(DEFAULT_PLUGIN_SECURITY_POLICY)).toBe(300);
    expect(idleDetectionIntervalSeconds({ ...DEFAULT_PLUGIN_SECURITY_POLICY, idleTimeoutMinutes: 0 })).toBe(60);
  });
});
