import { z } from "zod";

const PLUGIN_SECURITY_POLICY_KEY = "vaultmesh.plugin-security-policy.v1";

const pluginSecurityPolicySchema = z.object({
  lockOnBrowserRestart: z.boolean(),
  lockOnSystemLock: z.boolean(),
  idleTimeoutMinutes: z.union([
    z.literal(0),
    z.literal(1),
    z.literal(5),
    z.literal(10),
    z.literal(15),
    z.literal(30),
  ]),
  passkeyProxyEnabled: z.boolean().default(true),
});

export type PluginSecurityPolicy = z.infer<typeof pluginSecurityPolicySchema>;
export type BrowserIdleState = "active" | "idle" | "locked";

export const DEFAULT_PLUGIN_SECURITY_POLICY: PluginSecurityPolicy = {
  lockOnBrowserRestart: true,
  lockOnSystemLock: true,
  idleTimeoutMinutes: 5,
  passkeyProxyEnabled: true,
};

export async function loadPluginSecurityPolicy(): Promise<PluginSecurityPolicy> {
  try {
    const stored = await browser.storage.local.get(PLUGIN_SECURITY_POLICY_KEY);
    const parsed = pluginSecurityPolicySchema.safeParse(stored[PLUGIN_SECURITY_POLICY_KEY]);
    return parsed.success ? parsed.data : DEFAULT_PLUGIN_SECURITY_POLICY;
  } catch {
    return DEFAULT_PLUGIN_SECURITY_POLICY;
  }
}

export async function savePluginSecurityPolicy(policy: PluginSecurityPolicy): Promise<boolean> {
  const parsed = pluginSecurityPolicySchema.safeParse(policy);
  if (!parsed.success) return false;
  try {
    await browser.storage.local.set({ [PLUGIN_SECURITY_POLICY_KEY]: parsed.data });
    return true;
  } catch {
    return false;
  }
}

export function shouldLockForIdleState(policy: PluginSecurityPolicy, state: BrowserIdleState): boolean {
  if (state === "locked") return policy.lockOnSystemLock;
  return state === "idle" && policy.idleTimeoutMinutes > 0;
}

export function idleDetectionIntervalSeconds(policy: PluginSecurityPolicy): number {
  return policy.idleTimeoutMinutes > 0 ? Math.max(15, policy.idleTimeoutMinutes * 60) : 60;
}
