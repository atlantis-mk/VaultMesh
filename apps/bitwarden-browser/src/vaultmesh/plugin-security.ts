import { z } from "zod";
export const PLUGIN_POLICY_KEY = "vaultmesh.bitwarden-dev.security.v1";
export const PluginPolicySchema = z.object({ lockOnBrowserRestart: z.boolean(), lockOnSystemLock: z.boolean(),
  idleTimeoutMinutes: z.union([z.literal(0), z.literal(1), z.literal(5), z.literal(10), z.literal(15), z.literal(30)]) }).strict();
export type PluginPolicy = z.infer<typeof PluginPolicySchema>;
export const DEFAULT_PLUGIN_POLICY: PluginPolicy = { lockOnBrowserRestart: true, lockOnSystemLock: true, idleTimeoutMinutes: 5 };
export async function loadPluginPolicy(): Promise<PluginPolicy> {
  return new Promise<PluginPolicy>((resolve) => chrome.storage.local.get(PLUGIN_POLICY_KEY, (result) => {
    const parsed = PluginPolicySchema.safeParse(result?.[PLUGIN_POLICY_KEY]);
    resolve(!chrome.runtime.lastError && parsed.success ? parsed.data : { ...DEFAULT_PLUGIN_POLICY });
  })).catch(() => ({ ...DEFAULT_PLUGIN_POLICY }));
}
export async function savePluginPolicy(value: PluginPolicy): Promise<boolean> {
  const parsed = PluginPolicySchema.safeParse(value);
  if (!parsed.success) return false;
  return new Promise<boolean>((resolve) => chrome.storage.local.set({ [PLUGIN_POLICY_KEY]: parsed.data }, () => resolve(!chrome.runtime.lastError))).catch(() => false);
}
export function startPluginSecurity(lock: () => Promise<unknown>): void {
  if (!chrome.idle) return;
  let policy = { ...DEFAULT_PLUGIN_POLICY };
  let generation = 0;
  const refresh = async () => {
    const own = ++generation; const next = await loadPluginPolicy();
    if (own !== generation) return;
    policy = next; chrome.idle.setDetectionInterval(Math.max(15, (policy.idleTimeoutMinutes || 1) * 60));
  };
  const safeLock = () => { void lock().catch((): undefined => undefined); };
  chrome.idle.onStateChanged.addListener((state) => {
    if (state === "locked" && policy.lockOnSystemLock || state === "idle" && policy.idleTimeoutMinutes > 0) safeLock();
  });
  chrome.runtime.onStartup?.addListener(() => { void loadPluginPolicy().then((value) => { if (value.lockOnBrowserRestart) safeLock(); }); });
  chrome.storage.onChanged?.addListener((changes, area) => { if (area === "local" && changes[PLUGIN_POLICY_KEY]) void refresh(); });
  void refresh();
}
