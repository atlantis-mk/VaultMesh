import { SESSION_MESSAGE, VAULTMESH_STATUS_MESSAGE } from "./contracts";
// Both supported browsers expose the callback-compatible chrome namespace.
// This fork does not have WXT's browser global/polyfill in Chromium.
export function sendSessionMessage(message: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    // Both stages of popup initialization are read-only. Do not change mutation
    // deadlines or retry writes, even when a read response never arrives.
    const isStatus = !!message && typeof message === "object" && "kind" in message && message.kind === VAULTMESH_STATUS_MESSAGE;
    const isLoginList = !!message && typeof message === "object" && "kind" in message && message.kind === SESSION_MESSAGE && "action" in message && message.action === "logins";
    const isUnlockStatus = !!message && typeof message === "object" && "kind" in message && message.kind === SESSION_MESSAGE && "action" in message && message.action === "security-tool"
      && "command" in message && !!message.command && typeof message.command === "object" && "operation" in message.command
      && (message.command.operation === "pin.status" || message.command.operation === "biometric.status");
    let settled = false;
    const timer = isStatus || isLoginList || isUnlockStatus ? setTimeout(() => { settled = true; reject(new Error(isLoginList ? "login-list-timeout" : "connection-timeout")); }, 10_000) : undefined;
    try { chrome.runtime.sendMessage(message, (response: unknown) => {
      const error = chrome.runtime.lastError;
      if (timer) clearTimeout(timer);
      if (settled) return;
      settled = true;
      if (error || response === undefined) reject(new Error(isStatus ? "background-unavailable" : "desktop-unavailable"));
      else resolve(response);
    }); } catch {
      if (timer) clearTimeout(timer);
      settled = true;
      reject(new Error(isStatus ? "background-unavailable" : "desktop-unavailable"));
    }
  });
}

export function requestNativePermission(): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), 30_000);
    try {
      chrome.permissions.request({ permissions: ["nativeMessaging"] }, (granted) => {
        clearTimeout(timer);
        resolve(!chrome.runtime.lastError && granted);
      });
    } catch { clearTimeout(timer); resolve(false); }
  });
}
