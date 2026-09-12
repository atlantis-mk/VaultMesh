// Both supported browsers expose the callback-compatible chrome namespace.
// This fork does not have WXT's browser global/polyfill in Chromium.
export function sendSessionMessage(message: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response: unknown) => {
      if (chrome.runtime.lastError) reject(new Error("desktop-unavailable"));
      else resolve(response);
    });
  });
}

export function requestNativePermission(): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.permissions.request({ permissions: ["nativeMessaging"] }, (granted) => {
      resolve(!chrome.runtime.lastError && granted);
    });
  });
}
