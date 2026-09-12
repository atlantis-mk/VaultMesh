// Only these fixed codes cross the background/popup boundary. Never expose raw
// browser/native errors, paths, request payloads or broker response details.
export const CONNECTION_CODES = ["desktop-unavailable", "native-host-not-found", "native-host-forbidden", "native-host-exited", "native-permission-required", "background-unavailable", "connection-timeout", "login-list-timeout", "invalid-broker-response", "update-required", "unpaired"] as const;
export type ConnectionCode = typeof CONNECTION_CODES[number];
export function connectionCode(value: unknown): ConnectionCode {
  return CONNECTION_CODES.includes(value as ConnectionCode) ? value as ConnectionCode : "desktop-unavailable";
}
export function nativeConnectionCode(message?: string): ConnectionCode {
  if (/native messaging host not found|specified native messaging host not found/i.test(message ?? "")) return "native-host-not-found";
  if (/forbidden|access.*denied/i.test(message ?? "")) return "native-host-forbidden";
  if (/nativeMessaging|permission/i.test(message ?? "")) return "native-permission-required";
  if (/exited|failed to start|error when communicating/i.test(message ?? "")) return "native-host-exited";
  return "desktop-unavailable";
}
export function connectionMessage(value: unknown): string {
  const code = connectionCode(value);
  const messages: Record<ConnectionCode, string> = {
    "desktop-unavailable": "连接未完成，请确认桌面开发端仍在运行。",
    "native-host-not-found": "浏览器找不到专用 Native Host，请检查该浏览器的 Host 注册。",
    "native-host-forbidden": "浏览器拒绝连接 Host，请核对已加载插件的 ID 与 Host 允许的 ID。",
    "native-host-exited": "Native Host 启动失败或已退出，请检查桌面开发端和系统授权提示。",
    "native-permission-required": "请点击连接并允许插件连接桌面应用。",
    "background-unavailable": "插件后台没有响应，请在扩展管理页重新加载此插件。",
    "connection-timeout": "连接等待超时，请检查插件后台和系统授权提示后重试。",
    "login-list-timeout": "桌面连接已响应，但读取登录列表超时。请稍后刷新；未执行保存或删除。",
    "invalid-broker-response": "桌面响应不兼容，请确认桌面与插件使用同一版代码。",
    "update-required": "协议版本不兼容，请更新桌面端与插件。",
    "unpaired": "专用开发身份尚未完成配对，请检查桌面端的插件授权。",
  };
  return `${messages[code]}（${code}）`;
}
