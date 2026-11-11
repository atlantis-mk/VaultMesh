# ADR-0017：跨浏览器扩展共享远程 UI，使用浏览器特定 Native Messaging 身份

- 状态：Accepted
- 日期：2026-08-10
- 修订：2026-11-11，Chromium 不再使用 `webAuthenticationProxy`，Passkey 改为页面级 shim 且仍仅限 Chromium（ADR-0057）

## 决策

VaultMesh 继续只维护一套 WXT 扩展源码。Chrome/Chromium 使用 MV3、固定 manifest key 派生 ID 和 `allowed_origins`；Firefox 使用 WXT 的 Firefox MV2 target、固定 `browser_specific_settings.gecko.id` 和 `allowed_extensions`。两者调用同一 Browser RPC v2 与 Rust Native Host，但安装器为每个浏览器写入独立 manifest。

Native Host 在读取配对 secret 前按浏览器启动参数进行认证：Chrome 必须提供精确的编译期 `chrome-extension://<id>/` origin；Firefox 必须提供精确的已安装 manifest path 和编译期 Gecko ID。未知、缺失或混合参数全部拒绝。Firefox 不声明或模拟 Chromium-only `webAuthenticationProxy`，所以 Passkey proxy 保持 Chromium-only。

## 原因

- 单一扩展源码与同一 RPC policy 能避免 Firefox 形成第二套秘密或授权所有者。
- Chrome 与 Firefox 对 Native Messaging allowlist 字段、manifest位置和 Host 启动参数的契约不同，不能用一个宽松 origin 校验兼容。
- 固定 Gecko ID 让 Firefox manifest、Native Host 和可分发 ZIP 在开发与 Review sideload 之间保持稳定身份；后续商店身份必须单独验证。
- Firefox 缺少 Chromium WebAuthn proxy API；省略该 permission 并让现有 runtime capability detection返回 no-op，比伪造兼容层更安全。

## 后果

- macOS/Windows installer、卸载器和 AT 必须覆盖 Mozilla NativeMessagingHosts。
- Review CI 必须显式选择仓库固定的 `sideload-review` 公共身份并生成、检查两个浏览器 ZIP；不得读取或要求商店凭证。Firefox商店正式提交仍需独立 source ZIP 与商店审核流程。
- Chrome/Edge Passkey 行为不变；Firefox 包提供除 Passkey proxy 外的共享浏览器能力。
- 浏览器 authorization 仍由每条 Native Host/Broker连接的既有 session 生命周期隔离，最后一条授权结束后执行既有清理。

## 被拒方案

- 只把 Chrome ZIP 改名为 Firefox ZIP：manifest permission、身份和 Host 注册均错误。
- Firefox 复用 `allowed_origins` 或 Chrome origin 参数：不符合 Mozilla Native Messaging 契约并扩大身份混淆风险。
- 新建 Firefox 内置 Vault client：复制秘密 owner、解锁状态和持久化面。
- 在 Firefox 中模拟 Passkey proxy：没有等价浏览器 API，无法保持现有确认与签名边界。
