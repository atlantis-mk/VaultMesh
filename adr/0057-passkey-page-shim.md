# ADR-0057：以页面级 WebAuthn shim 取代全局 webAuthenticationProxy

- 状态：Accepted（2026-11-11 用户明确选择：完全移除 proxy、创建时每次选择、先只做 Chromium）
- 日期：2026-11-11
- 关联 Work：`CHG-2026-084-passkey-page-shim`
- 关闭 OPEN：无
- 修订关系：取代 `CHG-2026-083` 引入的“全站挂载 proxy”流程；不改变 `ADR-0003` 与 `ADR-0055` 中 Passkey 私钥只在桌面端签名、预检索索引仅含非秘密元数据的决定

## 背景

Chromium `chrome.webAuthenticationProxy` 面向远程桌面设计：attach 后整个浏览器 profile 的所有 WebAuthn 请求都交给扩展，扩展只能完成或失败，不能把同一请求交还浏览器。因此：

- 桌面端未运行、Vault 锁定或没有匹配凭据时，系统/浏览器的 Passkey（iCloud 钥匙串、Windows Hello、安全密钥、手机扫码）整体不可用。
- 回退只能靠 `NotAllowedError`、5 分钟 detach 和用户重试，网站常把它当作用户取消。
- `isUvpaa` 只能依据是否 attach 作答，实际是在冒充平台认证器。

## 决策

1. Chromium 扩展必须移除 `webAuthenticationProxy` 权限、`passkey-proxy` 及其全局 attach/detach、5 分钟 bypass 窗口和重试通知；不保留实验开关。
2. 扩展必须以 `world: "MAIN"`、`document_start`、`all_frames` 的 content script 包装 `navigator.credentials.create/get`，先保存原生函数引用。每个请求单独决策，需要回退时必须在同一次调用中直接调用原生函数，网站无需重试。
3. MAIN world shim 只做 WebAuthn 选项与响应的序列化、反序列化，不持有任何秘密。它通过 `window.postMessage` 与隔离世界 content script 通信，隔离世界再通过 `runtime.sendMessage` 交给 background；页面发出的任何字段都不是 origin 的依据。
4. Background 必须仅依据 `sender.origin`/`sender.url`、`tabId`、`frameId` 和 `webNavigation` 帧树确定 `remoteDesktopClientOverride.origin` 与 `sameOriginWithAncestors`，并自行写入请求 JSON，覆盖页面提供的同名字段。跨源子 frame（与顶层及所有祖先不同源）一律回退原生，由浏览器执行 permissions policy。
5. 以下情况必须直接回退原生，不得提示重试：通行密钥接管关闭、扩展未配对、桌面端不可达、`mediation: "conditional"`、依赖扩展结果的请求（`prf`、`largeBlob`、`hmacCreateSecret`、`credBlob`、`getCredBlob`、`payment`、`enforceCredentialProtectionPolicy=true`；其余扩展只作建议，与旧 proxy 一样被忽略）、请求参数超出大小上限、`passkeys.probe` 返回 `unavailable`。
6. 选择与解锁等待提示必须优先显示为发起请求标签页顶层 frame 内的页面对话框（closed shadow root、仅响应受信任事件），页面无法显示时回退到扩展 popup/窗口；对话框不得收集主密码、PIN 或生物识别，解锁只在扩展窗口完成。`create` 必须在每次请求时由用户选择“保存到 VaultMesh”或“使用浏览器/系统”，可以按 origin 记住选择，记住的选择不得跨 origin、不得保存 RP 以外的页面数据；`get` 在 `probe` 为 `available` 或 `unknown` 时仍须经原生确认，用户可以在选择窗口改用浏览器/系统。
7. 能力查询 `isUserVerifyingPlatformAuthenticatorAvailable` 与 `getClientCapabilities` 只在浏览器自己回答“没有平台认证器”且 VaultMesh 可用（接管开启、同源 frame 链、桌面端已配对可达）时由 shim 补位为可用，浏览器已回答“有”时不得改写，以免网站在发起创建前就判定设备不支持而绕过 VaultMesh。
8. 用户明确取消属于取消，返回 `NotAllowedError`；改用浏览器/系统、桌面不可用、无匹配均属于回退，不得返回错误。
9. 桌面端 `passkeys.probe/create/get`、预检索索引 v2、原生确认和私钥保护保持不变。
10. Firefox 范围不变：不包含 Passkey shim。

## 原因

- 页面级包装是 Bitwarden、Proton Pass 等密码管理器采用的唯一能做到逐请求回退的路径。
- 回退发生在同一次 `navigator.credentials` 调用内，避免全局状态、重试窗口和对其他站点的副作用。
- 信任边界保持在浏览器已验证的 `sender` 和桌面端 Rust 校验上，不引入新的秘密位置。

## 后果

- shim 对页面可见：页面可以检测到 `navigator.credentials.create/get` 已被替换，也可以在 shim 安装前保存原生引用而绕过它；这只会让该页面不使用 VaultMesh，不会降低秘密保护。
- 浏览器自身发起的流程（地址栏、Chrome 自带 Passkey 选择 UI、跨设备二维码）不经过 shim，仍由浏览器处理。
- 需要处理 `AbortSignal`、`timeout`、重复请求、frame 导航、扩展 context 失效和响应对象的 `PublicKeyCredential` 原型伪装。
- 条件式 UI（conditional mediation）仍不在当前范围。
- 迁移：升级后不再有 proxy attach；旧版本遗留的 attach 状态随扩展重载自动解除。`passkeyProxyEnabled` 存储字段保留原名以避免策略迁移，语义改为“接管通行密钥请求”。
- 回滚：恢复上一发布版本的扩展即可，没有持久化格式或 Vault 变化。

## 被拒方案

- 保留 proxy 并收紧 attach 条件：仍无法逐请求放行，只缓解“桌面不可用”场景。
- 保留 proxy 为可选开关：双路径增加测试与安全面，且未解决根因。
- 用 proxy 在 `unavailable` 时伪造页面重发：Chromium 已拦截的同一请求不能转交浏览器，重发会改变 origin 语义。

## 验证

- `CT-PASSKEY-001`：桌面端预检索、RP/`allowCredentials` 匹配与确认前再验证保持不变。
- `CT-PASSKEY-002`：background 决策与 origin 绑定、回退矩阵、取消语义、记住选择。
- `CT-PASSKEY-003`：MAIN world shim 的序列化、原生回退、`AbortSignal`、响应对象和未配对/不可用行为。
- `AT-PASSKEY-001`：真实 Chromium 中 VaultMesh 创建/登录、无匹配回退到系统通行密钥、桌面端关闭时系统通行密钥可用。
