# ADR-0057：以页面级 WebAuthn shim 取代全局 webAuthenticationProxy

- 状态：Accepted（2026-11-11 用户明确选择：完全移除 proxy、创建时每次选择；2026-11-18 补充 core/FFI 下沉、Factory+Adapter 分离、锁外单次解锁与 conditional 内联菜单决策；2026-11-19 修订：精简 `no-match` 卡片移除「填充密码登录」、拆分 `get`/`create` 全局默认策略并将站点规则统一收口至「设置 → 安全策略」）
- 日期：2026-11-11（修订：2026-11-18、2026-11-19）
- 关联 Work：`CHG-2026-084-passkey-page-shim`
- 关闭 OPEN：无
- 修订关系：取代 `CHG-2026-083` 引入的“全站挂载 proxy”流程；不改变 `ADR-0003` 与 `ADR-0055` 中 Passkey 私钥只在桌面端签名、预检索索引仅含非秘密元数据的决定

## 背景

Chromium `chrome.webAuthenticationProxy` 面向远程桌面设计：attach 后整个浏览器 profile 的所有 WebAuthn 请求都交给扩展，扩展只能完成或失败，不能把同一请求交还浏览器。因此：

- 桌面端未运行、Vault 锁定或没有匹配凭据时，系统/浏览器的 Passkey（iCloud 钥匙串、Windows Hello、安全密钥、手机扫码）整体不可用。
- 回退只能靠 `NotAllowedError`、5 分钟 detach 和用户重试，网站常把它当作用户取消。
- `isUvpaa` 只能依据是否 attach 作答，实际是在冒充平台认证器。

此外，早期实现将 WebAuthn 协议校验与签名置于桌面应用层 `apps/tauri-desktop/src-tauri/src/passkey_service.rs`，导致 `crates/vault-core/src/sync.rs` 需要跨层手写 JSON 解析；桌面 Broker 弹出原生确认框时持有全局互斥锁阻塞插件并发 RPC，且 macOS 托盘后台模式下未主动置顶激活；扩展侧对 `mediation: "conditional"`、`publicKey.timeout`、跨源 `PermissionsPolicy`/`topOrigin` 及无匹配引导尚不完整。

## 决策

1. Chromium 扩展必须移除 `webAuthenticationProxy` 权限、`passkey-proxy` 及其全局 attach/detach、5 分钟 bypass 窗口和重试通知；不保留实验开关。
2. 扩展必须采用 `PasskeyBrowserFactory` + `PasskeyBrowserAdapter` 架构（`apps/browser-extension/src/lib/passkey-browser-adapter.ts`）隔离浏览器差异：`ChromiumPasskeyAdapter` 启用页面级 WebAuthn shim；`FirefoxPasskeyAdapter` 保持 `disabled`（因 Firefox 缺失 `PublicKeyCredential.isConditionalMediationAvailable()` 与 `Document.permissionsPolicy`/`featurePolicy`），Firefox target 不注入 Passkey shim，产品范围不变。双方适配器源码无条件共同编译并通过各自单测。
3. 扩展必须以 `world: "MAIN"`、`document_start`、`all_frames` 的 content script 包装 `navigator.credentials.create/get`，先保存原生函数引用。每个请求单独决策，需要回退时必须在同一次调用中直接调用原生函数（当传入正整数 `publicKey.timeout` 时，按 `Math.min(Math.max(timeout, 1_000), PASSKEY_PROMPT_WAIT_MS)` 限时，回退原生时传入浅复制并扣减已耗时的剩余 `timeout`，下限 `1_000ms`），网站无需重试。
4. MAIN world shim 只做 WebAuthn 选项（含 `mediation` 与 `timeout`）与响应的序列化、反序列化，不持有任何秘密。它通过 `window.postMessage` 与隔离世界 content script 通信；隔离世界子 frame 必须先通过 `adapter.allowsFrameWebAuthn(document, operation)` 检查 `publickey-credentials-create` / `publickey-credentials-get` 权限策略（未授权时直接回退并记录 `permissions-policy-denied`），再经 `runtime.sendMessage` 交给 background；页面发出的任何字段都不是 origin 的依据。
5. Background 必须仅依据浏览器验证的 `sender.origin`/`sender.url`、`tabId`、`frameId` 与 `resolveFrameAncestry`（校验完整帧树无环且全为规范 HTTP(S) origin）确定 `remoteDesktopClientOverride.origin`、`sameOriginWithAncestors` 与 `topOrigin`，并自行写入请求 JSON，覆盖页面提供的同名字段；帧树不可信或含 opaque/`"null"` origin 时直接回退原生。
6. 以下情况必须直接回退原生，不得提示重试：通行密钥接管关闭、扩展未配对、桌面不可达、依赖扩展结果的请求（`prf`、`largeBlob`、`hmacCreateSecret`、`credBlob`、`getCredBlob`、`payment`、`enforceCredentialProtectionPolicy=true`；其余扩展只作建议被忽略）、请求参数超出大小上限、`PermissionsPolicy` 拒绝或帧链不可信。`mediation: "conditional"` 请求不再硬编码放行，仅在接管开启、未设站点 `"native"`、权限策略允许、`passkeys.probe` 返回 `available` 且存在候选时挂起于 broker，并接入 `InlineAutofillMenu` 顶部 `"通行密钥"` 分组（支持锁定态展示与桌面确认取消后保留重试）；否则立即回退浏览器原生条件式 UI。
7. 模态 `create` 与 `get` 提示必须优先显示为发起请求标签页顶层 frame 内的页面对话框（closed shadow root、仅响应受信任事件），页面无法显示时回退到扩展 popup/窗口；对话框不得收集主密码、PIN 或生物识别。支持三层设置分离：`browser-extension` 保留本地安全策略、`passkeyProxyEnabled`、全局默认策略（`passkeyGetDefault` 默认 `"vaultmesh"` 可切 `"ask"`，`passkeyCreateDefault` 默认 `"ask"` 可切 `"vaultmesh"`）与每站点 `SitePasskeyMode`（`"default" | "ask" | "vaultmesh" | "native"`，跨源以 `(topOrigin, origin)` 为复合键，跨源 `create` 强制询问且不自动记住选择），上述配置统一收口于「设置 → 安全策略」，Popup 密码库顶部不设常驻站点切换栏；`crates/vault-core` 零 UI/浏览器设置；桌面端拥有预检索索引 `browser_preauth_preview.rs`、`agent-unlock` 与原生确认。`get` 命中多条凭据时在对话框提供账号列表选择并传 `itemId`；`probe === "unavailable"` 且未记住原生时展示极简 `no-match` 卡片，仅提供「使用浏览器/系统（可记住）」与「取消」（2026-11-19 起移除「填充密码登录」按钮与 `password-login` 回调）。
8. 协议与密码学下沉：WebAuthn 协议校验、WebAuthn Level 3 `clientDataJSON`（跨源写入 `crossOrigin: true` 与规范 `topOrigin`）、`StoredPasskey`/`PrivateJwk`（`Drop` 自动 `zeroize` 私钥标量 `d`）、多候选逆序匹配（`matching_passkeys`）、`create_passkey`、`sign_passkey_assertion` 及同步辅助函数全部下沉至 `crates/vault-core/src/passkey.rs`（`crates/vault-core/src/sync.rs` 复用共享辅助函数，消除手写 JSON 重复解析）。`crates/vault-ffi`（`DesktopRuntime`）通过 `transaction(...)` 提供先原子写盘再发布内存状态的事务包装，并透传 `PasskeyError` 错误码与中文提示；`apps/tauri-desktop/src-tauri/src/passkey_service.rs` 退化为保持既有签名的薄门面。
9. 桌面 Broker 锁外执行与 macOS 前台置顶：`passkeys.probe` 保留返回含全部匹配 `candidates` 与 `hasLoginCandidates` 的向后兼容载荷（自 2026-11-19 起扩展侧忽略 `hasLoginCandidates`）。`passkeys.create`/`passkeys.get` 通过 `DeferredBrokerExecution` 释放 `Mutex<BrowserBrokerCore>` 锁后执行：锁定时若 `preauth_preview` 明确无匹配直接返回 `passkey-unavailable`；若 `begin_one_shot_unlock_for_fill` 可用则拉起 `agent-unlock` 单次临时解锁（Touch ID / PIN / 主密码），无平台 waiter 时 fail-closed 返回 `unlock-required`。随后在锁外执行 `blocking_show()` 原生确认（macOS 置 `set_dock_visibility(true)` 并通过 `objc2` 主线程 `activateIgnoringOtherApps: YES` 激活前台，跨源正文同时展示 `请求方：{origin}` 与 `当前网站：{topOrigin}`；结束后仅在无其他可见 VaultMesh 窗口时恢复 `set_dock_visibility(false)`），批准后重新校验撤销与磁盘状态再原子提交。
10. 能力查询 `isUserVerifyingPlatformAuthenticatorAvailable` 与 `getClientCapabilities` 只在浏览器自己回答“没有平台认证器”且 VaultMesh 可用（接管开启、权限策略与帧链允许、桌面端已配对可达）时由 shim 补位为可用，浏览器已回答“有”时不得改写，以免网站在发起创建前就判定设备不支持而绕过 VaultMesh。
11. 用户明确取消属于取消，返回 `NotAllowedError`；改用浏览器/系统、桌面不可用、无匹配回退均属于回退，不得返回错误。

### 跨进程取消与兼容

扩展后台必须为每次桌面 Passkey 操作生成独立 RPC UUID，使用 `passkeys.cancel` 取消该请求，并将网页模态期限收紧到 RPC 的 `expiresAt`。该取消操作必须通过既有配对鉴权，允许锁定态调用，无用户手势或确认要求。桌面须在原生确认前后重验该 UUID 的取消状态、有效期和浏览器会话代次。

桌面通过 `vault.status.passkeyCancellation` 声明支持此协议，扩展通过创建或断言输入的 `cancellable: true` 声明能够取消。混用缺少任一声明的版本时回退浏览器或系统实现。其余 Browser RPC 操作与 `passkeys.probe` 保持兼容。

## 原因

- 页面级包装是能够实现逐请求回退与条件式 UI 接管的唯一路径，且回退发生在同一次 `navigator.credentials` 调用内，无全局状态与重试窗口副作用。
- 将 WebAuthn 协议校验、密钥模型与签名下沉至 `crates/vault-core`，使 `VaultSession` 成为私钥生命周期与协议一致性的唯一所有者，`sync.rs` 与桌面端不再各自维护脆弱的 JSON 解析。
- 扩展、核心与桌面三层设置分离保持了 `vault-core` 的平台无关性与扩展本地策略的独立性。
- `PasskeyBrowserFactory` + Adapter 明确隔离了 Chromium 与 Firefox 的平台能力差异，避免条件编译污染核心流程。
- `DeferredBrokerExecution` 与 macOS 前台置顶消除了锁定态弹窗失败、后台确认不可见与长等待阻塞 `vault.status` 等桌面 RPC 的并发问题。

## 后果

- shim 对页面可见：页面可以检测到 `navigator.credentials.create/get` 已被替换，也可以在 shim 安装前保存原生引用而绕过它；这只会让该页面不使用 VaultMesh，不会降低秘密保护。
- 浏览器自身发起的流程（地址栏、Chrome 自带 Passkey 选择 UI、跨设备二维码）不经过 shim，仍由浏览器处理。
- 需要处理 `AbortSignal`、`publicKey.timeout`、conditional 挂起与取消重试、重复请求、frame 导航、扩展 context 失效和响应对象的 `PublicKeyCredential` 原型伪装。
- 诊断记录：每次回退、取消、失败、提示显示与凭据返回的原因码只在 `storage.session` 保留最近 20 条（origin、操作、原因码），设置页可查看与清除，不含任何请求内容。
- 迁移：升级后不再有 proxy attach；旧版本遗留的 attach 状态随扩展重载自动解除。`passkeyProxyEnabled` 存储字段保留原名以避免策略迁移，语义改为“接管通行密钥请求”。
- 回滚：恢复上一发布版本的桌面端与扩展即可，没有破坏性 Vault 格式变化。

## 被拒方案

- 保留 proxy 并收紧 attach 条件：仍无法逐请求放行，只缓解“桌面不可用”场景。
- 保留 proxy 为可选开关：双路径增加测试与安全面，且未解决根因。
- 用 proxy 在 `unavailable` 时伪造页面重发：Chromium 已拦截的同一请求不能转交浏览器，重发会改变 origin 语义。
- 在 `vault-core` 中直接保存扩展站点开关或将 Chrome/Firefox 差异散落为全局 `if/else`：破坏核心层与扩展层职责边界并增加跨端回归风险。

## 验证

- `CT-PASSKEY-001`：`crates/vault-core/src/passkey.rs` 与 `crates/vault-ffi` 的协议校验、含 `topOrigin` 的 `clientDataJSON`、多候选签名、`PrivateJwk` zeroize 与同步辅助函数单测，以及桌面端预检索、RP/`allowCredentials` 匹配与确认前再验证测试。
- `CT-PASSKEY-002`：`apps/tauri-desktop/src-tauri/src/browser_broker_tests.rs`（`DeferredBrokerExecution` 锁外执行与并发 `vault.status` 零阻塞、单次临时解锁、多候选探测与失效拒绝）及 `apps/browser-extension/src/lib/passkey-broker.test.ts`、`passkey-browser-adapter.test.ts`、`passkey-preferences.test.ts`、`plugin-security-policy.test.ts`、`settings-panel.test.tsx`、`popup-site-passkey.test.tsx`、`frame-origin.test.ts`、`autofill-page.test.ts`、`inline-autofill-view.test.ts`（origin/`topOrigin` 绑定、`PermissionsPolicy`、Factory+Adapter、回退矩阵、`get`/`create` 默认策略、设置页站点模式切换、`conditional` 内联菜单与极简 `no-match` 引导）。
- `CT-PASSKEY-003`：`passkey-shim.test.ts` 与 `passkey-dialog.test.ts`（选项序列化不含 origin、`publicKey.timeout` 传递与剩余时间回退、`mediation: "conditional"` 转发、响应还原为 `PublicKeyCredential`、页面对话框交互与能力查询）。
- `AT-PASSKEY-001`：真实 macOS 打包桌面端与 Chromium 扩展中完成创建/登录、多凭据选择、条件式内联菜单、锁定态 Touch ID/PIN 单次解锁、macOS 前台置顶原生确认、跨源 iframe 权限与 `topOrigin` 展示、极简无匹配回退、设置页默认与站点规则切换、桌面端关闭时系统通行密钥可用验收。
