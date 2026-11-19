# ADR-0058：统一紧凑解锁窗口与浏览器会话持久解锁

- 状态：Accepted
- 日期：2026-11-19
- 关联 Work：`CHG-2026-085-unified-compact-unlock-and-browser-session`
- 关闭 OPEN：无（`OPEN-001` Windows Hello 仍不支持，不因本 ADR 改变）
- 修订关系：补充 `ADR-0050`（主窗口平台认证适配器）与 `ADR-0051`（Browser 跟随桌面 Touch ID）；取代 `ADR-0055` 中“浏览器网页填充与 Passkey 使用不解锁 `BrowserBrokerCore` 的单次临时解锁”决定，其余（无秘密预检索索引、候选实时过滤、30 秒倒计时自动关闭）保持有效

## 背景

1. 桌面主窗口、浏览器插件 Popup 与 Agent MCP 解锁窗口各自实现解锁界面：主窗口卡片外围留白大、按钮间距松散；Agent 窗口是独立布局，Touch ID 走弹窗而非嵌入式 `LAAuthenticationView`，启用 Touch ID 后回退主密码而非 PIN；Popup 内自带 PIN/主密码/Touch ID 轮询表单。三端体验与安全边界不一致。
2. `ADR-0055` 让浏览器网页填充与 Passkey 在锁定态仅做“单次临时解锁”：每次填充都要重新认证，与 macOS 密码插件“会话期解锁一次、按策略自动锁定”的预期不符，也让 Popup 与网页填充的解锁状态割裂。
3. 桌面 `agent_unlock_window.rs` 为浏览器请求读取了桌面 `state.pin`，而不是浏览器扩展自己的独立 PIN。
4. 三端 PIN 各自独立，但只有 Agent 与浏览器各在自己页面管理，没有统一的桌面管理入口。

## 决策

### 1. 统一紧凑解锁窗口

1. 桌面主窗口（`解锁 VaultMesh`）、浏览器插件解锁（`解锁 VaultMesh 浏览器插件`）与 Agent MCP 解锁（`解锁 VaultMesh Agent工具`）必须复用同一套解锁卡片组件，提供嵌入式 Touch ID（`LAAuthenticationView`）、独立 PIN 与主密码三种因子；场景差异只通过 `UnlockSurfaceUiAdapter` 表达，组件内不得堆叠场景 `if / else`。
2. 主窗口锁定态与统一解锁浮窗必须自适应收缩到与卡片等大的紧凑尺寸：宽 `460` 逻辑像素，前端仅测量卡片固有高度并叠加 `8px` 防滚动条安全余量（视口目标高度限制在 `[280, 760]`，外层包裹 `min-h-svh` 容器并由底部 `flex-1` 无缝填充底部余量，严禁在 `cardRef` 自身加 `min-h-svh` 形成高度回环）；后端经由 `WindowChromeFactory` / `WindowChromeAdapter` 处理三端（macOS / Windows / Linux）顶栏补偿与 `plan_resize_steps` 缩放顺序策略：
   - macOS：`MacOsWindowChromeAdapter` 在主线程通过 AppKit 读取 `contentRectForFrameRect(frame).size.height - contentLayoutRect.size.height` 动态补偿 `FullSizeContentView` 顶栏高度（仅紧凑态叠加至窗口高度与 `min_height`，退出紧凑态恢复常规尺寸时绝不叠加），`agent-unlock` 冷启初始高 `472.0`（`440 + 32pt` 顶栏预留），`main` 静态配置冷启 `460×472`（Windows/Linux 首帧多 `32px` 无滚动条并于挂载后收缩贴合）；
   - Windows：`WindowsWindowChromeAdapter` 顶栏内嵌增量为 `0.0`（Win32 `AdjustWindowRectExForDpi` 已在外框补齐标题栏、边框与单行 `HMENU`），`agent-unlock` 冷启高 `440.0`；进入紧凑态先 `SetMinSize` → 仅 `current_resizable != Some(false)` 时 `SetResizable(false)` → `SetSize`，避免 `WS_SIZEBOX` 边框偏差与 macOS `setStyleMask` 异步竞态及抢焦点；
   - Linux（GTK 3）：`LinuxWindowChromeAdapter` 顶栏内嵌增量为 `0.0`、`requires_temporary_resizable_for_resize() == true`，`agent-unlock` 冷启高 `440.0`，紧凑态调整尺寸若不可缩放则临时 `SetResizable(true)` → `SetMinSize` → `SetSize` → `SetResizable(false)`，避免 GTK 3 忽略 `gtk_window_resize`；
   - `main` 进入 `/vault` 或 `/setup` 后必须立即恢复保存的常规尺寸（无顶栏补偿叠加）与 `resizable(true)`，消除启动大窗口闪现。
   - **三端无竞态窗口居中**：`tauri.conf.json` 为 `main` 启用 `"center": true`；`WindowChromeAdapter::centered_position` 结合当前显示器 `work_area`、`scale_factor`、目标内框尺寸与外框 Chrome 差值 `WindowFrameDelta`（`outer - inner` 钳制在 `[0..64, 0..128]`）计算并钳制工作区内居中坐标（macOS/Linux 输出 `Position::Logical`，Windows 按 DPI 换算输出 `Position::Physical`），绝不调用内置 `window.center()`。`MainWindowLayoutAdapter` 在 `compact <-> normal` 跨模式切换时设置 `recenter = true`，由 `plan_resize_steps` 在 `SetSize` 后执行 `SetPosition`；`agent-unlock`（含隐藏态更新紧凑高度）与 `agent-authorization` 在从隐藏态重新显示（`!was_visible`）前按当前显示器 `work_area` 重新居中。
3. 浏览器 Popup 锁定态只显示精简锁定页，不再收集 PIN、主密码或轮询 Touch ID；正常打开自动唤起桌面统一解锁窗，用户在设置中主动「立即锁定」后不立即重弹，仅显示手动解锁入口。Popup 关闭或失焦不得取消桌面解锁窗。
4. 新增 Browser RPC `browser.unlock.request` 作为 Popup 唤起统一解锁窗的唯一通道（`requiresUnlock: false`、`requiresGesture: true`、`requiresConfirmation: false`）。既有 `vault.unlock`、`pin.unlock`、`biometric.authentication.*` 保持向后兼容，不在本 ADR 内删除。

### 2. 多窗口 `LAAuthenticationView` 安全边界

1. 嵌入式认证命令只允许 `main` 与 `agent-unlock` 两个窗口调用；`agent-pairing`、`agent-authorization` 与其他窗口一律拒绝，且不得获得 `allow-desktop-authentication` 或窗口布局权限。
2. 同一时刻仅在当前聚焦且可见的解锁窗口挂载一个原生认证视图；协调器按窗口标签维护独立 generation，切换窗口、失焦、隐藏、关闭、30 秒过期、切换请求或提交 PIN/主密码都必须立即使旧 generation 失效并取消原生视图，迟到回调一律拒绝。
3. 完成结果必须绑定该窗口当前的目标解锁域（桌面、浏览器会话、浏览器重验、Agent），不能借用其他域的因子或授权。
4. Windows 适配器保持 `supported() == false`，不隐式调用 macOS 逻辑（`OPEN-001` 保持开放）。

### 3. 浏览器会话持久解锁

1. 浏览器解锁由单次临时解锁改为会话持久解锁：锁定态下的 `browser.unlock.request`、网页点击 `browser.autofill.execute`、`passkeys.create` / `passkeys.get` 经统一解锁窗验证后，在 `BrowserBrokerCore` 中持久化解锁，直至 `PluginSecurityPolicy`（空闲时长、系统锁定、浏览器重启）、`vault.lock`、撤销或桌面锁定规则触发自动/手动锁定。
2. 已解锁期间，非支付卡且 `masterPasswordReprompt == false` 的 Login/身份/SSH/Secret 填充零弹窗；支付卡与 `masterPasswordReprompt: true` 条目仍必须通过 `MasterPasswordReprompt` 解锁窗重验主密码，验证后不改写解锁状态，也不得借用 PIN 或 Touch ID。
3. Passkey 无论解锁前还是已解锁，每次创建与登录仍必须保留一次桌面系统原生确认 `confirm_passkey`；确认必须在 `Mutex<BrowserBrokerCore>` 锁外执行，批准后重新检查撤销、解锁态、磁盘状态与请求有效期再提交；拒绝确认只取消该请求，不修改 Vault，已完成的会话解锁不回滚。
4. 多个并发浏览器会话解锁请求必须合并到同一展示窗口并延长剩余等待，不得在合并时提前关窗或销毁已有输入；唤醒后必须重检撤销、解锁态、过期与解锁发起时的会话代次。主动锁定或系统锁定必须推进该代次。无平台等待者且未解锁时必须 fail closed 返回 `unlock-required`。
5. 浏览器会话解锁不授予桌面主窗口或 Agent 授权；桌面主窗口与 Agent 解锁同样不授予浏览器。三端授权继续独立。
6. `vault-ffi` 提供 `unlock_for_browser_with_verified_key`，使统一解锁窗已验证的 Vault Key 在浏览器 runtime 中打开 Vault 而不重复运行 KDF；该 Key 不得经 Browser RPC、日志或扩展 storage 传递。

### 4. 三端独立 PIN 与桌面统一管理

1. 桌面（`state.pin`）、浏览器（`state.browser_pin`）、Agent（`state.agent_pin`）保持独立存储、独立失败计数与锁定；浏览器解锁窗读取的是 `browser_pin` 而非桌面 PIN；桌面主密码解锁只重置桌面 PIN 失败计数。`TauriBrowserPlatform` 与 `RuntimeState` 共享同一个浏览器 PIN 服务实例，使扩展设置页与桌面端实时同步（实验身份 `into_bitwarden_development` 保持独立隔离）。
2. 桌面安全中心提供统一的 “PIN 快速解锁” 入口，集中管理三端各自的 6 位 PIN。新增桌面 operation `browser.pin.status` / `browser.pin.enable` / `browser.pin.disable` 与 `agent.pin.status`，与既有 `pin.*`、`agent.pin.enable/disable` 一起委托共享辅助函数；启用任一端 PIN 都要求桌面当前会话由主密码认证并取得快速解锁材料，认证因子必须由 Rust runtime 保存和验证；关闭要求桌面已解锁。扩展既有 `pin.status/enable/disable` RPC 保持兼容。
3. `vault.create`、`vault.change-password`、`vault.restore` 必须同步关闭三端全部 PIN；主密码解锁后对三端执行 “PIN 属于不同 Vault 则关闭”。Touch ID 继续依据 `ADR-0051` 统一跟随桌面配置，不新增扩展或 Agent 独立生物识别开关。

### 5. Factory + Adapter 架构约束

横跨 Rust 与 TypeScript 的平台、窗口布局、窗口顶栏适配、解锁域、PIN 域、Popup 解锁模式差异必须收敛为“判别枚举/联合类型 + 抽象契约 + 无状态适配器 + Factory”，适配器无条件参与编译（仅最内层 OS FFI 块可使用 `cfg(target_os)`），编排层与 UI 只面向抽象编程，不得散落 `if` / `cfg!` 形态分支。当前实现：`DesktopAuthPlatformFactory`、`UnlockSurfaceFactory`、`WindowLayoutFactory`、`WindowChromeFactory`（含纯函数 `compute_content_chrome_inset`、`compute_centered_logical_origin`、`plan_resize_steps` 与值对象 `WorkAreaBounds` / `WindowFrameDelta` / `CenteredWindowPosition`）、`PinDomainFactory`（Rust）；`UnlockSurfaceUiFactory`、`PlatformAuthBridgeFactory`、`PinSettingsDomainFactory`、`PopupUnlockFactory`（TypeScript）。

## 原因

- 统一卡片与适配器消除三处重复实现，使嵌入式 Touch ID、PIN 与主密码的行为和文案一致，并减小窗口留白。
- 会话持久解锁对齐用户对密码插件的预期，同时仍受 `PluginSecurityPolicy` 约束；高风险条目（支付卡、主密码重验）与 Passkey 签名保留逐次确认，不降低对关键秘密的保护。
- 将 `LAAuthenticationView` 限定在 `main` + `agent-unlock` 并以 generation 抢占，可避免多窗口同时认证或迟到回调解锁错误的域。
- 三端 PIN 隔离保持“一端失陷或锁定不影响另一端”，统一管理入口只改善可管理性，不合并秘密或失败计数。

## 后果

- 浏览器不再有“网页填充后 Popup 仍锁定”的行为；`ADR-0055` 中单次临时解锁语义被会话持久解锁取代，锁定态预检索候选与未解锁实时过滤不变。
- 浏览器解锁一旦完成，空闲、系统锁定、浏览器重启策略成为唯一自动锁定来源，因此其测试必须覆盖这些策略仍清除会话。
- `browser.unlock.request` 是 Browser RPC 的新增公共操作，必须同时更新 operation schema、policy、dispatcher、extension client、workflow manifest 与 parity 测试。
- 回滚：恢复上一发布版本的桌面端与扩展即可；没有 Vault 文件格式变化。PIN 记录文件沿用既有 `desktop-pin-unlock.json`、`browser-pin-unlock.json` 与 `agent-pin-unlock.json` 记录，无迁移。

## 被拒方案

- **保留单次临时解锁并仅统一界面**：无法满足会话期一次解锁的体验目标，且 Popup 与网页填充解锁状态继续割裂。
- **合并三端 PIN 或让浏览器/Agent 复用桌面 PIN**：破坏三端授权与失败计数隔离，扩大一个 PIN 泄露的影响面。
- **允许所有桌面窗口挂载嵌入式认证视图**：扩大特权窗口攻击面，且无法保证同一时刻只有一个原生认证视图。
- **在 Popup 或网页 DOM 内收集 PIN/主密码**：增加不可信页面或扩展上下文的暴露面，已由 `ADR-0055` 拒绝并保持。
- **已解锁期间自动批准 Passkey 签名**：Passkey 私钥签名不可逆，必须保留每次系统原生确认。

## 验证

- `CT-DESKTOP-AUTH-001`：`desktop_authentication` 协调器的多窗口抢占、仅 `main` + `agent-unlock`、取消/迟到回调、`DesktopAuthPlatformFactory` 全平台适配器，以及 `UnlockSurfaceFactory`、`PinDomainFactory`、`WindowLayoutFactory` 与前端 `UnlockSurfaceUiFactory`、`PlatformAuthBridgeFactory`、`PinSettingsDomainFactory` 全变体单测。
- `CT-BROWSER-002`：`browser.unlock.request` 的 Rust/TypeScript 路由、policy 与 parity；`ct_browser_002_persistent_session_unlock_and_zero_popup_subsequent_autofill` 持久会话解锁与后续零弹窗填充。
- `CT-PASSKEY-002`：`browser_broker_tests.rs` 中会话解锁后锁外 `confirm_passkey`、拒绝确认与确认前后过期不改写 Vault 的回归。
- `CT-BROWSER-001`：`PopupUnlockFactory` 锁定页自动/手动锁行为与 Popup 关闭不取消桌面解锁窗，`CT-BROWSER-003` 的插件 PIN 同步。
- `AT-DESKTOP-AUTH-001`、`AT-AGENT-UNLOCK-001`、`AT-BROWSER-001`：在真实签名 macOS 包上验收三端紧凑解锁窗、嵌入式 Touch ID、独立 PIN、多窗口焦点切换、浏览器会话解锁后零弹窗填充、支付卡/主密码重验及 Passkey 系统确认。
