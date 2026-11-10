# ADR-0055：浏览器未解锁候选摘要预检索与桌面统一临时解锁单次填充

- 状态：Accepted
- 日期：2026-11-09
- 关联 Work：`CHG-2026-060`
- 关闭 OPEN：无

## 背景

在原有浏览器扩展自动填充流程中，`browser.autofill.candidates` 与 `browser.autofill.execute` 均要求 `BrowserBrokerCore` 会话已处于解锁状态（`requiresUnlock: true`）。当用户在未解锁浏览器扩展时聚焦网页登录框或验证码输入框，内容脚本会直接调用 `vaultmesh.open-unlock` 打开工具栏 Popup 要求全局解锁整个浏览器会话，存在三个明显的体验与安全边界问题：

1. **未确认是否存在可用账号即强制解锁**：用户在网页输入框聚焦或输入用户名时，无法像 macOS iCloud 密码扩展或 VaultMesh Android 客户端（参见 `ADR-0044`）那样先查看当前站点是否存在匹配候选并按输入实时过滤。
2. **单次网页填充与 Popup 全局会话耦合**：用户仅希望在当前网页填充某一条账号，却被迫解锁整个浏览器 Popup 会话并暴露完整保险库浏览能力。
3. **临时解锁窗口职责分散与倒计时残留**：桌面端已为 Agent MCP 提供独立、置顶、`content_protected` 的受保护临时解锁窗口（`agent-unlock`），若在浏览器网页 DOM 内另建密码/PIN 浮层会增加网页侧受攻击面；同时现有临时解锁窗口在 30 秒倒计时结束后未自动关闭窗口，导致超时弹窗滞留桌面。

## 决策

1. **桌面端加密无秘密预授权候选摘要索引（Browser Pre-Auth Autofill Preview Index）**：
   - 沿用 `ADR-0044`（Android 预授权候选预览）与 `ADR-0053`（桌面统一钥匙串根秘密 `root-secret-v1`）边界，在桌面端 `DeviceCredentialStore` 中维护与当前 `vault.enc` 文件 SHA-256 摘要绑定的加密候选预览索引（作用域 `com.vaultmesh.desktop.browser-autofill-preview`）。
   - 预览索引仅保存非秘密匹配与展示元数据：`id`、`kind`、`title`、`subtitle`（用户名、掩码卡号摘要、身份摘要或主机名）、归一化站点匹配列表（`url`、`additionalUrls`、`website`、`host`）、`autofillOnPageLoad`、`masterPasswordReprompt` 与布尔标志 `hasTotpSecret`。
   - **严禁写入任何秘密值**：密码、TOTP 种子、完整卡号/CVV/PIN、敏感信息正文、SSH 私钥/口令、备注、自定义字段值与恢复码一律不得进入预览索引。
   - 桌面端或浏览器会话每次解锁成功及发生 Vault 变更（新增、修改、删除、恢复、密码轮换）时同步刷新预览索引；当 `BrowserBrokerCore` 处于锁定状态处理 `browser.autofill.candidates` 时，先校验磁盘 `vault.enc` 的实时 SHA-256 与索引记录一致，再按相同的同源/同主域名/页面上下文规则返回候选并标记 `requiresUnlock: true`。
2. **未解锁态候选展示与输入框实时过滤**：
   - 将 `browser.autofill.candidates` 与 `browser.autofill.execute` 的 RPC 策略调整为允许在 `BrowserBrokerCore` 锁定时调用（`requiresUnlock: false`）。
   - 内容脚本在锁定状态下聚焦输入框时直接展示匹配的候选列表，并在用户于登录用户名/邮箱输入框键入字符时，按候选 `subtitle` 前缀、邮箱 `@` 前本地部分前缀或 `title` 子串实时过滤候选列表；无匹配时自动隐藏内联候选浮层，不主动弹出解锁窗口。
   - 页面加载自动填充（`autofillOnPageLoad`）仅在 `requiresUnlock === false`（即浏览器会话已解锁）时自动执行，严禁在锁定状态下因页面加载自动拉起系统或桌面解锁窗口。
3. **复用桌面端统一受保护临时解锁窗口完成单次填充（与 Popup 会话解耦）**：
   - 当用户在网页内联候选列表中点击某一条目且 `BrowserBrokerCore` 处于锁定状态（或条目要求 `masterPasswordReprompt: true`）时，`browser.autofill.execute` 直接唤起桌面端统一受保护临时解锁窗口（`agent-unlock`，`index.html?surface=agent-unlock`），支持 `agent` 与 `browser-autofill` 两类挂起请求队列。
   - 对于 `browser-autofill` 请求，窗口展示目标站点 `topOrigin`、条目名称 `itemTitle` 与 30 秒倒计时，隐藏仅适用于 Agent 的范围开关；若桌面 Touch ID 已启用且条目不要求 `masterPasswordReprompt`，窗口打开时自动触发一次 Touch ID（`LAContext`），用户取消或未启用时可在同一窗口无缝使用 6 位 PIN 或主密码完成验证；若 `masterPasswordReprompt: true` 则直接要求输入主密码。
   - 验证通过后仅在局部临时 `DesktopRuntime` 实例中解密并生成绑定当前 `origin/tab/frame/document/handle` 的单次 `ApprovedFill`，随即销毁并清零临时 `DesktopRuntime`；`BrowserBrokerCore` 会话保持 `unlocked: false`，点击浏览器工具栏打开 Popup 仍须独立解锁。
4. **临时解锁窗口 30 秒倒计时结束自动取消并关闭**：
   - 无论是 `agent` 还是 `browser-autofill` 临时解锁请求，当 30 秒倒计时归零或收到后端超时事件（`agent-unlock-expired`）时，窗口必须自动取消当前超时请求；若队列中无下一个待处理请求，立即隐藏关闭窗口（`window.hide()`），消除超时弹窗滞留问题。

## 原因

- **对齐主流密码管理器直觉体验**：先确认当前网站有可用账号并支持输入过滤，仅在点击填充时按需认证。
- **最小权限与会话隔离**：单次网页填充不扩大为浏览器 Popup 全局解锁，也不在不可信网页 DOM 中渲染密码/PIN 输入框。
- **架构复用**：统一桌面端临时解锁窗口同时服务 Agent MCP 与浏览器单次填充，避免维护两套原生/浮层认证界面。

## 后果

- `browser.autofill.candidates` 与 `browser.autofill.execute` 在 `BROWSER_RPC_POLICIES` 中标记为 `requiresUnlock: false`，由各自处理器内部执行预览索引校验或单次临时解锁。
- `agent-unlock` 窗口状态协议扩展支持 `browser-autofill` 请求上下文，并在 30 秒超时后自动清理关闭。

## 被拒方案

- **在网页 Shadow DOM 内构建 PIN/主密码输入浮层**：增加了网页侧事件拦截与焦点竞争复杂度，且与桌面端已有的受保护临时解锁窗口重复建设。
- **点击网页候选时直接解锁整个浏览器 Popup 会话**：违背用户对“网页单次填充解锁”与“点击访问 Popup 独立解锁”的明确隔离预期。

## 验证

- `AT-AUTOFILL-001`、`AT-AUTOFILL-002`：验证锁定状态下候选检索、实时输入过滤、点击候选唤起桌面端临时解锁窗口完成单次填充，且填充后 Popup 仍保持锁定。
- `CT-BROWSER-002`：验证预授权候选索引不含任何秘密字段、绑定 `vault.enc` SHA-256 摘要，以及 RPC 契约一致性。
- `AT-AGENT-UNLOCK-001`：验证统一临时解锁窗口在 30 秒倒计时结束后自动取消并关闭窗口。
