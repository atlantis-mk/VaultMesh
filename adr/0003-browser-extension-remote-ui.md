# ADR-0003：浏览器扩展是远程 UI，不是 Vault Client

- 状态：Accepted
- 日期：2026-07-22
- 修订：2026-07-23，默认 broker owner 切换到 Tauri Rust runtime；2026-07-24，邮箱 OTP 候选改为显式打开后的全局短时候选

## 决策

Chromium MV3 extension 通过固定 ID、Rust native host 和 authenticated RPC v2 调用正在运行的
Tauri Rust broker。Extension 不打开 Vault、不持有 Vault Key、不持久化 Vault response；native
host 只转发。Desktop 与 extension 使用独立 authorization。

实验性 Bitwarden 副本采用用户明确选择的独立开发身份，与既有 WXT 扩展并存。开发 Host
使用不同的名称、固定浏览器 ID、OS 凭据条目、配对记录和 IPC endpoint；桌面进程为它创建独立
BrowserBrokerCore/DesktopRuntime 授权 handle，但仍由共享 core 拥有同一 Vault 的原子持久化。
开发 listener 仅在 debug 构建并显式启用时运行；系统锁定、退出和撤销必须清理它的授权。
不得将第二 ID 追加到既有 Host allowlist，或借用已有配对、PIN、生物识别和待确认状态。

经用户于 2026-09-12 明确批准，实验副本允许由可信工具栏 popup 主动创建独立编辑窗口。
Background 只登记其精确 window/tab ID 与 extension URL，不托管或持久化编辑草稿。
只有该窗口主动发起的恢复码原生文件对话框期间，允许在固定期限内保留组件内存草稿；
窗口关闭、导航、取消、锁定、撤销、断连和截止时间不受此例外豁免。
导入必须先保留源文件；成功保存 Login 后才可以消费桌面持有的短期不透明清理句柄，
由原生确认框询问删除并重验文件。无法确认保存结果时不能请求删除。

邮箱 OTP 是独立 browser authorization 内的全局短时候选，不按当前网站与发件域名过滤。只有用户
显式打开插件 popup 或 OTP 字段页内列表后才披露，选择后仍由 Rust 按 candidate ID、expiry 和当前
origin/tab/frame/document/handle 重新验证并生成单次 assignment；不得自动选择、自动填入或提交表单。

## 原因

- 当前实验副本按 Scope Matrix 将备份/恢复与批量导入集中在桌面端完成，避免为桌面已有工作流重复建立插件文件选择、预览和提交生命周期；这不是删除既有兼容 RPC 的决定，也不构成其他填充契约扩展的批准。
- 避免在 browser storage/runtime 复制加密 Vault 和解锁状态。
- File dialog、clipboard、biometric、SSH/email 和 Passkey signing 可以留在受控 desktop process。
- 独立 authorization/revoke 降低浏览器被长期授权的风险。
- 事务邮件的发件域名经常与业务网站不同，域名过滤会使真实验证码不可用；显式选择和短时生命周期
  是邮箱候选的主要披露边界。

## 后果

- 用户继续要求补齐 SSH/Secret 后，封闭计划可以扩展到这两类既有 Browser Required 能力。上游只原生拥有 SSH 公钥/标题，不具有 VaultMesh 服务 Secret 类型，因此采用原生 custom-field 精确匹配承载明确的适配来源，而不是新增全页面启发式或把 Secret 当 Login。HTTPS、空字段、显式选择、类型重验、二次验证和逐来源解密保持桌面控制；Passkey 私钥不属于此例外。具体规则由 Browser 专项规格拥有。

- 经用户明确要求，原生无值计划扩展到 card/identity。Rust 只为已绑定字段返回该来源的值；content 可在该字段范围内复用原生格式转换（有效期、国家/地区、select），不得用该值重新规划其他字段。生成器结果可以通过 fresh-gesture 有界操作交给桌面剪贴板，或按当前文档的原生角色写入空的新密码/用户名字段；不保存历史、不自动提交。

- Bitwarden 实验副本可以用原生识别和脚本生成器先生成不含秘密的 Login 字段计划，再通过既有
  `browser.autofill.execute` 的显式选择分支解析 username/password、TOTP 和 custom-field 来源。计划不是授权：Rust 必须
  独立验证项目、二次验证、页面绑定、字段排除和一次性期限，只返回逐 handle assignment。
  规划 metadata 只允许字段名称与索引，TOTP seed 和自定义字段值必须留在 desktop；完整或分段 OTP
  只通过已授权 handle 返回。每个 frame 必须单独绑定与重验，跨源选择必须确认真实目标来源。
  未支持的计划必须拒绝，不能回退到整条明文 CipherView 或另一套字段匹配。
  原生 content executor 每个动作及最终赋值前仍须验证 DOM 身份、原归属、资格和期限。

- Desktop app 必须运行，extension 才有完整能力。
- RPC 必须 versioned、authenticated、bounded、expiring、replay-protected，并有 capability policy。
- Autofill assignment 必须绑定页面文档，Passkey private key 只留在 encrypted core/main signing path。
- Browser release 必须同时验证 extension ID、native-host install/uninstall 和 desktop protocol parity。
- 任意已获独立授权的 HTTP(S) 页面在用户打开验证码候选 UI 后都可能看到最近未过期验证码，这是
  为跨域事务邮件可用性接受的风险；Provider credential、邮件正文、收件地址和 subject 仍不得进入 Browser RPC。

## 被拒方案

- Extension 直接读写 Vault：扩大秘密持久化面并产生双写/锁定问题。
- 在 native host 中解密：transport helper 变成第二 Vault client。
- Desktop unlock 自动授权 extension：破坏表面隔离和 revoke 语义。
- 按发件域名与网站 origin 过滤邮箱 OTP：事务邮件域名不稳定，导致合法候选在验证码页面不可用。
