# Browser integration spec

拥有：`REQ-BROWSER-*`、`REQ-AUTOFILL-*`、`REQ-PASSKEY-001`、`REQ-EMAIL-003` 的浏览器详细机制。Extension 是运行中 desktop app 的 transient remote UI，不打开 Vault。当前唯一 broker 位于 Tauri Rust runtime；111/111 RPC v2 route/policy 自动化 parity 必须持续通过，真实 Chromium 与发布安装由 `AT-BROWSER-001` 验收，Firefox 由 `AT-BROWSER-FIREFOX-001` 验收。File dialog、biometric、clipboard、SSH scan、email、Vault Key 和 persistence 均在 active desktop privileged process。

## 权威实现定位

- RPC operation/limit：`apps/tauri-desktop/src/shared/browser-rpc.ts`
- authorization policy：`apps/tauri-desktop/src/shared/browser-rpc-policy.ts`
- workflow coverage：`apps/tauri-desktop/src/shared/browser-extension-capabilities.ts`
- desktop dispatcher/broker/session：`apps/tauri-desktop/src-tauri/src/browser_broker.rs`
- extension schema：`apps/browser-extension/src/lib/protocol.ts`
- connection owner：`apps/browser-extension/src/entrypoints/background.ts`
- discovery/fill：`apps/browser-extension/src/entrypoints/vaultmesh.content.ts`

以上文件拥有完整枚举/API；本 Spec 拥有跨文件行为和安全约束。

## 开发身份与 host

macOS 集成开发使用 `pnpm browser:dev`。该命令必须编排仓库的 `pnpm tauri:dev` 与 `pnpm extension:dev`，不得启动 `/Applications/VaultMesh.app` 代替 Tauri 开发运行时。命令必须先构建当前 workspace 的 debug Rust native host，等待 Tauri dev Broker 就绪并完成 Host 往返探测，再启动 WXT。

WXT 必须使用固定的专用 development profile；Host manifest 必须同时安装到该 profile 的 `NativeMessagingHosts`，不能依赖 WXT 临时 profile 或普通浏览器 profile。Extension key 与 native-host `allowed_origins` 必须派生同一固定 ID。任一开发子进程失败、退出或收到 Ctrl+C 时，根命令必须回收 Tauri、WXT、开发浏览器和 debug Host，不得留下后台进程。

使用其他 key 时设置 `WXT_CHROME_EXTENSION_KEY`；若同时设置 `VAULTMESH_BROWSER_EXTENSION_ID`，它必须等于派生 ID。只供本地解压安装的 Review package 必须显式选择 `VAULTMESH_EXTENSION_DISTRIBUTION=sideload-review`，复用仓库固定的公共 sideload key；商店或正式公开 release 必须提供独立 key。Packaged build 必须安装 host `com.vaultmesh.browser`；development registration 禁止进入 package。

## 跨浏览器身份、Native Host 与打包

Chrome/Chromium target 使用 MV3、固定 `WXT_CHROME_EXTENSION_KEY` 派生的 32 位 ID、
`minimum_chrome_version` 与 `webAuthenticationProxy`。Firefox target 使用 WXT Firefox MV2、固定
`browser_specific_settings.gecko.id`，并且必须省略上述 Chromium-only manifest 字段和 permission。
两个 target 共享 popup/background/content 源码、Browser RPC v2、瞬态状态与秘密边界；runtime 对缺失
`webAuthenticationProxy` 的既有 capability detection 必须保持 no-op，所以 Firefox 不宣称 Passkey proxy。

Native Messaging 使用浏览器特定 manifest，不能共享一份宽松 allowlist：

- Chrome/Edge manifest 使用唯一 `allowed_origins: ["chrome-extension://<compiled-id>/"]`。
- Firefox manifest 使用唯一 `allowed_extensions: ["<compiled-gecko-id>"]`。macOS 位于用户级 Mozilla
  `NativeMessagingHosts` 目录；Windows 由 HKCU Mozilla `NativeMessagingHosts` registry 指向该 manifest。
- 同一个 Rust Host binary 必须先识别浏览器官方启动参数，再读取 pairing secret。Chrome 只接受精确
  origin；Firefox 只接受精确 installed manifest path 加 Gecko ID。缺参、未知 ID、错误路径或混合参数
  必须返回安全失败，不能尝试兼容或降级。
- Chrome 与 Firefox Host connection 继续使用既有每连接 authorization/session 生命周期；任一浏览器
  都不得把配对状态、Vault response 或受保护值写入 extension storage。

`pnpm extension:release:zip:all` 必须从同一 source/version 生成命名稳定的 Chrome 与 Firefox ZIP，
解析内部 manifest、验证目标/身份/permission/版本、执行 ZIP 完整性检查，并排除 source map、环境文件、
凭据和非发布输出。完整 Review workflow 显式使用 `sideload-review` 身份，在三个桌面目标成功后把两个
本地安装 ZIP 发布到同一版本的不可变 R2 `releases/v<version>/` 路径；publisher 必须验证公开 URL 下载
内容与构建产物逐字节一致，并在 Actions 摘要输出 Chrome/Chromium 与 Firefox 的直接链接。相同 ZIP
也加入 GitHub Draft，但不进入桌面 updater manifest、不提交任何浏览器商店。Firefox store source ZIP
可以作为 CI 内部构建输出，但不冒充安装包或商店审核完成。

## Transport 与 authorization

- Protocol v2 message 必须 size-bounded、UUID-correlated、HMAC-authenticated、expiring、replay-protected。
- Background worker 是 long-lived native-messaging port 的唯一所有者；popup 关闭不终止 desktop connection。
- Desktop 和 extension unlock 独立；revoke 立即使 browser session/pending work 失效。
- Operation 必须分类；mutation 需要 fresh gesture，destructive operation 还需要 command-bound one-use confirmation。
- Import/SSH content 保持在 expiring main-process session，只向扩展返回 opaque ID 和安全 preview；response 不含 local path。
- 普通 list/detail metadata 必须省略 protected value。Login `items.detail` 因包含 custom-field value，明确分类为 fresh-gesture `pageDisclosure`，不是普通 metadata；其 response 只用于当前 popup 操作，不得进入 extension storage、持久化 UI state、日志或 crash data。
- Lock、disconnect、revoke、shutdown、expiry、navigation、page hide/unload 清除相关 pending state。
- Version mismatch 返回 `update-required`，禁止 downgrade。
- Tauri desktop handle 与 browser handle 必须分离；任一 surface 的 unlock/lock 不自动改变
  另一 surface。Rust route/policy 必须与本规格上方的 TypeScript owner 做可执行 parity 校验；
  未覆盖的 operation 必须 fail closed，不能声称 parity。

## Extension 偏好与瞬态状态

Extension local storage 只可以保存 schema-validated、renderer-safe 的用户偏好：生成器最后类型与
四类生成参数、插件锁定策略，以及按 exact origin 记住的 opaque Login ID。桌面安全设置、PIN、
生物识别与配对由 privileged desktop runtime 持久化，extension 只通过 typed RPC 读取和更新，
不得建立第二份本地所有者。

生成结果与历史、Vault workspace、搜索和类型筛选、编辑/捕获草稿、主密码/PIN 输入、受保护字段、
填充值、pending confirmation、assignment、authorization/session material 必须保持瞬态。无效、
未知版本或不可读的偏好必须回落到安全默认值，不能阻止生成、discovery 或显式 fill。

## Recovery-code 文件导入

插件 Login 编辑器可在用户明确点击后调用 `items.recovery-codes.import-file`。该 operation 必须分类为需要 browser unlock、fresh gesture 和 command-bound one-use confirmation 的 system-dialog；在打开文件框前，Tauri platform 必须恢复、显示并聚焦 `main` 窗口，然后将文件选择框和删除确认框都绑定为该窗口的原生子对话框。无法取得或聚焦主窗口时必须 fail closed，不得在浏览器后方打开无 parent 对话框。文件选择、有界 UTF-8 读取、格式识别、删除确认、摘要重验和删除全部由 Tauri Rust platform 执行。

普通文本必须继续按换行解析、忽略全空白行并保留每个非空码的内容。完整识别到由 `N. DDDD DDDD` 条目组成的 Google 编号下载表时，parser 必须忽略表外标题和说明、拆分同一行的多个条目并按连续编号排序；编号缺失或重复必须拒绝，不能静默回退为普通文本而把说明文字当作恢复码。格式识别不得依赖账户名、页面语言或真实恢复码值，测试只能使用虚构码。

响应只可包含解析后的恢复码、basename 和 `deleted`/`kept`/`failed` 状态，不得包含完整路径、文件 bytes 或摘要。Codes 只能进入当前 popup 的 Login 编辑草稿，离开编辑器、popup 关闭、锁定、断开、取消或保存后必须清除，不得进入 extension storage、content script、日志、通知正文或 crash data。用户选择保留、删除前文件变化或 `remove_file` 失败都必须保留源文件并返回非敏感状态。

## Recovery-code 查看与复制

插件 Login 编辑器可以在存在性摘要为真时显式调用 `items.recovery-codes` 查看全部恢复码，或调用 `items.copy-recovery-code` 复制指定索引。两个 operation 都必须要求 browser unlock、fresh gesture，并且每次请求都必须携带用户刚输入的主密码，由 core 无条件重新验证；查看后发起复制也必须再次输入并验证，不能复用查看授权或 Login 普通 re-prompt 设置。

查看响应只可包含有界恢复码列表，并且只能保存在当前 popup 组件内存；隐藏、离开编辑器、popup 关闭、锁定、断开或失败必须清除，不得进入 background、content script、extension storage、日志、通知或 crash data。复制必须由 Tauri Rust platform 从 core 读取指定索引并直接写入带过期清理的系统剪贴板，响应只返回非敏感的 `clearsAt`，不得把被复制的恢复码再次返回插件。非法索引、错误密码、锁定或校验失败不得披露值或修改剪贴板。

## Discovery 与 fill

Discovery 只允许 field metadata、origin/document identity、handle 和 empty bit，禁止当前 value。Top-page origin 与 target-frame origin 必须在 discovery、authorization 和 assignment 全程分离绑定。

场景识别必须以字段角色和表单簇为先：content script 在同一真实 form，或无 form 时的最小可见伪表单容器内识别 account、current-password、new-password、confirmation-password 和 OTP；再按显式 `autocomplete`/直接字段元数据、同簇密码结构、form action/page path/submit 语义、排除导航链接后的弱上下文分层判定。弱页面文案不得跨表单覆盖局部强信号，尤其“注册/创建账户”导航链接不得把账号 + 当前密码 + 登录提交按钮的簇判为 signup。冲突或低置信度必须保守回落；只有可靠 new-password 角色可以展示密码生成器。可靠 password-change 簇内的显式 Login 选择成功填入 current-password 后，content script 可以按本地生成器设置生成一次新密码，并且必须只同步写入同簇、仍为空的 new-password/confirmation-password；任一目标已有值时不得自动生成或覆盖。诊断结果只能包含有限理由代码和分数，不得包含字段 value。

Content script 可以处理标准 input、textarea、select、contenteditable、open shadow root、extension 可访问的 closed root 以及允许执行的 same/cross-origin frame。DOM mutation 和 same-document navigation 后 debounce rescan。Canvas-only control 和不可访问 closed root 为 unsupported。

写入必须使用 native value setter 并 dispatch `input`/`change`。Page-load fill 仅限 login/OTP context、stored preference、one-shot 和 empty field；signup、password change/reset、card、identity、secret、SSH、re-prompt 和 overwrite 均禁止自动 disclosure。排序：exact path > exact origin > same-protocol host，remembered login 优先。

Popup 显式选择调用 `browser.autofill.execute`；Tauri Rust broker 在返回 short-lived one-use assignment 前 revalidate item/document。Card 必须验证 current master password。Legacy `browser.fill.request` 可以打开 desktop approval dialog，但不是当前 popup selection 主路径。所有 fill 都禁止 submit。

至少一个 assignment 成功后只记录 encrypted bounded audit：time、origin、item kind/ID/title、field count。禁止 field name/value。

## Email OTP 候选与填充

Content script 只在可信用户点击语义明确的获取/发送/重发验证码 control 后请求 `email.otp.watch`；desktop 必须立即增量检查并启动或刷新 90 秒、3 秒间隔的 bounded boost。重复点击刷新期限，普通页面检测不得无限维持高频轮询。

插件 popup 打开或用户点击 OTP 字段页内图标时可以通过 `email.otp.candidates` 查询当前 HTTP(S) origin。Rust Email OTP service 必须拥有候选和 expiry，验证 origin 是有效 HTTP(S) origin 后返回全部未过期候选的有界 code/source/received/expiry 摘要，不得按当前网站与 sender domain 过滤；account address、subject、message ID、Provider credential 和邮件正文不得进入 Browser RPC。Popup 或页内候选关闭、隐藏、导航、锁定或断开清除对应组件内候选，禁止写入 background cache 或 extension storage；跨 origin frame 的页内查询必须 fail closed。

用户在 popup 或 OTP 字段页内列表点击候选时调用 `email.otp.fill`；页内选择消息只可携带 candidate ID，不得回传 code。Background 重新 discovery 选择来源 tab 的当前 same-origin frame，desktop 按 candidate ID、expiry、origin、tab/frame/document/handle 重验，但 origin 只绑定 assignment、不用于候选过滤，并只为 empty、text-compatible OTP control 返回短时单次 assignment；不得覆盖非空字段、填入非 OTP control、记录 code/audit 或提交表单。Navigation、重复 discovery、candidate expiry、lock、revoke、disconnect、失败和成功后的重复执行必须 fail closed。

## Capture

Submission observation 可以对新生成或用户编辑的 login/card/identity 显示 Save/Ignore。只有用户确认才写入；观察到 submit 不等于 server success。未修改的 autofilled password 不得重复 capture。

插件从网页识别出的 developer/service secret 只有在用户确认后才可以通过 desktop privileged operation 写入加密 Vault，创建时 `masterPasswordReprompt` 必须默认为 `false`；用户可以在项目编辑器中显式开启二次验证，既有项目不得被改写。

## Authenticator QR capture

Content script 不得因为动态或静态页面出现疑似验证器 QR 而插入 VaultMesh 按钮、菜单或其他
QR UI，也不得仅为 QR 发现持续观察或修改网页。只有用户在插件 popup 内主动发起当前页面识别，
或在 Login 编辑器点击“从当前网页扫描验证器二维码”后，content script 才可以对当前 HTTP(S)
tab 的可访问 frame 执行一次可见 QR 扫描。隐藏来源、非 TOTP QR、跨 origin 不可读取图像和不受
支持的 TOTP profile 必须 fail closed。

扫描得到一个 TOTP URI 时，把它加入当前 popup 的捕获或 Login 编辑草稿；多个结果必须让用户明确选择。目标
Login 已有 TOTP 时必须确认覆盖，但扫描本身不得写入 Vault。只有用户保存 Login 后才复用既有
`items.update`，保留其他字段，并由 core 规范化 TOTP 和执行原子持久化。不得静默保存、创建
独立 authenticator secret 或提交网站表单。

TOTP URI 只可在本次 content response、当前 popup React state 和 desktop privileged update 的
有界内存中短暂存在；不得进入网页 DOM、background inline capture registry、extension storage、
日志、通知正文或非秘密 settings。关闭 popup、取消编辑、lock、disconnect、failure 或保存完成
后不得保留额外副本。已有 OTP discovery/fill assignment 行为不变。

## Passkey

Chromium 127+ WebAuthn proxy 把 ES256 credential 存为 protected `authenticator-key` secret，并在 active desktop privileged process 签名。创建或导入时 Extension 可以提供当前 origin 记住的默认 Login opaque ID，但 Tauri broker 必须按 RP/origin 重新验证后才能写入关联；无有效默认值时可以唯一用户名匹配，仍不确定时表示为 Passkey-only Login，不进入普通 Secret/密钥分类。每次 registration/assertion 必须显示 RP/origin/account context 的 native confirmation。Extension lock detach proxy。Conditional mediation、largeBlob/PRF 不在当前范围。

新版 registration 必须从创建开始设置不可变的 BE 标志，签名计数固定为零；BS 只有在已授权对端持久化成功（包含重试时版本清单确认）后才能为真。旧 BE=0 凭据必须保持本机使用，重新注册后才可参与同步。同步 Passkey 不传递浏览器授权，使用时仍执行上述验证与确认。完整备份、复制与恢复规则由 `lan-vault-sync.md` 和 `ADR-0019` 拥有。

## 验证

```sh
pnpm extension:typecheck
pnpm extension:test
pnpm extension:build
pnpm verify:browser-parity
pnpm tauri:test
```

Public RPC operation 缺少 policy、dispatcher 或 extension workflow route 时 parity 必须失败。
