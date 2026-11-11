# Browser integration spec

拥有：`REQ-BROWSER-*`、`REQ-AUTOFILL-*`、`REQ-PASSKEY-001`、`REQ-EMAIL-003` 的浏览器详细机制。Extension 是运行中 desktop app 的 transient remote UI，不打开 Vault。当前唯一 broker owner 位于 Tauri Rust runtime；全部 RPC v2 route/policy 自动化 parity 必须持续通过，真实 Chromium 与发布安装由 `AT-BROWSER-001` 验收，Firefox 由 `AT-BROWSER-FIREFOX-001` 验收。File dialog、biometric、clipboard、SSH scan、email、Vault Key 和 persistence 均在 active desktop privileged process。

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

使用其他 key 时设置 `WXT_CHROME_EXTENSION_KEY`；若同时设置 `VAULTMESH_BROWSER_EXTENSION_ID`，它必须等于派生 ID。仓库固定的公共 key 即 Chrome Web Store 条目公钥（ID `bdneegbnjbheblmamalplnddbodcghbg`）；开发、Review 本地解压包与商店/正式 release 必须共用该身份，Review package 仍可显式选择 `VAULTMESH_EXTENSION_DISTRIBUTION=sideload-review`。Packaged build 必须安装 host `com.vaultmesh.browser`；development registration 禁止进入 package。

## 跨浏览器身份、Native Host 与打包

Chrome/Chromium target 使用 MV3、固定 `WXT_CHROME_EXTENSION_KEY` 派生的 32 位 ID、
`minimum_chrome_version`，且任何 target 都不得声明 `webAuthenticationProxy`。Firefox target 使用 WXT Firefox MV2、固定
`browser_specific_settings.gecko.id`，并且必须省略上述 Chromium-only manifest 字段。
两个 target 共享 popup/background/content 源码、Browser RPC v2、瞬态状态与秘密边界；Passkey shim 与 bridge
只进入 Chromium target，所以 Firefox 不宣称 Passkey 支持。

Native Messaging 使用浏览器特定 manifest，不能共享一份宽松 allowlist：

- Chrome/Edge/Brave/Arc/Vivaldi/Chromium manifest 使用唯一 `allowed_origins: ["chrome-extension://<compiled-id>/"]`。
- Firefox manifest 使用唯一 `allowed_extensions: ["<compiled-gecko-id>"]`。macOS 位于用户级 Mozilla
  `NativeMessagingHosts` 目录；Windows 由 HKCU Mozilla `NativeMessagingHosts` registry 指向该 manifest。
- 同一个 Rust Host binary 必须先识别浏览器官方启动参数。Chromium 系列接受 `[origin]` 或 `[origin, "--parent-window=..."]`；Firefox 只接受精确 installed manifest path 加 Gecko ID。缺参、未知 ID、错误路径或混合参数必须返回安全失败。
- Native Host 采用零文件、零钥匙串无状态中继架构（ADR-0056），不再读写 `browser-host-config.json` 或系统钥匙串。Host 启动时在 `127.0.0.1:42800..=42850` 扫描发现桌面端本地回环 API（`/discover`），并将 stdin/stdout 消息无状态转发至桌面端 `/rpc`。
- 本地回环 HTTP API 由桌面主进程管理，严禁提供 CORS 放行头；凡包含 `Origin`、`Sec-Fetch-*` 头或 `OPTIONS` 探测方法的请求直接返回 403 Forbidden，杜绝恶意网页扫描探测。
- Chrome 与 Firefox Host connection 继续使用既有每连接 authorization/session 生命周期；任一浏览器
  都不得把配对状态、Vault response 或受保护值写入 extension storage。

macOS/Windows 正式构建每次启动必须从当前 desktop executable 目录定位包内 `vaultmesh-native-host`，确认其为非空普通可执行文件，再幂等为所有已安装的受支持浏览器（Chrome、Edge、Firefox、Brave、Arc、Vivaldi、Chromium）写入生产 Host manifest。App 被移动后必须刷新 manifest 路径；文件缺失或旧路径必须自动修复，内容正确时不得重写。桌面端提供统一的 Doctor 诊断体系与 `desktop.browser-integration.retry` 自动修复通道，并只读检测各浏览器 Profile 下的 VaultMesh 扩展安装状态；当检测到浏览器已安装但未安装插件时，提供 `desktop.browser-integration.open-store` 一键打开安装页面（Chrome 打开官方 Chrome Web Store 页面，其他尚未上架商店的浏览器打开当前版本对应的 GitHub Release 发布页）。普通与 updater App bundle 必须包含 Native Host。显式卸载注册前必须先退出客户端，否则后续正式版启动会重新注册。

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
- 系统锁定必须清除 Browser 解锁与待执行确认，保留配对身份；睡眠恢复必须先清除各入口明文授权。普通 desktop 锁定不替代 Browser 独立锁定。LAN 密文收发不授予 Browser 权限，解锁会话接收合并后必须使 fill/confirmation 缓存失效并通知界面刷新。
- Operation 必须分类；mutation 需要 fresh gesture，destructive operation 还需要 command-bound one-use confirmation。
- Import/SSH content 保持在 expiring main-process session，只向扩展返回 opaque ID 和安全 preview；response 不含 local path。
- 普通 list/detail metadata 必须省略 protected value。Login `items.detail` 因包含 custom-field value，明确分类为 fresh-gesture `pageDisclosure`，不是普通 metadata；其 response 只用于当前 popup 操作，不得进入 extension storage、持久化 UI state、日志或 crash data。
- Lock、disconnect、revoke、shutdown、expiry、navigation、page hide/unload 清除相关 pending state。
- Popup 事件轮询必须识别 Broker 的 `vault-changed` 并刷新当前已授权的安全摘要；已有锁定事件在重新解锁后可以作为历史游标读取，不能当作传输故障。
- Version mismatch 返回 `update-required`，禁止 downgrade。
- Tauri desktop handle 与 browser handle 必须分离；任一 surface 的 unlock/lock 不自动改变
  另一 surface。Rust route/policy 必须与本规格上方的 TypeScript owner 做可执行 parity 校验；
  未覆盖的 operation 必须 fail closed，不能声称 parity。

## Popup Touch ID

当前 WXT 插件必须通过 Rust broker 跟随 desktop 的当前 Vault Touch ID 配置（ADR-0051），不得复制设置或 Vault Key 到 extension。锁定页首次可见且用户尚未选择输入方式时自动触发一次系统弹窗，取消/失败后只允许显式重试。桌面和 Browser 的解锁授权继续独立；主窗口嵌入式认证和 Agent 认证保持各自生命周期。

Rust 必须通过 start/poll/cancel 会话管理原生 LAContext。Start 需要可信 popup 的 fresh gesture，poll/cancel 必须携带本轮随机 session ID 并通过既有连接鉴权；poll 的认证提交不是普通 metadata。会话最长 30 秒，poll 刷新 3 秒租约，关闭/隐藏、回退、断连、系统锁定、撤销或租约到期必须取消。仅有效 poll 可以在重新检查当前 Vault 和 credential ID 后短时读取凭据并提交 Browser unlock；旧回调不得自行读取凭据或发布授权。无活跃 popup 不能靠后台连接保留待提交认证。Background 必须在 Native Host 断连时丢弃当前认证 ID，重连不得继续旧认证轮询；无法发送取消时由 Rust 租约清理原生会话。

旧 WXT 生物识别启用/关闭操作必须安全拒绝并指向桌面设置，旧独立凭据保留以支持代码回滚但不再参与当前认证。实验副本身份仍维持独立凭据，不继承桌面授权或配置。Windows 首版继续明确不支持；PIN 与主密码保留。

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

页内选择与页面自动填充必须携带仅在当前 content script 内可解析的 document/target 引用；本地引用最多 64 个，60 秒失效，只保存 DOM 归属、不保存字段值。Background 必须限定发送者 frame，二次确认必须保留该引用及已有账号覆盖策略；失效引用必须返回空 discovery，禁止扩大到其他表单或 frame。最终写入过程中必须重验目标资格、文档和原表单归属。Popup 无页内目标的显式选择仍使用既有当前 tab discovery；这些引用不改变 native Browser RPC。

场景识别必须以字段角色和表单簇为先：content script 在同一真实 form，或无 form 时的最小可见伪表单容器内识别 account、current-password、new-password、confirmation-password 和 OTP；再按显式 `autocomplete`/直接字段元数据、同簇密码结构、form action/page path/submit 语义、排除导航链接后的弱上下文分层判定。弱页面文案不得跨表单覆盖局部强信号，尤其“注册/创建账户”导航链接不得把账号 + 当前密码 + 登录提交按钮的簇判为 signup。冲突或低置信度必须保守回落；只有可靠 new-password 角色可以展示密码生成器。可靠 password-change 簇内的显式 Login 选择成功填入 current-password 后，content script 可以按本地生成器设置生成一次新密码，并且必须只同步写入同簇、仍为空的 new-password/confirmation-password；任一目标已有值时不得自动生成或覆盖。诊断结果只能包含有限理由代码和分数，不得包含字段 value。

Content script 可以处理标准 input、textarea、select、contenteditable、open shadow root、extension 可访问的 closed root 以及允许执行的 same/cross-origin frame。DOM mutation 不得触发整页 discovery；same-document navigation、BFCache 恢复和显式 rescan 请求各重新执行一次发现。新增、显现或语义改变的登录/OTP 表单必须在固定 100 毫秒窗口内通过局部无值发现发送 ready，background 才开始有界轮询；不得依赖初始 ready 或手工 rescan 才启动。局部 pass 必须覆盖发现、角色/簇判断及目标采集，无 form 控件不得隐式枚举 document；已有伪表单的分步插入必须保留原簇归属，pass 退出后的正常 target resolve 必须仍然成立。Canvas-only control 和不可访问 closed root 为 unsupported。

Rescan 调度必须按 mutation 记录判定相关性：字段、表单或包含字段的容器的增删，以及字段自身或含字段容器的属性变化与语义文本变化，只可以触发局部无值发现与当前字段的有界重验；非字段节点的 `class`/`style` churn、无关列表标记的增删和插件自身注入 UI 的变化不得触发任何工作。任何 mutation 都不得触发整页 `querySelectorAll("*")` 遍历：每个非插件 UI 的新插入子树都必须观察其中的 shadow root（观察代价与被插入内容成正比，不能被字段相关性门禁跳过）；局部发现与已知局部簇追踪各最多 256 个 scope，固定窗口不得因连续 mutation 无限延期，导航、BFCache 冻结及 dispose 必须清理队列。字段失去资格时必须在 100 毫秒内撤下图标和菜单，相关性必须沿 composed 祖先跨 ShadowRoot.host，并覆盖同簇标签等语义变化。单次 discovery 必须在同一 pass 内一次性枚举文档控件，并复用该 pass 的角色、簇、可见性和候选提交控件结论；DOM 访问量必须与文档规模成正比，禁止按字段数 × 祖先深度重复遍历全文档。输入事件只允许更新本次填充已记录控件的编辑位，不得重新运行字段分类或 discovery。回归以 `CT-AUTOFILL-001` 的 DOM 工作计数为准。

内联资格判断必须先排除非填充用途和不可交互字段，再检查字段自身的标准 autocomplete、词语边界和同簇角色；不得仅以 checkout、SSH 或 developer-secret 场景为整个表单授予同一填充类型。Discovery 可以保留供显式 custom-field 匹配的未知字段，但这不自动赋予其页内图标。Mutation 后与候选响应落地前必须重验资格。菜单必须支持 Escape、Tab、方向键与输入法组合输入，位置必须限制在当前 frame 视口内。

Content 与 Rust 字段排除词必须共享 `apps/tauri-desktop/src/shared/autofill-field-policy.json`；英文启发式必须尊重词语边界，允许 camelCase、下划线和空格分词，不得以 `statement` 包含 `state` 等子串推导字段。小尺寸 frame 内菜单必须限制宽高并可滚动；上下均不足时可以覆盖当前 frame 内的字段，不得向其他 frame 转发候选或受保护值。菜单必须随 visual viewport 平移或缩放重新定位。

自定义元素延迟 attachShadow 必须使用有数量和期限上限的追踪：最多 256 个待处理宿主、每批 64 个轮转，未注册阶段最多 60 秒，注册后等待 root 最多 30 秒；轮询间隔必须限制在 250–2000 毫秒。超时宿主不得因普通重复扫描无限重启计时，页面上下文更新可以重新开始。Shadow root 内的 submit/formdata/keydown/focus/input/click 监听必须在卸载时清理，composed 事件必须去重。Assignment 开始前必须消费对应 handle 集；旧填充结束不得清除后续 discovery。History、hash、BFCache 和最终写入前的 URL 检查必须使旧文档身份失效。

写入必须使用 native value setter 并 dispatch `input`/`change`。Page-load fill 仅限浏览器会话已解锁（`requiresUnlock === false`）、login/OTP context、stored preference、one-shot 和 empty field；锁定状态、signup、password change/reset、card、identity、secret、SSH、re-prompt 和 overwrite 均禁止自动 disclosure。排序：exact path > exact origin > same-protocol host，remembered login 优先。

桌面端在 `device-credentials.enc`（作用域 `com.vaultmesh.desktop.browser-autofill-preview`，ADR-0055）中维护与当前 `vault.enc` SHA-256 绑定的无秘密自动填充候选预览索引（仅保存 `id`、`kind`、`title`、`subtitle`、归一化匹配站点、`autofillOnPageLoad`、`masterPasswordReprompt` 与布尔标志 `hasTotpSecret`）。当 `BrowserBrokerCore` 锁定时，`browser.autofill.candidates` 先校验磁盘 `vault.enc` 的实时 SHA-256 与索引一致，再返回当前页面匹配的候选并标记 `requiresUnlock: true`。用户在网页聚焦输入框或点击内联图标时直接展示候选浮层；在登录账号/邮箱输入框键入字符时，按 `subtitle` 前缀、邮箱 `@` 前本地部分前缀或 `title` 子串实时过滤候选，无匹配时自动收起浮层。

Popup 或页内显式选择调用 `browser.autofill.execute`；当 `BrowserBrokerCore` 处于锁定状态（或条目要求 `masterPasswordReprompt` 且未提供 `masterPassword`）时，Broker 唤起桌面端统一受保护临时解锁窗口（`agent-unlock`）执行单次授权（Touch ID 自动触发或同窗口 PIN / 主密码回退；`masterPasswordReprompt` 条目直接要求主密码），在局部临时 `DesktopRuntime` 中完成重验并生成单次 `ApprovedFill` 后立即销毁临时 Runtime，不解锁 `BrowserBrokerCore` 会话且不写入 `popupWorkspaceCache`。Card 填充在已解锁会话中仍验证 current master password（或通过上述桌面临时解锁窗口验证主密码）。Legacy `browser.fill.request` 可以打开 desktop approval dialog，但不是当前主路径。所有 fill 都禁止 submit。

至少一个 assignment 成功后只记录 encrypted bounded audit：time、origin、item kind/ID/title、field count。禁止 field name/value。

生成器复制必须通过解锁且 fresh-gesture 的有界桌面操作写入过期清理剪贴板，仅返回清理期限。插入必须来自可信 popup，绑定当前 tab/frame/document 及短期合格空目标；密码/口令只允许可靠的空新密码和同簇确认框，用户名只允许空用户名字段；UUID 使用用户显式选择的空文本目标。结果不得写入后台缓存或持久化存储，取消、隐藏、锁定、超时与迟到响应必须清理且不得自动重试。

## Email OTP 候选与填充

Content script 只在可信用户点击语义明确的获取/发送/重发验证码 control 后请求 `email.otp.watch`；desktop 必须立即增量检查并启动或刷新 90 秒、3 秒间隔的 bounded boost。重复点击刷新期限，普通页面检测不得无限维持高频轮询。

插件 popup 打开或用户点击 OTP 字段页内图标时可以通过 `email.otp.candidates` 查询当前 HTTP(S) origin。Rust Email OTP service 必须拥有候选和 expiry，验证 origin 是有效 HTTP(S) origin 后返回全部未过期候选的有界 code/source/received/expiry 摘要，不得按当前网站与 sender domain 过滤；account address、subject、message ID、Provider credential 和邮件正文不得进入 Browser RPC。Popup 或页内候选关闭、隐藏、导航、锁定或断开清除对应组件内候选，禁止写入 background cache 或 extension storage；跨 origin frame 的页内查询必须 fail closed。

用户在 popup 或 OTP 字段页内列表点击候选时调用 `email.otp.fill`；页内选择消息只可携带 candidate ID 与本地目标引用，不得回传 code。Background 重新 discovery 选择来源 tab 的当前 same-origin frame，页内选择必须进一步限定来源 frame 和表单簇；desktop 按 candidate ID、expiry、origin、tab/frame/document/handle 重验，但 origin 只绑定 assignment、不用于候选过滤，并只为 empty、text-compatible OTP control 返回短时单次 assignment；不得覆盖非空字段、填入非 OTP control、记录 code/audit 或提交表单。Navigation、重复 discovery、candidate expiry、lock、revoke、disconnect、失败和成功后的重复执行必须 fail closed。

## Capture

Submission observation 可以对新生成或用户编辑的 login/card/identity/SSH/Secret 显示 Save/Ignore。只有用户确认才写入；观察到 submit 不等于 server success。未修改的 autofilled password 不得重复 capture。

SSH/Secret 捕获复用相同来源匹配与 Save 生命周期，且仅限 HTTPS；SSH account/key 混合来源必须拒绝，缺少必填主机/账号或密钥不得虚构。Secret 的具体类型必须在确认 UI 明示，多个受保护类型来源必须拒绝，更新必须重验现有 kind 且不能转换。新 Secret 的 website 绑定捕获 origin，默认不要求二次验证；更新保留 website、scopes 及二次验证。捕获只保存用户实际编辑过的字段，未编辑受保护值不得重新读取或清除。

Capture 与生成填充必须复用局部表单归属，包含 `form=` 关联控件和可访问 Shadow DOM；非 composed submit 在对应 root 内监听。SPA 保存点击必须在页面处理器可能同步销毁输入框前提取候选，捕获仍仅触发用户确认。生成记录必须绑定所属表单，不能在相邻表单提交时使用；字段实际提交的新密码优先于先前生成记录。

原生 `form.submit()` 绕过 submit 事件时可以观察 formdata，但只能从关联 DOM 表单提取支持的候选，不得序列化任意 FormData 项；脚本构造 FormData 也可能产生该事件，因此仍不得推断登录成功。Enter 观察必须排除 IME、已取消事件、打开的候选菜单、OTP 和无效表单；input 型保存按钮必须按其 value 判定动作。多个新密码/确认字段存在空值或不一致时必须拒绝密码候选。

同一 capture 从 popup、通知和独立确认窗口并发确认时必须共享一次正在进行的保存；完成或失败后清除该请求引用。过期、已消费或已取消的 capture 不得重新执行 mutation。

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

TOTP URI 只可在本次 content response、当前 popup 组件 state 和 desktop privileged update 的
有界内存中短暂存在；不得进入网页 DOM、background inline capture registry、extension storage、
日志、通知正文或非秘密 settings。关闭 popup、取消编辑、lock、disconnect、failure 或保存完成
后不得保留额外副本。已有 OTP discovery/fill assignment 行为不变。

## Passkey

Chromium 127+ 页面级 WebAuthn shim 把 ES256 credential 存为 protected `authenticator-key` secret，并在 active desktop privileged process 签名。创建或导入时 Extension 可以提供当前 origin 记住的默认 Login opaque ID，但 Tauri broker 必须按 RP/origin 重新验证后才能写入关联；无有效默认值时可以唯一用户名匹配，仍不确定时表示为 Passkey-only Login，不进入普通 Secret/密钥分类。每次 registration/assertion 必须显示 RP/origin/account context 的 native confirmation。

Extension 不使用 `chrome.webAuthenticationProxy`，不得持有浏览器全局 WebAuthn 状态（ADR-0057）。Chromium target 以 `world: "MAIN"`、`document_start`、所有 frame 注入 shim，包装 `CredentialsContainer.prototype.create/get`；隔离世界 bridge 经 `runtime.sendMessage` 交给 background。MAIN world 只序列化公开请求参数与还原公开响应，不持有秘密；`origin` 与 `sameOriginWithAncestors` 必须由 background 依据浏览器验证的 `sender` 与 `webNavigation` 帧树写入，覆盖页面提供的同名字段。只有 frame 与全部祖先同源时才由 VaultMesh 处理，其余 frame 交给浏览器执行 permissions policy。

每个请求单独决策，需要回退时必须在同一次 `navigator.credentials` 调用内调用原生函数，不得要求网站或用户重试：通行密钥接管关闭、未配对、桌面不可达、`mediation: "conditional"`、依赖扩展结果的请求（`prf`、`largeBlob`、`hmacCreateSecret`、`credBlob`、`getCredBlob`、`payment`，或 `enforceCredentialProtectionPolicy` 为 true；其余扩展只作建议被忽略，仅转发 `appid` 与 `credProps`）、请求超限、跨源 frame 与 `passkeys.probe` 返回 `unavailable` 都直接回退。`probe` 为 `available` 或 `unknown` 时，background 必须优先在发起请求的标签页顶层 frame 内显示页面对话框（closed shadow root，仅响应受信任事件，Escape 取消），让用户选择“使用 VaultMesh”或“使用浏览器/系统”或取消，`create` 同样每次选择；页面无法显示时才回退到工具栏 popup/独立窗口。页面对话框只回答所属标签页的提示，不得输入或接收主密码、PIN 或生物识别，锁定时只提供“打开解锁窗口”；选择可以按 origin 与操作（create/get）记住，记住的值只保存该非秘密 enum，设置页可以全部清除。选择 VaultMesh 且 Vault 锁定时进入解锁等待，用户可以改用浏览器/系统；等待最长 5 分钟，超时与用户取消都以 `NotAllowedError` 结束，改用浏览器/系统与无匹配不是错误。页面 `AbortSignal`、导航、标签页关闭必须取消该请求拥有的等待。每次不由 VaultMesh 响应的决策必须向 background/页面控制台输出不含请求内容的原因码，便于诊断。索引只保存 RP ID、credential ID、account、origin、item ID 等非秘密路由元数据，并绑定当前 Vault 路径与文件摘要；索引不可用或过期时 `probe` 保守返回 `unknown`，由 `passkeys.get` 严格重验，无匹配仍回退。插件安全策略提供“接管网页通行密钥请求”开关（沿用 `passkeyProxyEnabled` 存储字段）；关闭时所有请求直接回退。能力查询 `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable` 与 `getClientCapabilities` 只在浏览器自己回答“没有平台认证器”时才由 shim 补位：背景确认接管开启、同源 frame 链且桌面端已配对可达（锁定也算可用）后，把 `userVerifyingPlatformAuthenticator`/`passkeyPlatformAuthenticator` 报告为可用，其余能力字段不变；浏览器已回答“有”时不得询问或改写，可用性结果只缓存 10 秒。这使依据该查询决定是否开始创建的网站（如 Google）仍会向 VaultMesh 发起请求，实际由用户在对话框中选择提供方。Firefox target 不包含 shim 与 bridge。

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

## 已配对设备填充互通

REQ-DEVICE-ASSIST-001 / REQ-ANDROID-026 与 [独立互通规格](../specs/device-fill-assist.md) 定义逐设备一次授权、锁屏号码/短信交付及短时秘密生命周期。既有禁止 RECEIVE_SMS 的条款限于手机本地 Autofill；独立互通服务仅在用户主动启用后可以请求 RECEIVE_SMS，不使用 READ_SMS。短信正文仅本机瞬态解析，验证码不进入 Vault、备份、日志、同步或普通 DTO。系统限制自动读取时使用显式手动交付。
