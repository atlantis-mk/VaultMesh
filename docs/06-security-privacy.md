# 安全与隐私

## 安全目标

复制的 Vault 文件在没有主密码时不可读取或无检测篡改；锁定应用不能保留访问受保护值的授权 UI 路径。

范围内风险：offline guessing、ciphertext/header modification、nonce 生命周期、日志/源码/UI/extension storage 泄漏、未启用平台可用的窗口内容捕获保护、desktop/browser/page 授权混淆、RPC replay/expiry/origin substitution、失败提交回滚。

范围外风险：已被攻陷的 OS/process/browser/keylogger/accessibility tool、攻击者观察已授权 session、用户提交秘密后的远端服务泄漏、当前范围外的 sync/share/account recovery。

## LAN peer pairing

LAN peer discovery 默认关闭且只在用户显式开启的有限窗口内运行。mDNS 记录是未认证输入，不能包含用户、主机、Vault 或秘密数据，也不能单独授予信任。首次 TLS 会话必须由双方核对同一安全短码并确认；双方同时发起时只保留按临时实例 ID 确定的规范 TLS 会话，竞争会话不得形成第二个确认或错误地覆盖规范会话状态。双方还必须交换本地持久化成功状态，任一端失败时不得进入 connected。已配对身份固定到 OS-protected proof，证书漂移、记录损坏、取消、超时或撤销均拒绝。LAN service 不接触 Vault runtime、Agent broker、Browser RPC、clipboard、renderer persistence、analytics 或 crash payload。

## Vault 与文件边界

- `vault-core` 唯一拥有加密、serialization、validation、unlocked state 和 rollback。
- 主密码不写盘；没有恢复后门；backup 仍需主密码。
- Mutation 只有在原子文件提交成功后才发布新内存状态。
- Format/KDF 规则见 `docs/05-data-model.md` 和 `ADR-0001`。

## Desktop WebView 边界

- API request workbench 的 WebView 只能提交 Environment opaque ID 与有界结构化 request；不能使用 renderer fetch、
  Tauri HTTP plugin、generic invoke、完整 URL 或展开 credential。Rust 两阶段 reference 绑定 canonical request、live
  Environment revision/policy digest 与 DNS pin，mutation/非公共/明文 target 使用原生确认。
- Desktop HTTP 只允许 public WebPKI HTTPS 或逐次确认的 loopback/private HTTP(S)；metadata/link-local/混合 DNS、
  invalid certificate、redirect、proxy、Cookie、retry、compression 和 raw/binary response fail closed。Response 只经
  size/schema/encoding/Header allowlist 与 credential canary 重构后返回，且只存在当前 renderer 内存。

Renderer 无 filesystem、arbitrary IPC、clipboard、native dialog 和 OS integration 权限。Tauri
调用经过 window-bound capability、穷举 operation 和 Rust payload/authorization validation；
renderer 只能通过 typed adapter 使用编译期已知 operation。

Summary/detail 省略 protected value。有界且用户授权的 reveal/fill preview 可以短暂进入 desktop renderer，但不得进入 store、snapshot、log 或 crash report。Protected clipboard write 由特权 desktop runtime 完成并过期清理。

每个 Tauri 产品窗口从创建起启用平台内容捕获保护，renderer 无权关闭。Windows 10 2004+
必须使用公开系统捕获排除能力并执行 packaged AT；macOS 的 AppKit sharing hint 只作尽力防护，
不能承诺阻止现代系统截屏/录屏。该保护不替代失焦锁定、secret 最小展示或生命周期清理。

## Browser 与网页边界

- Extension 是 authenticated remote UI，不是 Vault client；native host 不能打开 Vault。
- Extension 不接收 Vault Key、envelope、recovery material、provider token 或 native path，也不持久化 Vault response。
- Desktop unlock 不授权 extension；pairing secret 受 OS 保护；revoke 清除 session/pending request。
- RPC v2 请求 size-bounded、correlated、authenticated、expiring、replay-protected；main 执行 capability policy。
- Discovery 只包含 metadata/empty bit。Origin、tab、frame document、handle 和 expiry 一直绑定到 assignment。
- 自动 disclosure 只允许启用且匹配的 empty login/OTP field；card、identity、secret、SSH、re-prompt、signup 和 password maintenance 不自动填充。
- 显式 fill 可按策略 overwrite，但不提交表单。匹配 origin 被攻陷后可读取填充值，这是 autofill 的已接受固有风险。
- Email OTP 在独立 browser authorization 解锁且用户打开 popup 或显式点击 OTP 字段页内图标后作为全局短时候选披露，不按网站与发件域名过滤；选择后只允许一次性填入当前 origin 的空 OTP 字段，不进入 extension storage 或 fill audit。任意已授权 HTTP(S) 页面显式打开候选 UI 后都可能看到最近未过期验证码，这是已接受风险。
- Service 地址、自动 cluster 和关联关系只属于桌面导航 metadata，不进入 Browser RPC，不参与 discovery/assignment，
  也不得扩大 Login URI、Passkey RP、Secret website、HTTP 或 SSH target。

## Passkey 边界

Passkey private key 是 encrypted secret。active desktop runtime revalidate RP/origin，逐次 native confirmation 并签名，只返回 public WebAuthn response。Private key 不进入 page、popup 或 extension storage；extension lock 必须 detach proxy。

## Email、Import 与 SSH 临时状态

Email token/app password 是 encrypted internal record。Main 只读邮件、内存解析正文并保留 expiring candidate；Browser RPC 可以向任意已授权 HTTP(S) 页面返回全部未过期候选的有界 code/source/received/expiry 摘要，并在选择时由 main 重新验证 candidate、expiry 和当前页面 assignment。Import 和 SSH scan content 也只存在于 opaque ID 指向的有界 main-process session。恢复码文件的 bytes 和完整路径只存在于单次特权 Rust 操作；解析后的删除必须有原生确认并在删除前重新校验文件摘要，拒绝、文件变化或删除失败必须保留文件。完成、取消、过期、撤销或 final lock 必须销毁其他有界状态。

禁止把 email body/OTP、import secret、recovery-code file content/path、SSH private key、token、local path 或 pending assignment 写入 log、telemetry、browser storage 或 non-secret settings。文件删除只移除当前文件系统条目，不承诺安全擦除、副本或备份清理。

插件查看 Login 恢复码时，每次必须由 core 重新验证当前主密码，解密列表只进入当前 popup 组件内存并在隐藏、离开、锁定、断开或失败时清除。复制同样逐次重新验证，但值只由 Tauri Rust platform 写入带过期清理的系统剪贴板；插件只接收清理时间，不接收复制值。查看授权不得复用于复制，恢复码不得进入 background、content script、extension storage、日志、通知或 crash data。

## Agent Capability Broker 边界

- 本地 Agent、模型与 MCP tool caller 默认不可信；MCP stdio shim 只是不拥有秘密和策略的 transport。
- IPC peer 的 PID、parent PID、创建时间、当前路径、binary hash 与 MCP `clientInfo` 只作为当前
  连接证据。Broker 必须验证 packaged shim，但不得把 shim 身份误写为 MCP 宿主身份。`--client` 提供的稳定
  自定义 key 只表示用户批准的本地集成，可以被同一 OS 用户的其他进程自报；它不是软件品牌认证。
  持久 pairing proof 必须绑定规范化 client key、当前 OS 用户和 protocol epoch，并由 OS credential storage
  保护；撤销 proof 后同一 key 必须重新配对。
- Agent 不因 Vault 已解锁或 desktop/browser 已授权而获得 ambient authority；每次操作必须绑定持久 pairing、
  connection session、opaque account、capability、精确 target、canonical request、risk 与 expiry。
- Pairing 不得解锁 Vault。默认每个已验证 MCP transport 必须由用户在独立 native Agent unlock window 建立
  memory-only unlock lease；用户可以显式允许同一 pairing identity 的并行 transport 共享一次解锁。主密码、
  Agent PIN、biometric result 与 Vault Key 不得进入 MCP/IPC。desktop、browser、另一 client 或不同 Vault 的解锁
  状态不能满足该 gate；connection scope 的真实断连或 client scope 的最后一条同身份真实断连、显式 Agent lock、pairing revoke、系统锁定/睡眠、退出和
  最后 lease 消失必须清除对应 authority，Agent lock 不改变 desktop/browser authorization。每条 lease 另受
  独立的有界空闲时限与最长连续解锁策略约束；有限时长下，活动只能刷新空闲时限，不能延长绝对时限，执行中
  动作也不能绕过绝对到期清理。用户可以显式选择“直到关机”关闭绝对截止，但 lease 不持久化且空闲、系统
  锁定/睡眠、真实断连、撤销、Vault 锁定/切换和退出清理仍强制执行。该非秘密策略独立持久化，不得复用
  desktop/browser 自动锁定设置。
- Client-shared unlock 只复用 factor gate，不得共享 connection session、action permission、connection permission、
  pending continuation 或资源 owner。共享 owner 必须由 Rust broker 从 client key、OS user、protocol epoch 与
  Vault namespace 推导；scope 切换必须 fail-closed 清除现有 lease 和 authority。
- Tauri Rust broker 是 policy、风险感知 permission、secret use、adapter、safe output、audit 与 cleanup 的唯一
  owner。受保护值只在固定 protocol adapter 的最小作用域从 `vault-core` 取得，使用 zeroizing buffer，并不得
  通过 MCP/IPC、renderer、argv、普通环境、临时凭据文件或 Agent 可读 browser state 传递。
- ApiEnvironment 只能由用户通过 desktop typed API 创建、修改和删除。Agent 不得成为 Environment、auth、
  Header、credential selector、origin/base path、wildcard、redirect/TLS policy 或显示文案的作者；MCP 不存在环境
  detail/CRUD 工具。
- Environment discovery 使用独立 allowlist，所有 Service/reference/lifecycle 均 live 的记录返回 opaque ref、
  批准 label、kind、`http` capability 和可选 openapiUrl。Origin、base path、auth、Header 和 credential ref 即使是
  非秘密也不得进入 Agent IPC、error、audit、log 或 snapshot。OpenAPI URL 不由 VaultMesh 访问且不构成 target/permission。
- Environment 出现在目录中不授予动作 authority；Agent 仍必须具有独立 unlock lease，并让每个动作通过风险感知
  Action Lease 与适用的逐次确认。Environment 级 enable 开关不得成为第二套授权状态。
- Environment/Service/credential/lifecycle 漂移必须提升或影响目录 revision，并使旧 cursor 与未来 authority fail closed；
  delete/restore 不得复活旧 permission，label 相同不得自动改绑。
- Agent 以安全搜索取得 exact Vault item 或 live ApiEnvironment 后提交 typed action；broker 从 Vault 字段、
  内置规则或 capability-specific typed internal definition 编译 Canonical ActionPlan。Direct compatibility
  HTTP/access-token 的 origin/base path 只来自 Secret `website`；结构化 HTTP target/config 由 ApiEnvironment 拥有且
  当前切片只 discovery、不执行。Agent 只提交 exact method/path/query/body/response mode；wildcard 只能由原生授权 UI 从当前 path
  生成。Agent 不能提交完整 URL/origin/header/credential、risk、display 或 permission pattern。
  用户保存的 exact HTTP(S) `website` 同时表示该账户对 public/private/loopback/link-local/metadata 目标和
  HTTP 或 HTTPS 传输的选择；Broker 不再增加 EndpointTrust、私网 allowlist、certificate pin 或证书错误拒绝。
  此链路不承诺抗网络窃听、中间人或对端冒充；产品仍必须保证 Agent 不能替换账户绑定的 origin、port 或 base path。
  原生裁决只签发 exact action、版本化 action class 或 capability scope 的 once/connection/persistent lease；connection
  绑定真实 Agent transport 并跨内部防重放 session 轮换存活，但在断连、App restart、revoke 或 final lock 清除；
  超过本次调用等待时限后签发的 once lease 只能由下一次匹配调用原子消费；
  persistent lease 使用 OS-key-protected AEAD owner-only store。缺失、损坏与漂移默认 Ask，任何 lease 都不能绕过
  connection session、target/Host Key、risk ceiling、destructive enablement 或 adapter hard policy。
- Unknown client/version/tool/field、重放、参数/target/binary/host-key 漂移、歧义账号、过期和 policy parity
  失败全部拒绝。R0 自动通过硬策略；R1–R4 在同一权限界面显示 broker 生成的 canonical action 摘要，不再创建独立
  action confirmation。R2/R3 的 permission lease 不能代替每次执行的 exact fresh confirmation；R4 Allow 仅 exact + once，
  persistent Deny 可以保留。
- App/broker 重启后 shim 可以使用原 client key 重新建立 verified transport，但只能复用有效 pairing proof 与
  持久 permission rule；旧 unlock/connection/once authority 和资源不得恢复。未完整送达的 frame 可以用同一
  request ID 重送，完整送达后响应丢失只允许重放 R0 幂等操作；其他动作必须返回 `execution-unknown` 并禁止
  自动重试，避免远端副作用重复发生。
- SSH、HTTP、managed web 与 protected action 只能使用 Agent 专项 Spec 穷举的动作工具；raw secret、
  通用 shell/curl/target/DOM/CDP/signing oracle、unlock/reveal/copy/export 永久禁止。
- 用户可以通过 R3 exact-only 的 `vaultmesh_ssh_host_setup` 明确建立当前 OS 用户可直接使用的持久
  OpenSSH alias。Agent 只能提交 alias；broker 拥有 exact account/target/Host Key、ED25519 生成、本地
  create-new key/config、远端安装、登录验证和失败补偿，且不得把 key、host 或路径返回 MCP。该 alias 完成后
  的外部 `ssh <alias>` 不经过 VaultMesh MCP 逐命令授权，原生授权 UI 必须在建立前明确提示这一 authority
  扩张；已有 alias/key/config/symlink 冲突全部 fail closed。
- 生成的 SSH key 必须先原子保存为加密 Vault SSH key item；其 alias/account/target/Host Key 绑定由 Vault
  独占拥有。安全 summary/detail 只可以投影只读 alias，其他绑定字段不得离开 Core。本地只保留 OpenSSH
  必需的 owner-only key/config，不保存
  `manifest.json`；Vault 绑定缺失、目标漂移或本地 key 不匹配时不得推断、重绑或覆盖。
- 远端命令输出、API/网页业务数据和 download 可能敏感，必须经 capability hard policy、字段/PII allowlist、
  secret canary、大小/速率限制重新构造；解析或 redaction 失败只返回稳定 safe error，不回退原文。
- 已批准但恶意的 remote target/binary、HTTP/TLS 网络攻击与被攻陷 OS 不属于客户端可绝对防御的凭据保密保证；
  产品只承诺 VaultMesh 不向 Agent 披露凭据材料、不跨账户或 exact origin 使用，并通过最小权限和有界结果降低风险。
- Revoke、disconnect、cancel、timeout、expiry、child exit、broker shutdown 与 final lock 必须幂等清除适用的 Agent
  connection session、confirmation、PTY/browser/child、continuation 和敏感 buffer；session expiry 可以在同一已验证
  paired transport 上签发无旧 authority 的新基础 session，final lock 可以保留 transport identity 但必须返回 typed
  lock error，只有 pairing revoke/真实断连移除连接 identity。audit 只记录有界非秘密 envelope。

## 已接受安全决策

- Argon2id 固定 64 MiB、3 iterations、parallelism 1、32-byte output；先拒绝 attacker-controlled alternative。
- Wrapped-key 与 payload nonce 分别随机；header version/salt/KDF 是 AAD。
- Quick unlock 只以 OS facility 包装随机 Vault Key，不保存或替代主密码。
- Item re-prompt 在 core 保护 copy/reveal；Login recovery codes 与 card 无条件逐次重新验证主密码；
  browser fill policy 独立。
- Unknown Vault/RPC/ABI version fail closed。
- Fill/import/scan/email temporary data 都必须 bounded、memory-only、terminal-path cleanup。
- Tauri 产品窗口默认请求 OS 内容捕获保护；Windows 公共捕获排除是必须验收的纵深防御，
  macOS sharing hint 不得被描述为通用截屏阻断保证。

## 公开发布前安全 Gate

- 独立密码学、格式和 unlocked-key lifecycle 审计（`OPEN-003`）。
- Windows DPAPI/Hello、screen capture、clipboard、lock、backup 审查（`OPEN-001`）。
- Signing、notarization、updater integrity、native-host installation、dependency/supply-chain 审查。
