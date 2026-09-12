# Agent Capability Broker 专项规格

本文是本地 Agent Capability Broker 跨模块行为的唯一专项规格所有者，由
`CHG-2026-020-agent-capability-broker` 接受并合并。工具目录、风险等级、授权、adapter、输出、审计和
生命周期的规范性行为以本文为准；公共类型与枚举的实现定位由代码拥有，不在其他文档复制。

## 1. 安全性质与边界

### 1.1 必须成立的性质

1. **No secret API**：不存在能够返回主密码、Vault Key、password、API token、Cookie、SSH private
   key/passphrase、TOTP/email OTP、recovery code、client secret 或等价可逆表示的 MCP operation。
2. **Use without disclosure**：秘密只在 Rust-owned protocol adapter 内用于已批准 target；MCP shim、
   Agent、renderer、extension、native host 和普通 child environment 均不是 secret owner。
3. **No ambient authority**：没有只凭 desktop、browser、其他 MCP client 或底层 runtime 已解锁即可执行的
   Agent operation。每次请求必须来自已配对 client key，并有当前 verified transport 的 MCP unlock lease、
   connection session、account binding 和 capability policy。
4. **Request integrity**：需要确认的授权绑定完整 canonical request。确认后不能替换账号、host、port、
   origin、method、path、command、arguments、body、selector、RP、challenge 或 output destination。
5. **Fail closed**：未知 client/version/tool/field/account/capability、歧义选择、过期、重放、锁定、
   policy drift、target drift、binary drift、host-key drift 和 schema drift 全部拒绝。
6. **Terminal cleanup**：success、failure、cancel、timeout、disconnect、revoke、final lock、navigation、
   child exit 和 broker shutdown 都有显式、幂等的资源与敏感 buffer 清理。
7. **Bounded results**：Agent 只获得完成任务所需的 schema 化业务结果；raw transcript/body/DOM/header、
   local path、credential-bearing error 和无限 stream 均禁止。
8. **One policy owner**：工具目录、schema、风险等级与授权要求只有一个机器可读 owner，MCP list、Rust
   dispatcher、native UI 和 parity test 由它生成或验证。

任何实现无法证明以上任一性质时，必须停止对应 adapter，不得用文案、MCP client approval 或输出
redaction 声称安全完成。

### 1.2 准确的保证

VaultMesh 可以保证自身不会把凭据材料序列化或有意暴露到 Agent boundary，并限制它只到达已绑定
adapter/target。VaultMesh 不能保证以下内容永远不敏感：SSH 命令输出、API 业务响应、网页账户数据、
下载文件或用户要求 Agent 处理的数据。

已批准 target 如果恶意或被攻陷，可能把收到的 bearer credential 变换后编码进业务响应。通用客户端无法
对任意变换提供绝对检测。因此目标身份、最小权限 credential、typed response 和用户信任是强制前提，
产品不得宣传为对恶意终端的密码学隔离。

### 1.3 威胁参与者

| 参与者 | 默认信任 | 约束 |
| --- | --- | --- |
| Agent/model/tool caller | 不可信 | 只能提交 schema request；不能读取 broker memory、secret DTO 或授权 token |
| MCP stdio shim | 不可信 transport | 无 Vault Key/secret/policy；被杀死只造成连接终止 |
| Tauri Rust broker | 特权可信计算基 | 唯一执行 policy、confirmation、secret use、audit、cleanup |
| `vault-core` | secret owner | 唯一解密、模型 validation、mutation rollback owner |
| Desktop renderer | 非特权 UI | 只显示安全 metadata 和 native approval result；无 generic invoke |
| Remote target | target 级显式信任 | 精确绑定身份、协议和最小 credential；不能动态改变 |
| 同用户恶意进程/被攻陷 OS | 当前安全范围外 | 仍使用 peer identity、OS ACL、code signing、sandbox 做纵深防御 |

## 2. 运行时拓扑与所有权

```text
任意本地 stdio MCP client（包括 Codex/OpenCode）
        │ MCP stdio（无 secret）
        ▼
vaultmesh-agent-mcp shim
        │ Agent IPC v2 + peer identity
        ▼
owner-only UDS / Windows named pipe
        │
        ▼
Tauri Rust Agent Capability Broker
  ├─ persistent client pairing + per-transport MCP unlock lease
  ├─ Agent-only Vault runtime + connection-owned session
  ├─ account search + ActionPlan compiler + authorization lease
  ├─ request canonicalizer + quota + safe audit
  ├─ SSH adapter
  ├─ HTTP adapter
  ├─ managed-web adapter
  └─ OTP / Passkey / credential-action adapters
        │ minimal bounded secret access
        ▼
DesktopRuntime / vault-core ── atomic encrypted Vault
```

不得让 MCP shim 链接解密 core、打开 Vault 文件或直接 import adapter。不得让 `vault-core` 知道 MCP、
Codex、OpenCode、SSH/HTTP/browser UI；core 只拥有内部 ConnectorDefinition validation、secret lookup 与 mutation。

现有 `apps/tauri-desktop/src-tauri/src/ssh_service.rs` 可以作为 SSH library 基础；Agent 路径禁止使用
`apps/tauri-desktop/src-tauri/src/ssh_external.rs` 的外部终端/临时 identity 文件策略。受保护值继续
通过 `crates/vault-ffi/src/runtime.rs` 的有界 runtime path 取得，并在 final lock 时接入现有 Rust
lifecycle cleanup。

## 3. MCP 与 Agent IPC 合约

### 3.1 MCP surface

v2 只声明 MCP `tools` capability：

- 可以：`initialize`、`tools/list`、`tools/call`、safe progress/cancel。
- `tools/list` 必须稳定返回 v2 公共工具目录；工具 schema 可见性不授予 pairing、session、account、permission
  或 confirmation。当前连接的真实可执行范围只由 broker 在每次 `tools/call` 时裁决。
- 不声明：secret resources、prompts、sampling、roots 写入或让 MCP client 代替 native authorization 的 elicitation。
- MCP logging/progress 只允许 request ID、stage、非秘密 count 和 safe status code。
- 工具结果优先使用 bounded `structuredContent`；不得把异常栈、command line、headers、DOM 或原始 stderr
  作为 fallback text 返回。

### 3.2 公共请求 envelope

```json
{
  "protocolVersion": 2,
  "requestId": "uuid",
  "accountRef": "opaque-or-omitted-for-metadata",
  "tool": "vaultmesh_ssh_exec",
  "toolVersion": 1,
  "parameters": {},
  "confirmationTicket": "opaque-optional"
}
```

`AgentClient` 与 connection session 来自已验证 connection，不接受 request 自报；shim 不发送或预轮询
`sessionId`。`accountRef` 与 ticket 是不可枚举 opaque ID。每个 request ID 单次使用；broker 只解析一次，
在填充所有默认值后生成 canonical
request，不允许 client 利用 JSON key order、Unicode、大小写、默认端口、路径归一化或重复 header
制造确认与执行差异。

Shim 对每个 MCP `tools/call` 只构造一个 request envelope。若 owner-only IPC 在完整 newline frame 送达前失败，
shim 可以丢弃旧连接、用相同 client key 重新 hello，并以同一 request ID 重送一次；这不恢复旧 transport 或
session。若 frame 已完整送达但 response 丢失，只有 registry R0 幂等操作可以在新连接上使用同一 request ID
自动重放；R1–R4 必须返回 `execution-unknown`、`retryable: false` 与安全重试提示，Agent 必须先检查目标状态，
不能自动重复动作。新 broker 尚未就绪时返回 `broker-restarting` 与 `retryable: true`，shim 保持存活供后续调用重连。

### 3.3 响应 envelope

```json
{
  "ok": true,
  "requestId": "uuid",
  "auditRef": "opaque",
  "result": {},
  "truncated": false,
  "continuationRef": null
}
```

Continuation 是 broker-owned、有 account/session/tool binding 和短 expiry 的结果 handle，不是本地文件路径。
错误只返回稳定 code、safe message、retryable、可选 native-action-required，以及 allowlist 后的安全 details
（仅 `missingFields`、`allowedSources`、`retryHint`）；不得返回 library debug、远端认证细节、匹配到的 secret
字节、Agent 提交的 target/policy 或内部路径。

### 3.4 版本规则

- Agent IPC 与 MCP tool contract 独立于 Browser RPC v2。
- unknown major/version/tool/required field 必须拒绝；禁止自动 downgrade。
- v2 新工具是 public surface change，必须同时更新 registry、policy、dispatcher、client fixtures、parity
  test、专项 Spec 与 traceability。
- tool schema 只允许 append-only optional field 且安全默认不扩大权限；否则提升 toolVersion 或 protocol。

## 4. Client pairing 与连接 session

### 4.1 Pairing

VaultMesh 随应用分发固定 MCP shim。第一次连接必须显示独立、置顶、不可复用主窗口 capability 且
content-protected 的系统配对窗口，不得打开主窗口或要求用户进入设置/安全中心。配对不要求 Vault 已解锁，
也不得创建或借用 desktop/browser/Agent Vault authority。该窗口只能调用 safe status 和当前 pairing
approve/deny 的最小 typed API。MCP config 必须以 `--client <client-key>` 提供稳定、
自定义且通过长度/字符校验的 integration key；不得把 Codex/OpenCode 或其他产品固化成协议枚举或白名单。
MCP 标准不认证该值，因此它只表示用户批准的本地集成，不表示已验证的软件品牌。配对窗口只显示原始 key，
并明确同一 OS 用户的其他进程可以自报相同 key。PID、parent PID、进程创建时间、当前路径、binary hash 与
MCP `clientInfo` 只用于当前 IPC 连接校验，不属于持久 identity，也不得写入 pairing record。Broker 必须从
socket/pipe 验证 packaged shim；不得用 shim 的进程属性代替 MCP 宿主身份。
短生命周期 MCP 探测进程在用户解锁或确认前退出时，同一 client key 的申请可以在内存中保留至窗口完成或
10 分钟到期；同一 key 重连只刷新该申请。用户接受后创建 pairing record，当前连接立即获得基础能力；
若当前连接已经退出，pairing proof 必须成功持久化，使同一 OS 用户下使用该 key 的下一次连接直接继续。
拒绝或关闭窗口必须终止该身份的当前连接。批准或拒绝的 command response 返回后必须立即关闭配对窗口；
持久 proof 必须绑定规范化
client key、当前 OS 用户与 protocol epoch，并保存于 OS-protected credential storage。client key 本身不是
bearer secret，可以出现在 MCP config；proof 不得进入 config、环境变量或仓库。撤销必须删除 proof，下一次
使用同一 key 连接时重新配对。

配对与动作授权必须由 broker 以不同的 native action code 路由。只有
`pairing-required/approve-pairing` 可以显示上述系统配对窗口；`permission-required/request-permission`、
`authorization-required/request-authorization` 必须显示独立、全局置顶且 content-protected 的最小权限系统授权窗口，
不得显示、聚焦或刷新主窗口。R0 自动通过硬策略，R1–R4 在 permission window 中完成显式 Allow，不再创建第二个 action confirmation
窗口。授权 WebView 应在应用启动后隐藏预热；请求出现时立即显示，以进度条
展示本次调用可继续的 30 秒时限。broker 的实际等待到期必须向当前授权引用发送超时事件，使窗口立即归零；超时后保留
窗口并显示本次失败。
配对窗口对同一 pending identity 的重复连接/错误通知必须幂等，不得重复聚焦或刷新。配对完成后 Agent 原样重试
工具调用，broker 才进入 ActionPlan；进入动作授权后 broker 应保留原始调用等待本地裁决，不再要求 Agent 二次重试。

Unix socket 使用 owner-only 权限并验证 peer UID/PID；Windows named pipe 使用当前用户 ACL、拒绝远程
client并验证 client PID/image。正式包必须校验 shim code signature/hash；开发 build 只允许开发 app ID、
独立 socket/credential namespace，并对每个 session 保持 native confirmation。

### 4.2 Connection session

Pairing 只表示 client identity，不授予账号操作。每个已配对 stdio connection 任一时刻只由 broker 持有一个
短时 session；不得提供手工创建、暂停、缩短、扩大或恢复 session 的产品 API。session 只保存当前连接引用、
expiry、request/output quota、request replay 状态与资源取消句柄。Connection permission lease 绑定真实 transport，
不属于可透明轮换的内部 session。账号目标、风险和
confirmation 均在具体调用时从 Vault account 或内部 ConnectorDefinition 编译为 Canonical ActionPlan。

仓库文件、MCP arguments 或 client config 不得静默创建/扩大 production binding。断连、撤销、final lock、
expiry 或 App 重启必须清除 active session；pairing 与持久 permission rule 可以保留。

App 重启后仍存活的 stdio shim 必须重新连接新 socket/pipe 并用原 client key 完成 hello，不得要求 Codex/OpenCode
进程或 MCP 配置重启。重新 hello 创建全新 verified transport 与基础 session；持久 pairing proof 可以免除再次
配对，持久 permission rule 可以重新匹配，但旧 unlock lease、connection lease、once lease、pending、continuation、
replay record 与子资源全部不可恢复。传输重试必须遵守 3.2 的 delivery boundary，不能以“自动重连”为由重放
结果不确定的动作。

完成 pairing 后，单个 session 最长 15 分钟。到期时 broker 必须先终止旧 session authority、pending
authorization、continuation 与子资源，保留绑定同一真实 stdio transport 的 connection permission lease，再为该仍存活、
已验证且已配对的 transport 原子签发新的基础 session；不得断开或要求用户重连 MCP，也不得把旧 session authority
复制到新 session。Vault final lock 必须
执行相同的特权状态清理，但可以保留当前 transport identity；锁定期间需要 Vault 的调用返回 `vault-locked`，
本地解锁后同一连接按需获得新的基础 session。Pairing revoke 则删除 proof、终止 authority，后续必须重新配对。
Agent 可以搜索安全账号 metadata 并直接提交 registry 中的动作工具；
工具可见不等于允许，broker 在每次调用上裁决。账号目录只包含 opaque `accountRef`、item kind、用户 label、
environment、favorite/tag 派生索引、semantic capability 与命名 action/tool 安全摘要；不得包含 username、URL、
host、notes、受保护字段、target、internal definition ID、候选值或权限状态。账号发现不要求预授权；Shim 不得先调用
session status 或自行解释 allowed tool。

### 4.3 MCP 独立解锁与锁定

Agent unlock scope 默认 `connection`：每个已配对、已验证 stdio transport 必须在首个 Vault-dependent tool 前
取得独立、memory-only MCP unlock lease，绑定 `vault_namespace × pairing_identity × client_id/transport_generation × unlock_generation`。
用户可以显式选择 `client`：相同 `vault_namespace × client_key × OS user × protocol_epoch` pairing identity 的并行
verified transport 共享一个 memory-only lease。两种 lease 都不得绑定可透明轮换的内部 connection session。
desktop、browser、不同 pairing identity 或不同 Vault 已解锁均不能满足当前调用的 access gate。

用户可以在安全中心或当前 `agent-unlock` window 显式选择 connection/client scope；后者只能修改该非秘密 enum，
并继续复用 scope 切换时的 fail-closed 清理。用户只能在第三个独立、置顶、content-protected 的 `agent-unlock`
系统窗口输入主密码或使用 Agent 专用 PIN/biometric。该窗口只能读取当前安全 unlock request/status、修改 unlock
scope、执行 Agent runtime unlock、取消或锁定；不得
approve pairing、resolve action permission、读取 Vault detail 或调用主 renderer dispatcher。主密码、PIN、
biometric result 与 Vault Key 不得进入 MCP tool schema、Agent IPC、shim stdin/stdout、日志或 audit。Agent
quick-unlock record 与 OS credential namespace 必须独立于 desktop/browser。桌面端用户启用 Touch ID 时，Rust
privileged runtime 必须在同一次本地确认后同步 provision 独立 Agent biometric record；禁用、改密、Vault switch/restore
或 factor drift 必须同时失效。每个新 unlock request 检测到有效 Agent biometric record 后必须自动尝试一次 Touch ID，
不得因状态刷新或失败重复弹出；失败或取消后窗口必须显示明确错误并保留主密码 fallback，主密码表单必须支持 Enter
和按钮提交。

锁定状态下，`initialize`、`tools/list` 与 `vaultmesh_request_local_ui` 可以工作；账号
目录及全部 Vault action 必须返回 typed `mcp-locked` 并唤起 Agent unlock window。MCP 不提供 session 状态查询、
锁定或解锁工具，Broker 可以等待最多 30 秒；
成功后只通过内部 native continuation 复用同一 request ID 和已解析请求。超时返回 `mcp-unlock-timeout`，窗口
可以继续保留，随后成功签发的 lease 只供下一次显式重试。公共 MCP 不提供接收 factor 的 unlock operation。
同一 unlock scope owner 的并发调用必须共享一个 pending unlock request；一次 factor 成功必须向该 request 的
全部 waiter 发布结果，不能被第一个 waiter 单独消费。可见窗口不得因重复 waiter 反复 show/focus/refresh；已完成
request 不得在 lease 再次锁定后复用。Connection scope 的不同 transport 继续使用不同 request 与 lease。

Connection scope 的真实 disconnect 必须清除对应 lease；client scope 的单条并行 transport disconnect 只清理其
session/authority/resource，同一 identity 最后一条真实 transport disconnect 才清除共享 lease。VaultMesh 软件触发的
Agent lock、pairing revoke、系统锁定/睡眠、应用退出、Vault switch/restore 和 factor drift 必须清除适用 lease 与
全部下游 authority/resource。内部 connection session 透明轮换不清除有效 lease。最后一个 Agent lease 消失时必须锁定 Agent-only runtime；Agent lock 不改变 desktop、
browser 或其他 MCP client。多个 surface 的 mutation 必须经过同一 Vault 级写入协调与 revision revalidation。

Agent unlock lease 必须同时受独立的空闲时限和最长连续解锁策略约束。默认空闲时限为 15 分钟，可选
5/15/30/60 分钟；默认最长连续解锁为 8 小时，可选 1/4/8 小时或直到关机。MCP 调用和执行中的动作视为活动，
动作结束后重新计算空闲时限；有限最长连续时限不因活动刷新。“直到关机”只关闭绝对截止时间，不持久化
lease。任一适用时限到期必须撤销对应 client lease、connection authority、pending continuation 与子资源；
最后一个 lease 到期时立即锁定 Agent-only runtime。设置保存在独立的非秘密、owner-only Agent access settings
中，不得复用 desktop/browser 自动锁定设置，也不得允许关闭空闲、系统锁定/睡眠、真实断连、撤销、Vault
锁定/切换、factor drift 和退出的强制清理。

Agent access settings 另保存 `connection/client` unlock scope，默认 connection。Client scope 只共享 unlock gate，
不得共享 connection session、permission lease、continuation 或 child resource；scope 切换必须清除全部现有 Agent
unlock lease 与 authority，要求按新 scope 重新解锁。

### 4.4 风险等级

| Tier | 示例 | 默认裁决 |
| --- | --- | --- |
| R0 metadata | capability、非秘密 account label、item health | 有效 connection session 内允许 |
| R1 external read | SSH 只读命令、GET API、网页 extract | 首次 target/account 确认；当前连接可复用权限 |
| R2 mutation | upload、POST/PUT、服务重启、credential test/rotate | 权限界面醒目标注；使用 typed scope/lifetime |
| R3 privileged | root/admin、生产 PTY、Passkey、recovery consume、tunnel | 强警示；仍可选择 once/connection/persistent |
| R4 destructive | delete、purge、不可逆 rotate、危险运维 | 默认拒绝；显式 policy 启用后使用同一权限界面 |
| Never | secret reveal/export、任意 shell+secret、任意 target | 无 policy 可以允许 |

### 4.5 直接动作授权

Agent 从 `accounts_list` 取得 exact `accountRef` 后直接调用动作工具，不调用独立 permission tool。Broker 必须先
验证 registry schema，再从 Vault item、内置规则或内部 ConnectorDefinition 编译不可变 Canonical ActionPlan；
计划包含 account、exact target identity、capability、canonical parameters、output policy、risk、policy revision
和安全原生文案。Agent 不能提交 target、Host Key、URL、selector、binary、credential source、risk、scope 或文案。

授权键固定为：

```text
client_key × vault_namespace × account_ref × target_identity × capability
  × typed_predicate × lifetime × effect × policy_revision
```

`typed_predicate` 为 exact canonical action、版本化 action class 或 capability 内全部结构化动作；`lifetime` 为
once、connection 或 persistent；`effect` 为 Allow 或 Deny。Once 必须在执行开始前原子消费；connection lease
绑定真实 Agent transport，内部 15 分钟防重放 session 轮换不得清除它，但断连、App restart、revoke 或 final lock 必须清除；persistent rule 使用 OS-protected random key 加密到 owner-only AEAD
本地规则库，AAD 绑定 protocol epoch、Vault canonical-path namespace 与 OS user。key/file 缺失、损坏、Vault
移动、identity 或 policy revision 漂移统一回到 Ask。撤销 pairing 删除该 client 的规则。

同一 predicate 精确度下 Deny 优先于 Allow，predicate 精确度依次为 exact、action class、capability；更精确规则不允许扩大
capability。授权只决定动作能否进入执行；R0 自动通过硬策略，R1–R4 的当前动作确认与 permission Allow 合并，
不再使用独立 action confirmation challenge。R2/R3 的 connection/persistent permission 只记住允许申请的范围，
每次执行仍必须由同一权限窗口签发 exact、single-use execution grant；R4 Allow 只接受 exact + once，Deny 可以 persistent。

原始调用的权限等待生命周期固定为 30 秒。Broker 必须在 stdio connection 内挂起原始调用，
授权窗口允许后仅通过内部 native continuation 复用同一 request ID、canonical parameters 与 ActionPlan；该 continuation
不得开放为 IPC/MCP API，也不得绕过 replay 防护。拒绝、关闭或超时必须结束本次等待并返回稳定结果；permission
pending 保留到 connection session 结束，使超时后作出的 once/connection/persistent Allow 可供下一次显式重试使用；倒计时内 Allow
同时放行当前动作。授权窗口只允许读取当前非秘密授权摘要并 resolve 当前 permission，
不具备 `desktop_invoke`、Vault detail 或任意导航能力；主窗口失焦锁定不得把受信任授权窗口误判为离开应用。

SSH exec 使用结构化 `program` 与 `arguments[]`。原生 UI 提供显著风险等级、工具类型、目标和命令摘要，并提供
“当前命令 / 安全命令 / 所有结构化命令”三种 predicate，以及“允许一次 / 当前连接 / 始终允许 / 拒绝本次 / 始终拒绝”。
命令摘要以等宽 Markdown code-block 风格展示；倒计时结束后仍可 resolve 原 permission pending，此时 once Allow 从下一次
匹配调用开始并只被消费一次，connection/persistent 同样从下一次调用开始生效。R1 默认推荐 safe + connection；
R3 只提供 exact scope，R4 Allow 只提供 exact + once；R2/R3 即使选择 connection/persistent 也必须逐次 fresh confirm。
Allow 按风险着色但不改变授权语义。安全命令由版本化机器可读 catalog
的 executable 与 argv grammar 判断，拒绝 shell operator/redirect/substitution、通用解释器、sudo/su、网络转发、
环境/历史输出和修改型参数；catalog 版本变化使 safe rule 回到 Ask。All-command 仍只绑定 exact account 与 Host
Key 下的 SSH exec，不授予 PTY、tunnel、upload 或其他能力。

HTTP predicate 必须绑定 access-token Secret 的 exact canonical origin/base path、account、method 与 typed path
predicate；Web predicate 继续绑定命名 recipe。UI 的“此网站此能力”不得扩展到其他 origin、capability 或 selector，
HTTP path pattern 只能由原生 UI 从当前精确 path 生成。任何 lifetime 都不授予 Agent 文件系统路径、原始文件
bytes 或结果保存位置。

## 5. 多账号与内部 ConnectorDefinition

### 5.1 当前模型

SSH account 由 SSH Vault item 直接拥有；Agent 看到的 `accountRef` 是该 item 的 opaque reference，不存在 SSH
第二账号配置。Broker 在动作时读取受保护 detail、验证 Host Key 并编译 ActionPlan，secret 只进入 SSH adapter。
只有 tunnel 可从内部 ConnectorDefinition 读取与 exact SSH item/host/port/Host Key 绑定的固定 endpoint、loopback
listener、连接数和 TTL；该记录不是账号或权限 owner，definition ID 和 destination 不由 Agent 提交或发现。

`access-token` Secret 直接拥有 authenticated HTTP，不使用 ConnectorDefinition。
Secret `website` 固定 canonical HTTP(S) origin 与可选 base path；Agent 只提交 method、相对
base path 的精确 path、有界 query/JSON body 与 response mode。Broker 从 live Secret safe detail 与当前参数编译
immutable ActionPlan，并在 token use 前重新读取 item 比较 kind、origin/base path、method/path/query/body
digest、response mode、risk 与 matcher revision；token value 本身轮换不使 target permission 失效。

ApiEnvironment 是新结构化 HTTP 的 target/config owner，Login/Secret 继续唯一拥有 credential value。Environment 由用户
在 desktop 下手动配置 canonical origin/base path、auth binding、fixed Header、可选 openapiUrl、revision 与
policy digest；Agent 没有 Environment CRUD/detail。当前 `CHG-2026-026` 把全部 live Environment 以独立 allowlist
投影为 opaque `environmentRef`/`accountRef`、Service + Environment label、kind、`http` capability 与可选 openapiUrl，
但目录可见性不授予动作 authority，也不为其编译或执行 HTTP ActionPlan。执行由 `CHG-2026-028` 接入；direct access-token Secret 在此之前保留兼容，且任何
授权不得自动迁移到 Environment。

Managed web 与上述 SSH tunnel 可以保留各自 Rust-owned typed `AgentConnectorDefinition`，固定无法从 Vault item
推导的 recipe/selector 或 endpoint。ConnectorDefinition 不保存 client permission，不拥有账号或 credential，
不通过 MCP/renderer 暴露 ID 或 CRUD，也不作为 Agent 需要创建或理解的账号层。OTP、recovery 与 Passkey 从
相应 typed web 动作派生。凭据生成、测试、轮换和撤销不属于 Agent 公共能力。

旧账号配置模型、其权限规则、CRUD 与旧记录读取全部不存在。所有 Vault 统一写入和读取 format 3；其他所有
版本在 KDF 前拒绝，不得迁移、投影、降级或静默丢弃其中的数据。持久授权由独立本地 AEAD 规则库拥有，因此
授权变更不触发 Vault 全量重写。

### 5.2 选择算法

发现与执行顺序固定：

1. `accounts_list` 在非秘密索引上应用 bounded `query`、`kinds`、`capabilities`、`environments`、`favorite`、
   `tags`，再按稳定顺序以 `limit`（1–100）和 opaque cursor 分页；cursor 绑定查询摘要与目录 revision；
2. Agent 使用返回的 exact `accountRef` 直接调用动作工具；label、username、repository path 或模型推断不能替代；
3. Broker 编译 ActionPlan 并查询 deny/allow lease；Ask 时打开原生授权 UI，同一调用在允许后继续；
4. 进入 adapter 前再次验证 session、account revision、target identity、policy revision、permission 与 confirmation；
5. UI 不可用、取消、候选为零、目录漂移、规则损坏或目标歧义时 fail closed。

生产与测试 environment 不得共享授权；account/target/Host Key 切换使既有 lease、confirmation 与 continuation 失效。
ApiEnvironment cursor revision 还必须绑定未投影的 Environment revision/policy digest；target/auth/Header/credential/service
漂移使旧 cursor 拒绝。执行切片必须让同一漂移撤销 future ActionPlan/permission/resource。

## 6. MCP 工具目录 v3

工具名称与参数 schema 是 public contract。下表的“返回”均指经过 broker hard output policy 的 schema 化结果。

### 6.1 Broker 与 metadata

| Tool | 能力 | 返回 | 风险 |
| --- | --- | --- | --- |
| `vaultmesh_accounts_list` | 以 query/type/capability/environment/favorite/tag + cursor/limit 搜索筛选安全账号或 live ApiEnvironment metadata；capability 使用 `ssh-exec`/`http` 等公共语义名，未知值明确拒绝 | accounts/nextCursor/total；opaque accountRef、label、kind、environment、semantic capabilities、命名 action/risk/tool 摘要；ApiEnvironment 可额外返回同值 environmentRef 与可选 openapiUrl；不含 connector 来源、target、auth、Header、credential ref 或权限状态 | R0 |
| `vaultmesh_request_local_ui` | 请求打开 unlock/account edit/backup 等本地 UI | accepted/cancelled only | R1–R4 |
| `vaultmesh_local_file_select` | 由 native dialog 选择供指定 upload/import 动作消费的文件 | purpose-bound handle/basename/size/mime | R2–R3 |
| `vaultmesh_result_save` | 由 native dialog 把 broker-owned result handle 保存到用户选择的位置 | saved/cancelled only | R2–R3 |

`vaultmesh_request_local_ui` 不返回 UI 中输入、显示、复制、导入或导出的内容。File handle 绑定
client/session/account/purpose、摘要、expiry 和单次消费；完整路径与 bytes 不返回 Agent，保存结果也不返回路径。
动作调用产生的 pending authorization 绑定 stable client key、connection session、account、target、capability、
canonical parameters、policy revision 与 expiry；Agent 不持有可单独批准它的 permission API。重复、参数替换、
account/target/policy 更新、client disconnect 和 final lock 使其失效。

### 6.2 SSH

| Tool | 能力 | 返回 | 风险 |
| --- | --- | --- | --- |
| `vaultmesh_ssh_exec` | 对 SSH account 执行结构化 `program` + `arguments[]` | exit/status/bounded stdout/stderr | R1–R4 |
| `vaultmesh_ssh_upload` | broker-owned local handle → approved remote path | bytes/hash/status | R2 |
| `vaultmesh_ssh_download` | approved remote path → broker-owned result handle | bytes/hash/handle | R1–R3 |
| `vaultmesh_ssh_public_key_install` | 通过现有 channel 安装 public key并验证 | fingerprint/status | R2 |
| `vaultmesh_ssh_host_setup` | 为 exact SSH account 生成并在 Vault 保存专属 ED25519 key、安装公钥并创建 VaultMesh 管理的 OpenSSH alias | alias/command/opaque credentialRef/public fingerprint/status；无 key/path/host | R3 exact-only |
| `vaultmesh_ssh_pty_open` | 打开独占 PTY session | sessionRef/terminal metadata | R3 |
| `vaultmesh_ssh_pty_read` | 读取 sanitized bounded terminal output | chunks/sequence | R3 session |
| `vaultmesh_ssh_pty_write` | 写入 bounded bytes/resize-safe input | accepted sequence | R3 session |
| `vaultmesh_ssh_pty_resize` | 调整 PTY | status | R3 session |
| `vaultmesh_ssh_pty_close` | 关闭 PTY | exit/status | R3 session |
| `vaultmesh_ssh_tunnel_open` | 仅内部 ConnectorDefinition 预定义且绑定 exact SSH item/Host Key 的固定 tunnel | sessionRef/status | R3 |

upload/download/public-key/PTY 在 v2 进入 SSH item direct ActionPlan；tunnel 只有存在唯一匹配的固定
ConnectorDefinition endpoint 时才进入该 SSH item 的安全目录，否则 fail closed。不得添加
`ssh_send_password` 或把认证 secret 写入 PTY。

`vaultmesh_ssh_host_setup` 只接受受限 `alias`。Host、port、username、Host Key、bootstrap credential、
ED25519 算法、key/config 路径和 OpenSSH 选项全部由 broker 从 exact SSH item 与固定策略构建。该动作
建立当前 OS 用户可直接使用的持久 OpenSSH authority，因此必须为 R3 exact-only、逐次原生确认且不允许
connection/persistent Allow；授权界面必须说明完成后的 `ssh <alias>` 不再经过 VaultMesh MCP 逐命令授权。

### 6.3 Authenticated HTTP

| Tool | 能力 | 返回 | 风险 |
| --- | --- | --- | --- |
| `vaultmesh_http_request` | access-token Secret fixed HTTP(S) origin/base path + Agent exact method/path、有界 query/JSON body 与 status/json response mode | status 或 bounded reconstructed JSON | R1–R4 method floor |
Agent 不能设置完整 URL、origin、wildcard、`Authorization`、`Cookie`、`Proxy-*`、`Host`、client-cert、
hop-by-hop header 或任意 redirect policy。Agent 只能提交精确 path；原生 UI 可以把当前 path 变成 exact、完整
segment `*` 或 terminal `**` permission predicate。初版不接受自定义 header、raw text、HTML 或 binary body/response。

### 6.4 Managed web

| Tool | 能力 | 返回 | 风险 |
| --- | --- | --- | --- |
| `vaultmesh_web_session_open` | 为 account/target 创建或恢复隔离会话并由 broker 登录 | sessionRef/login state | R1–R3 |
| `vaultmesh_web_navigate` | 导航到内部定义允许的 origin/path | page state enum | R1–R3 |
| `vaultmesh_web_extract` | 执行预定义 selector/schema extraction | typed fields only | R1–R3 |
| `vaultmesh_web_act` | click/select/fill 非秘密业务字段/submit 批准动作 | action result | R2–R4 |
| `vaultmesh_web_download` | 下载批准资源到 broker handle | hash/size/handle | R1–R3 |
| `vaultmesh_web_session_close` | 注销并销毁隔离 session state | status | R1 |

禁止 arbitrary JavaScript、raw CDP、raw DOM、Cookie/storage/header dump、screenshot 默认返回、密码字段
读取、任意 selector 和跨 account session reuse。

### 6.5 Protected actions

| Tool | 能力 | 返回 | 风险 |
| --- | --- | --- | --- |
| `vaultmesh_otp_fill` | 把 TOTP/email OTP 直接提交给 managed target | submitted/expired/status | R2–R3 |
| `vaultmesh_recovery_code_consume` | 选择、提交并在成功证据后标记 recovery code | consumed/status | R3–R4 |
| `vaultmesh_passkey_request_begin` | 在绑定 managed-web session 内捕获批准 recipe 发起的 WebAuthn 请求 | opaque requestRef/operation/expiry | R2 |
| `vaultmesh_passkey_perform` | 对 requestRef 绑定的 RP/origin 完成 registration/assertion 并把公共响应交回目标页 | completed/status | R3 |
| `vaultmesh_items_list_metadata` | 查询 session 允许的 renderer-safe metadata | bounded summaries | R0 |
| `vaultmesh_item_get_metadata` | 查询单项非秘密 metadata/health | safe detail | R0 |

所有 protected action 必须复用统一 typed lease。Managed-web 动作从 typed internal definition 编译，HTTP
从 access-token Secret 与当前 exact request descriptor 编译 per-tool/parameter immutable ActionPlan。
OTP/recovery 的 `targetRef`、Passkey begin 的 `sessionRef + recipe`、
Passkey perform 的单次 `requestRef` 必须进入 canonical parameters digest，并继续由 broker resource store 重验
client、connection session、account、origin、expiry 与 single-use。Broker 不得公开 credential lifecycle ActionPlan、
managed/control credential transaction 或等价工具；旧开发 Vault 的 revoked/needs-review 标记只能作为
fail-closed 输入保留，不能产生可执行 action 或 authority。

Generic signing oracle 不进入 v1。SSH、Passkey、Git 或 cloud signing 必须各自绑定协议、target、challenge
语义与用户确认，不能通过一个 `sign(bytes)` 暴露。

### 6.7 永久禁止目录

以下名称及语义等价物属于 Never，不得由管理员 policy 解锁：

```text
get_password / get_api_key / get_private_key / get_cookie / get_otp
get_recovery_code / export_secret / dump_vault / reveal / copy_secret
run_arbitrary_shell_with_secret / curl_with_raw_auth / browser_raw_dom
unlock_with_password / read_backup / read_import_source
```

## 7. Adapter 设计

### 7.1 SSH adapter

- 使用 Rust SSH library 直接认证；username/host/port/credential 来自 exact SSH Vault item，Host Key identity 来自
  broker 的 ActionPlan/已批准 pin；不创建或选择第二账号配置。
- 首次 host key 只能在 native UI 显示完整 fingerprint 后绑定；变化一律拒绝，不允许 Agent 选择“忽略”。
- non-PTY 默认；`program` 与 `arguments[]` 分开 canonicalize，拒绝 NUL、控制字符、shell operator、redirect、
  substitution 与本地 shell 拼接。远端协议最终命令行只由单一 canonical serializer 产生。
- exact predicate 绑定完整 canonical program/argv；safe predicate 绑定 safe catalog ID/version；all predicate 只
  允许结构化 exec。安全目录初版只允许无修改参数的系统观察命令（如 `hostname`、`uname`、`uptime`、`whoami`、
  `id`、`date`、`df`、`free`、`ps`），并明确拒绝通用解释器、`sudo`/`su`、环境/历史输出、网络客户端与写操作。
- remote shell command 的破坏性无法完全静态识别；未命中 safe catalog 的命令至少为 R2，已知特权/破坏模式
  提升为 R3/R4 并在权限界面显著警示，persistent all-command 不能改变该风险分类或绕过 hard policy。
- output 有 byte/time/line/rate limit，UTF-8 policy、binary detection 和 safe truncation；认证 error 不返回
  方法细节或 secret-derived information。
- PTY 是完整远程 shell authority：open 必须经过风险感知权限裁决；输入/输出 sequence-bound；strip OSC、
  DCS、OSC-52 clipboard、危险 hyperlink/control；不记录 transcript；disconnect/final lock 关闭 channel。
- `sudo` 只允许独立 privileged policy 明确的 `sudo -n` 动作且不得进入 safe/all-command 自动复用。看到 password prompt 必须停止，
  不得从 Vault 自动输入。
- SFTP path 必须 canonicalize 并受 prefix policy；symlink/race 在最终 open 后重验；本地端只用 opaque handle。
- tunnel 只允许 ConnectorDefinition 固定 endpoints、连接数和 TTL，不允许 SOCKS/dynamic forwarding。
- OpenSSH host setup 必须使用内置 ED25519 generator，先把 key 与 account/alias/target/Host Key 绑定通过
  Core/Runtime 原子事务保存为加密 Vault SSH key item，再在 `~/.ssh/vaultmesh/` 的 create-new、owner-only
  路径写入专属 key 与独立 host fragment，并只在 `~/.ssh/config` 顶部维护固定 managed Include。不得覆盖
  既有 key/alias/config、跟随 symlink、保存本地 `manifest.json` 或把 key/path/host 返回 Agent。加密 Vault
  key 记录与本地 key 先作为不进入 config 的 pending identity 持久化；远端安装后必须以新 key 验证，只有
  验证通过才发布 fragment/include。失败、取消或
  结果不确定时保留 exact pending identity，后续只能由用户显式重试复用同一 key 幂等恢复，不得自动重放或
  生成第二把 key。完全匹配的既有 managed setup 只有在新 key 仍可登录时才可以返回 `alreadyConfigured`。
- 生成的 SSH key summary/detail 只投影 `managedSshAlias`。软件卡片显示 `ssh <alias>`，编辑表单只读展示
  alias 并隐藏托管 key replacement/clear；普通 title 更新不得改变 alias。

### 7.2 HTTP adapter

本节当前描述 direct access-token Secret compatibility adapter。ApiEnvironment 的结构化 target/auth/Header 注入由
`CHG-2026-028` 接入；`CHG-2026-026` 不允许 discovery 项执行 `vaultmesh_http_request`，也不迁移 direct permission。

- Exact `access-token` Secret 固定 HTTP(S) origin/base path 与 Bearer credential。Agent 提交 method、相对 base path 的
  精确 absolute path、有界 query/JSON body 与 response mode；不能提交完整 URL、origin、port、header、auth strategy、
  redirect、TLS policy、wildcard、risk 或 credential。Secret kind 或 website/base path 漂移回到 Ask；
  token value 原子轮换不改变 target identity。
- Path parser 只能运行一次并产出 canonical segments；拒绝 dot segment、反斜线、控制字符、encoded slash/backslash/dot、
  absolute/scheme-relative URL、query/fragment 混入、重复解析差异与 base-path escape。`http-path-v1` pattern 只允许
  literal、完整 segment `*` 和 terminal `**`，且只能由 native UI 从当前 exact path 生成。Method 精确匹配；Deny
  优先；matcher revision 变化使旧规则回到 Ask。
- Method risk floor 为 `GET/HEAD=R1`、`POST=R2`、`PUT/PATCH=R3`、`DELETE=R4`；typed
  destructive action 可以提高不得降低。R1 可以记住 path predicate；R2/R3 scope 可以记住但每次 request fresh
  confirm；R4 Allow 只 exact + once。
- 每次请求在连接前解析 DNS 并把解析结果固定到当前连接；不按 public/private/loopback/
  link-local/metadata 地址类别拒绝 exact 账户目标，不增加 private-host allowlist。
- HTTP 与 HTTPS 都按 Secret 保存的 scheme 执行。HTTPS 不以 WebPKI、hostname、expiry 或 self-signed 证书校验作为请求门槛；
  direct Secret 链路不保存 certificate pin 或其他 `EndpointTrust`，也不承诺此链路的对端身份、抗窃听或抗中间人性。
- credential 只在最终批准 request 内注入；redirect 一律拒绝，不能由 Agent 或 permission 覆盖。
- `status` response 丢弃 body；`json` 先在 broker 内完成大小/depth/item 限制、secret canary/常见编码和敏感键
  redaction，再构造新 DTO；不转发 `Set-Cookie`、认证 challenge、raw headers/body 或 library dump。
- 不提供生成、测试、轮换或撤销凭据的 Agent adapter。Agent 不能提交 managed/control credential、credential field、
  apply/test/rollback 或 revoke/restore transaction descriptor；这些凭据管理动作只由本地 UI 拥有。

### 7.3 Managed-web adapter

- 使用 VaultMesh-owned、per-account 隔离浏览器目录/内存 session；不得复用用户 Chrome、extension 或
  Agent browser state，不开放 remote debugging port。
- 登录 recipe 由用户在 native UI 创建/批准，包含 exact origins、字段角色、成功/失败条件和可选 MFA
  step；Agent 不能提交 password selector 或登录脚本。
- credential fill + submit + success detection 是 broker-owned 原子 login phase。此阶段 Agent 无 DOM、
  CDP、screenshot、network、Cookie 或 storage access。
- 登录后只开放内部 ConnectorDefinition 中的 navigate/extract/action recipe。`web_extract` 重新构造 typed value，不返回
  raw DOM；password/hidden/token/cookie/storage 节点永远排除。
- 每个 navigation/redirect/popup/download 重验 origin、session、account 和 expiry。跨 origin 默认关闭。
- OTP/recovery code 只在 broker 内取得并填入；recovery code 只有目标成功证据满足后才原子标记 consumed。
- Passkey recipe 只能是 `passkey-registration` 或 `passkey-assertion`，并固定 path 与触发 selector。
  `vaultmesh_passkey_request_begin(sessionRef, recipe)` 在目标页临时接管对应 WebAuthn 调用、点击固定 selector、
  验证 public request 的 RP/origin/challenge 后，只向 Agent 返回与 client/connection session/account/origin/operation/
  expiry 绑定的单次 `requestRef`。Agent 不得获得 request JSON、challenge、credential allow/exclude list 或
  页面 completion channel；`vaultmesh_passkey_perform(requestRef)` 在原生确认后由 Rust Passkey service
  生成/签名并把公共 response 直接交回同一页面 Promise，Agent 只得到完成状态。
- Passkey request 在 perform、页面导航、session close、cancel、revoke、timeout 或 final lock 时必须单次完成
  或以 `NotAllowedError` 拒绝并清除；requestRef 与 operation 不允许由 Agent 分别声明或重绑定。
- close/revoke/final lock 清 Cookie、storage、cache、download handles 和 process；当前实现禁止持久登录，
  internal definition 的 `persistSession` 必须为 false。
- 现有 Chromium extension 继续禁止自动 submit；managed web 是独立 Agent surface，不能借此修改 Browser RPC。

## 8. Confirmation、canonicalization 与资源状态

### 8.1 Confirmation ticket

```text
ticket = opaque(random, broker-owned)
record = H(
  client_id, session_id, account_ref, tool, tool_version,
  canonical_target, canonical_parameters, request_body_digest,
  risk_tier, issued_at, expires_at, nonce
)
```

Ticket 单次使用、短 TTL、仅内存保存。Native dialog 展示由同一 canonical record 渲染的账号、环境、
目标、动作和风险，不使用 Agent 自报 summary。取消、窗口关闭、锁定、参数变化、再次提交或过期都拒绝。

### 8.2 Resource state machine

```text
Created → Authorized → Running → Completing → Closed
                   ↘ Canceling ───────────────↗
                   ↘ Expired / Revoked / Locked
```

所有 transition 由 broker owner 串行化；terminal state 不可恢复。Continuation/session ref 包含 generation，
防止 ID reuse。取消先阻断新输入，再 cancel IO/child，等待有界 grace，必要时强制关闭，最后 zeroize 与
audit safe terminal result。

### 8.3 Quota

每 client/session/account/tool 必须有并发数、请求率、累计输出、managed session 数、PTY buffer、HTTP body、下载、
browser page 和 child runtime 限制。达到 quota 返回稳定错误并保留 broker 可用性；不得把 overflow 写入磁盘。

## 9. Output policy 与审计

### 9.1 Output pipeline

```text
adapter bytes
  → protocol parser
  → typed response schema
  → field allowlist / PII policy
  → secret canary + canonical encoding redaction
  → size/rate truncation
  → newly constructed MCP DTO
```

任何 parser/schema/redaction 失败都丢弃结果并返回 safe error，不能回退 raw output。Binary/download 只返回
broker handle、hash、size 和 mime policy；Agent 要消费文件必须调用明确的下一步 adapter，不拿本地路径。

### 9.2 Audit schema

允许：时间、client key/session ID、account opaque ID/display label、environment、tool、target class/
approved display、risk、decision、confirmation kind、duration、result class、exit/status class、bounded counts。

禁止：secret、username/email 默认值、request/response body、headers、command output、PTY transcript、DOM、
Cookie、OTP、recovery code、private/local path、full command when it may contain user data。Audit 保持 encrypted、
bounded、可由用户本地清理，不发送 analytics/telemetry。
实现上限为 500 条；审计持久化失败必须返回 `audit-unavailable`，不能发布已构造的成功结果。显式 v2→v1
降级前的 encrypted backup 保留审计历史，v1 rewrite 清除 Agent audit。

## 10. 与 VaultMesh 现有功能的映射

| 现有功能 | Agent 入口 | 结果 |
| --- | --- | --- |
| Login/password | managed login | 登录/业务结果；无密码 |
| Card/identity fill | managed web approved recipe | action status；无完整卡号/PIN/未选身份字段 |
| Developer/service secret | HTTP/protected connector | typed result；无 token/value |
| SSH credential | SSH exec/SFTP/PTY/install public key/setup OpenSSH host alias | remote/config status；无 password/private key/passphrase/key path |
| TOTP/Email OTP | `vaultmesh_otp_fill` | submitted/expired；无 code |
| Recovery code | `vaultmesh_recovery_code_consume` | consumed/status；无 code |
| Passkey | `vaultmesh_passkey_request_begin` + `vaultmesh_passkey_perform` | opaque requestRef/completed；无 request challenge/private key |
| Password health | item metadata/health summary | score/count；无 protected field |
| Item CRUD | metadata query；secret create/edit 请求 native UI或 connector action | safe metadata/status |
| Import/scan | 请求 native UI | count/safe preview/status；无 source bytes/path |
| Backup/restore | 请求 native UI only | accepted/cancelled；无 factor/file/result data |
| MCP unlock/quick unlock | 独立 Agent native window only | memory-only caller lease；无 factor/Vault Key response |
| Reveal/copy | 无 Agent operation | 永久 UI-only |

## 11. 标准 MCP client 接入

所有客户端都配置同一个随 VaultMesh 分发的 local stdio MCP executable，并通过 `--client` 提供稳定自定义
integration key；不得为 Codex、OpenCode 或其他产品创建不同安全逻辑。安装 UI 只写 executable path 与
非秘密 client key，不写 token/account/secret。v2 集成采用
稳定的完整公共工具目录，不能按 pairing 或动态 session 过滤 MCP `tools/list`。实际 capability call 仍必须
通过 VaultMesh pairing、当前 connection session、account、permission 与 risk；授权变化不依赖客户端重启
或重新发现工具。Agent 应使用 query/filter/cursor 调用 `vaultmesh_accounts_list`，取得 exact `accountRef` 后直接
调用动作工具。若需要 Ask，原生窗口在同一动作上显示 broker 编译的 target、action、risk 与 scope；允许后同一
调用继续，拒绝返回稳定错误。`capabilities[]` 使用公共语义能力名，`actions[].tools` 才使用 MCP 工具名；账号
不需要预授权即可出现。Agent 不调用 permission tool、不创建或查询第二账号配置、不得寻找“已授权账号”，也不得补交
target 或 policy。

Codex/OpenCode 自带的 tool approval 建议保持 ask，但 broker 不信任 client 声称的 approval。Client 退出、
MCP cancel 或 stdin 关闭必须结束 connection session；同一存活连接的 session 到期只执行内部轮换，
新连接复用 pairing，但绝不恢复旧 session。VaultMesh App 重启后，仍存活 shim 自动重连并取得新 transport；
R0 查询可以安全重放，动作在送达后丢失响应必须报告 `execution-unknown` 而不是自动重复。正式验收包括：

- 安装、升级、卸载与路径空格；
- client rename/config copy 不能继承授权身份；
- tools/list schema parity；
- 多账号 exact selection；
- native deny/cancel/revoke/final lock；
- stdout/stderr/log/config/workspace 无 secret canary；
- Codex/OpenCode 各自完整 SSH 与 HTTP 垂直切片。

## 12. 测试设计

### 12.1 Contract tests

| Test ID | 必须证明 |
| --- | --- |
| `CT-AGENT-PROTOCOL-001` | schema/version/size/correlation、unknown fail-closed、registry↔dispatcher↔policy parity、safe error、App 重启后 shim 重新 hello、同 request ID 的 delivery-safe/R0 重放与 R1–R4 `execution-unknown` |
| `CT-AGENT-AUTH-001` | pairing identity、peer checks、deny/cancel/revoke、pairing 跨连接复用且 connection session 不恢复、App 重启后 shim 无需重启且只复用 pairing/persistent rule、存活连接 session 到期透明轮换、final lock 保留 transport identity 但清除 authority、pairing 与 action authorization code/UI 路由隔离 |
| `CT-AGENT-UNLOCK-001` | pairing/unlock/action 三状态与三窗口隔离、desktop/browser/other-client 不可借用、Agent-only runtime、per-transport lease、独立持久化 idle/absolute lock、执行中 activity 与绝对到期、30 秒同调用 continuation/超时重试、VaultMesh 软件触发的 Agent lock、独立 PIN namespace、disconnect/revoke/system-lock/last-lease cleanup、factor 不进入 MCP/IPC |
| `CT-AGENT-POLICY-001` | risk tier、canonical request、ticket single-use/expiry、parameter substitution/replay rejection |
| `CT-AGENT-ACCOUNT-001` | Vault 候选与内部 definition 投影的安全 metadata、稳定分页/过滤/目录漂移游标拒绝、无 username/URL/host/secret/definition ID、exact binding、production/test isolation、switch invalidation |
| `CT-AGENT-SECRET-001` | canary 不进入所有 MCP/IPC/error/log/env/argv/temp/DOM/audit surface；无 raw secret tool |
| `CT-AGENT-LIFECYCLE-001` | success/failure/cancel/disconnect/revoke/final-lock/crash/timeout 资源和 buffer cleanup、15 分钟 session 轮换不要求 MCP 重连且不继承旧 authority、App 重启后新 transport/session 与动作结果不确定性、锁定返回 typed error |
| `CT-AGENT-AUDIT-001` | audit allowlist、bounded retention、redaction、no transcript/body/header/path |
| `CT-AGENT-SSH-001` | host-key/auth/command/SFTP/tunnel policy、只读 alias 卡片/编辑表单、OpenSSH alias/key 加密 Vault 原子持久化与重启恢复、无 manifest、create-new 与 owner-only 权限、pending identity/config fragment、冲突/symlink/target drift 拒绝、新 key 登录验证、显式幂等恢复、no key/path response、sudo-n、output quota、cancel/unknown |
| `CT-AGENT-PTY-001` | open confirmation、sequence/generation、OSC/DCS/OSC52 filter、quota、resize/close/final-lock |
| `CT-AGENT-HTTP-001` | auth injection、header denial、redirect/cross-origin denial、exact account target/DNS connection pin、HTTP/HTTPS、private/loopback/link-local/metadata address、self-signed TLS、schema/redaction |
| `CT-AGENT-WEB-001` | isolated account session、atomic login、no raw DOM/CDP/cookie、origin/nav/OTP/cleanup |
| `CT-AGENT-AUTHN-001` | OTP/recovery/Passkey/generate/rotate/test/revoke 不返回 secret且成功/失败原子语义正确 |
| `CT-AGENT-CODEX-001` | Codex stdio install/list/call/cancel/revoke/multi-account E2E |
| `CT-AGENT-OPENCODE-001` | OpenCode stdio install/list/call/cancel/revoke/multi-account E2E |
| `CT-AGENT-PERMISSION-001` | Retired historical test ID；当前授权由 `CT-AGENT-AUTHZ-002/003` 覆盖，不保留旧配置兼容路径 |
| `CT-AGENT-DISCOVERY-002` | 非秘密 query/filter/cursor、semantic capability 与 action tool 名分离、未预授权账号可见、未知 capability 明确拒绝、目录 revision 漂移、无 definition/target/permission/secret metadata |
| `CT-AGENT-AUTHZ-002` | direct action、单次 parse/forward、connection-owned session、ActionPlan、exact/class/all predicate、once/connection/persistent allow/deny、once 原子消费与超时后下一次调用消费、存储损坏 Ask、revoke cleanup、独立最小权限授权窗口、预热/置顶/30 秒进度、broker 超时事件立即归零、超时保留失败状态与同 request native continuation、confirmation 分离 |
| `CT-AGENT-SSH-SAFE-001` | structured program/argv、safe catalog grammar/version、shell/operator/interpreter/sudo/network/mutation 拒绝、exact/safe/all scope 与 Host Key/policy drift |

### 12.2 Adversarial matrix

- MCP：oversize、duplicate key、unknown field/version/tool、request replay、slowloris stdout、cancel race。
- Identity：socket/pipe theft、wrong UID、binary/hash change、parent spoof、copied config、stale pairing。
- Policy：Unicode/path/host normalization、default port、case、encoded slash、duplicate headers、body after confirmation。
- HTTP：redirect chain、credential cross-origin、DNS rebinding、IPv4/IPv6 alternate form、public/private/loopback/link-local/metadata exact target、HTTP、self-signed TLS、
  response token reflection、oversize/compressed bomb、invalid content type。
- SSH：host-key change、auth fallback、command injection tokens、infinite output、binary output、SFTP traversal/symlink、
  PTY escape/OSC52、sudo password prompt、network loss。
- Web：login redirect、iframe/pop-up/new origin、password field extraction、Cookie/localStorage access request、navigation race、
  session mix-up、OTP expiry/reuse、download path escape。
- Lifecycle：lock during secret use、revoke during confirmation、double cancel、broker/shim/client crash、App 重启自动
  重连、frame 未完整送达/完整送达后断连的重放边界、sleep/resume、app upgrade/uninstall。
- Permission：Agent 伪造 target/label/risk/schema/scope、unknown action、cross-client/account/Vault replay、
  persistent allow 提升 R2–R4、Deny bypass、once double-consume、AEAD key/file 损坏与 prompt flooding。
- Compatibility：format 3 create/write/read、所有其他版本 pre-KDF refusal、恶意 header/ciphertext、
  format-3 backup/restore、原子 mutation/rollback，并证明不存在旧格式 reader、升级、降级或迁移入口。

### 12.3 Platform acceptance

`AT-AGENT-MACOS-001` 与 `AT-AGENT-WINDOWS-001` 必须在签名 packaged app 验证 socket/pipe ACL、shim
identity、OS credential storage、Codex/OpenCode、process cleanup、sleep/system lock、upgrade/uninstall。协议类
AT 另外按工具目录登记；不支持某 adapter 的 release 必须从 scope 和工具 registry 中一致移除，不能返回
静态 unsupported 却声称 Required 完成。

`AT-AGENT-AUTHZ-002` 必须用真实 Codex/OpenCode 验证账号搜索/筛选、direct action 首次打开本地确认、
同一调用继续、30 秒进度、broker 超时立即归零与超时保留失败窗口、exact/safe/all-command 的 once/connection/persistent allow/deny、
超时后 once 仅授权下一次调用、重启恢复、损坏回 Ask、
reconnect cleanup、R2–R4 强制确认和 pairing/权限列表撤销。`AT-AGENT-PERMISSION-001` 只保留为历史证据。

`AT-AGENT-UNLOCK-001` 必须用 packaged Tauri 与真实 Codex/OpenCode 验证配对不解锁、首个 Vault 调用打开
独立 Agent unlock window、主密码与 Agent PIN、desktop/browser/other-client 隔离、同调用继续与超时后重试、
VaultMesh 软件触发的 Agent lock、disconnect/revoke/system lock/sleep/last-lease cleanup，且 MCP transcript 无 factor canary。

## 13. 实施期间的反偏差规则

1. 每个实现 PR 必须只对应 `change.md` 中一个可验证 Task，并在描述中列出 Requirement/Test。
2. PR 修改公共工具/schema/policy 时，parity test 必须在同一 PR 先失败后通过。
3. 任何人提出 raw secret、通用 shell、通用 target、复用 Browser authorization 或环境变量 secret，
   必须引用本 Work 的 Never/Rejected 条款并停止实现；改变方向只能新建/修订 Accepted CHG/ADR。
4. Phase 不得越级：基础 authorization/secret/lifecycle test 未 Pass，PTY 与 managed web 不得启用。
5. 生产 internal definition 默认 disabled，样例/fixture 只使用虚构域名、假 token、测试 SSH key 和本地 test server。
6. Feature flag 默认 off；迁移不自动配对，不自动授权，不创建 production capability。
7. 每完成一个 adapter，执行最窄 CT、全 Agent parity、相关 Rust/Tauri Gate 和 secret scan；证据写回 Change。
8. Verified 前由未参与实现的 reviewer 对照本设计逐条检查，不得只审 diff。

## 14. 已接受基线

`CHG-2026-020`、`CHG-2026-021` 与 `ADR-0007`、`ADR-0008`、`ADR-0009`、`ADR-0012` 已明确接受以下选择，实施不得偏离：

- local stdio MCP only；remote/cloud Agent 继续 Out；
- Rust broker 是唯一权威，shim 永不拥有 secret/policy；
- Agent authorization 与 desktop/browser 独立；
- Agent pairing 不解锁 Vault；每个 verified MCP transport 使用独立 Agent-only runtime unlock lease，factor
  只进入 native Agent unlock window，最后 lease 消失即清除 runtime；
- SSH 直接使用 Vault SSH item；只有固定 tunnel endpoint 与 managed web 在需要时保留不拥有 account、credential
  或 client permission 的内部 ConnectorDefinition；Agent Profile 与未发布 format 2 不存在；
- Agent 搜索账号后直接调用动作工具；shim 不预轮询 session，broker 单次解析并拥有权威 session/授权裁决；
- typed authorization lease 绑定 client/Vault/account/target/capability/predicate/lifetime/effect/revision；
- persistent authorization 使用 OS-key-protected AEAD 本地规则库，缺失/损坏/漂移默认 Ask；
- safe SSH command 使用版本化 catalog 与 argv grammar；R0 自动通过硬策略，R1–R4 使用同一风险感知 permission UI，
  R2/R3 逐次 fresh confirm，R4 Allow 仅 exact + once，不创建独立 action confirmation；
- 不提供任何 secret getter/reveal/copy/export；
- SSH/HTTP/managed-web 使用动作级工具；
- managed web 与现有 extension 分离；
- remote business result 可能敏感，按 output policy 返回；
- 先完成治理合并与基础安全垂直切片，再实现高风险 PTY/managed web；
- macOS/Windows packaged E2E 与独立安全评审是 Verified 必要条件。

改变任一选择必须修订 Accepted CHG/ADR 与本专项 Spec，不得在实现阶段临时解释。
