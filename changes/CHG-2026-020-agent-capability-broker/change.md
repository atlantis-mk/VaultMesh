# 以不披露凭据的能力代理向本地 Agent 提供 VaultMesh 操作

> 当前状态是 Implementing。2026-07-25，维护者通过 Codex 任务指令批准完成本 Work，接受本文件、
> Agent 专项 Spec 的已接受基线与 `ADR-0007`、`ADR-0008` 冻结的产品、安全和兼容选择；主规格、Requirement/Test、
> Traceability 与 YAML 路由已经合并并通过 `pnpm docs:check`。

## 问题或目标

Codex、OpenCode 等本地 Agent 需要代表用户完成服务器运维、受认证 API/网站信息获取、OTP/Passkey
等操作。现有 VaultMesh 能安全保存和使用这些凭据，但没有独立 Agent trust
boundary；直接提供密码读取、shell 环境变量、临时私钥文件、通用 curl 或 Agent 可读浏览器 DOM
会泄露凭据或形成 confused deputy。

本变更的目标是新增本地 Agent Capability Broker：Agent 只提交账号引用、目标和业务动作，VaultMesh
在 Rust privileged runtime 内完成授权、取用秘密和协议执行，只返回有界结果。多账号由既有本地加密
Vault item 拥有，不引入 VaultMesh 账号、服务器、同步、分享或恢复后门。普通用户不应维护授权 JSON；
Agent 在 pairing 后搜索非秘密账号 metadata，再直接提交类型化动作；Rust broker 编译不可变动作计划并由原生
UI 裁决 exact/action-class/capability 范围的一次、连接期、持久允许或拒绝。账号只由 Vault item 拥有；
内部 managed-web/SSH-tunnel 连接定义只保存无法从 item 推导的 adapter 约束，不构成第二套账号模型。

## 预期行为

### 2026-09-09 维护者增量：MCP Touch ID 优先解锁与主密码反馈

维护者要求桌面端启用 Touch ID 时同步 provision 使用独立 record/OS credential namespace 的 Agent Touch ID
凭据。每个新的 MCP unlock request 默认自动尝试一次 Touch ID；失败或取消后不得因刷新重复触发，窗口必须显示
明确错误，并保留支持 Enter 与按钮提交的主密码表单。该增量不复用 desktop/browser session，不改变 Agent lease、
scope、timeout 或 MCP/IPC factor 隔离。

### 2026-07-29 维护者增量：专属 OpenSSH 主机别名

维护者要求 Agent 可以为 exact SSH 账号一次性生成服务器专属 ED25519 key、安装公钥并写入本机
OpenSSH config，使当前 OS 用户随后可以执行 `ssh <alias>`。新增公共工具
`vaultmesh_ssh_host_setup(accountRef, alias)`，风险固定为 R3 exact-only；Agent 不能提交 host、username、
port、Host Key、算法、key/config 路径或 OpenSSH 选项，也不能取得公私钥原文、本地路径或目标字段。

Rust broker 在原生授权窗口明确提示该操作会建立不再受 VaultMesh MCP 逐命令 Action Lease 控制的持久
本机 SSH authority。实现先原子创建软件内 SSH key 记录，并把 account/alias/target/Host Key 绑定只保存在
加密 Vault；本地不保存 manifest，只从 Vault 记录 create-new 物化 owner-only key，并使用固定 managed Include
与每 alias 独立 fragment。完成本地冲突/可写性预检后，再以现有 account credential 和 exact Host Key 安装公钥，
并以新 key 验证。Vault key 记录 + 本地 key 先作为不进入 OpenSSH config 的 pending identity 持久化；失败、
取消或结果不确定时保留该 exact identity 并返回 typed incomplete/unknown，禁止自动重放。后续用户显式重试必须复用同一 key，以远端
exact-line 幂等安装和 key-login 验证恢复；只有验证通过才发布 fragment/include。完全匹配的既有 managed
setup 只有在 key login 仍通过时才返回 `alreadyConfigured`。该安全与所有权选择由 `ADR-0013` 冻结。

### 2026-07-28 维护者增量：撤销 format 1 一次性迁移兼容

维护者确认需要保留的 Vault 已完成 format 3 迁移，并明确删除剩余 Preview 数据。产品仍处于开发测试阶段，
不再保留 format 1 的 reader、主密码迁移、迁移备份、quick-unlock 特判或测试 fixture。Core、FFI、Tauri、
renderer、Agent、Browser、quick unlock 与 restore 必须只接受 format 3；所有其他版本必须在 KDF 前拒绝，
不得提供迁移、降级或专用备份 API。`ADR-0012` 同步修订该不可逆兼容决策。

### 2026-07-28 维护者增量：完整移除 Agent Profile 与未发布 format 2

维护者确认产品仍处于开发测试阶段，不保留 Agent Profile 兼容。实现必须删除 `AgentProfile` 数据模型、
payload collection、Profile permission rule、Core/FFI/Tauri CRUD、renderer contract、Broker Profile fallback、
Profile ID discovery 与旧记录读取。旧 format 2 不迁移、不解密，在 KDF 前拒绝；测试 Vault 直接重建。

managed-web recipe 与 SSH tunnel endpoint 改由 Rust-owned typed `AgentConnectorDefinition` 保存。该记录不拥有账号、
credential 或 client permission，不通过 MCP/renderer 暴露 CRUD，只向 exact Vault item 投影安全 action catalog。
该阶段曾允许 development format 1 经主密码认证后一次性迁移；本文件上一条维护者增量已撤销该兼容。
当前只接受 format 3，其他版本在 KDF 前拒绝。持久授权继续只由独立 AEAD 规则库拥有；`ADR-0012`
冻结当前格式与所有权决策。

### 2026-07-28 维护者增量：Access-token Secret 直接 HTTP 与路径权限

维护者否决 authenticated HTTP/credential lifecycle 的 Profile/ConnectorDefinition 预配置体验，要求与 SSH direct
action 对齐。`access-token` Secret 现在是 HTTP/lifecycle 唯一 account/credential owner，`website` 固定 HTTP(S)
origin/base path；Agent 直接提交精确 method/path 和有界业务参数，Broker 编译 immutable ActionPlan。公共 HTTP
contract 升级为 v2，删除命名 `operation` 作为 direct Secret 的入口。HTTP method 定义风险下限，持久权限使用
`http-path-v1` exact/完整 segment `*`/terminal `**` typed predicate；Agent 不能提交 wildcard，只有原生授权 UI 可以
从本次 canonical path 生成 pattern。Credential lifecycle 显式引用 managed/control access-token Secret 和 exact
transaction method/path，继续由 Rust broker 拥有 candidate、补偿与原子 Secret commit，不再读取或创建 Profile。

该安全决策由 `ADR-0011` 冻结。实施必须同时升级 registry/shim/IPC parity、authorization store、path canonicalizer、
permission UI、Secret lifecycle health、format-2 pre-KDF refusal 与 HTTP/authn/authorization CT；在这些
垂直切片全部通过前，旧 ConnectorDefinition lifecycle 实现只能作为历史证据，不能被声明为新行为完成。

### 2026-07-28 维护者增量：账户 website 直接拥有 HTTP 网络目标

维护者否决为 HTTP 账户增加 `EndpointTrust`、私网 allowlist、certificate pin 或其他网络信任配置。
`access-token` Secret 已保存的 exact HTTP(S) `website` 就是该账户唯一目标 owner；Agent 无法提交或
替换 scheme、host、port 与 base path。Broker 必须允许该 exact 目标使用 HTTP、HTTPS、localhost、
private/link-local/metadata IP 与证书异常的 HTTPS，不再以 WebPKI 或地址类别作为授权门槛。
此选择明确接受网络窃听、中间人与对端冒充风险；VaultMesh 继续保证凭据不进入 Agent、不跨账户/
exact origin 使用，且 redirect、path escape、header 提交、输出 canary 和动作授权边界不变。

以下 ID 在 Draft 中保留；只有 Change 被 Accepted 后，才按任务 `AGENT-001` 一次性合并进主规格、
YAML 和 Traceability，避免 Draft 行为被误认为当前 Required：

| Proposed Requirement | 冻结的用户结果 | Proposed acceptance |
| --- | --- | --- |
| `REQ-AGENT-001` | 用户首次确认稳定 client key 后永久保留配对直至撤销；每次连接自动创建不可管理、不可恢复的内部 session | `CT-AGENT-AUTH-001`、`AT-AGENT-PAIRING-001` |
| `REQ-AGENT-002` | Agent 可以分页列出非秘密 Vault 账号 metadata 并调用动作工具，但不能读取任何凭据原文或 internal definition ID | `CT-AGENT-PROTOCOL-001`、`CT-AGENT-SECRET-001` |
| `REQ-AGENT-003` | 每次调用绑定 client key、session、account、target、capability、规范化请求和 expiry；多账号选择确定且 fail closed | `CT-AGENT-POLICY-001`、`CT-AGENT-ACCOUNT-001` |
| `REQ-AGENT-004` | Agent 可以执行受策略约束的 SSH exec、SFTP、签名、公钥安装和可选 PTY，而密码/私钥/passphrase 不离开 Rust adapter | `CT-AGENT-SSH-001`、`CT-AGENT-PTY-001`、`AT-AGENT-SSH-001` |
| `REQ-AGENT-005` | Agent 可以访问账户 exact HTTP(S) 目标，认证材料内部注入且不跨账户/origin；网络地址类别与证书异常不另建配置或拒绝 | `CT-AGENT-HTTP-001`、`AT-AGENT-HTTP-001` |
| `REQ-AGENT-006` | Agent 可以在 VaultMesh 隔离浏览器 session 中登录、导航和提取批准信息，不能读取密码、Cookie 或完整 DOM | `CT-AGENT-WEB-001`、`AT-AGENT-WEB-001` |
| `REQ-AGENT-007` | Removed before release：固定 CLI connector 不再作为当前 Agent 能力；旧 format-2 记录也不再读取 | N/A（旧 CLI 测试 ID retired） |
| `REQ-AGENT-008` | TOTP、Email OTP、recovery code、Passkey、生成/轮换等通过 fill/submit/sign/store 动作消费，不返回秘密值 | `CT-AGENT-AUTHN-001`、`AT-AGENT-AUTHN-001` |
| `REQ-AGENT-009` | Superseded before release；旧独立权限申请与 compatibility bridge 已删除 | Retired：`CT-AGENT-PERMISSION-001`、`AT-AGENT-PERMISSION-001` |
| `REQ-AGENT-010` | Agent 搜索/筛选非秘密账号 metadata 后直接提交动作；shim 单次转发，broker 绑定 connection session 并编译 Canonical ActionPlan | `CT-AGENT-DISCOVERY-002`、`CT-AGENT-AUTHZ-002`、`AT-AGENT-AUTHZ-002` |
| `REQ-AGENT-011` | 统一 typed Action Lease；SSH 支持 exact/safe/all structured command 的 once/connection/persistent allow/deny，超时后 once 仅允许下一次调用，持久规则进入 OS-key-protected 本地 AEAD store | `CT-AGENT-AUTHZ-002`、`CT-AGENT-SSH-SAFE-001`、`AT-AGENT-AUTHZ-002` |
| `NFR-AGENT-001` | 凭据及其可逆表示不进入 MCP/IPC response、日志、audit、crash、snapshot、命令行或 Agent 可读临时状态 | `CT-AGENT-SECRET-001`、`CT-AGENT-AUDIT-001` |
| `NFR-AGENT-002` | revoke、final lock、disconnect、cancel、timeout、process exit 和 expiry 清除 session、session、PTY、browser、child process 与敏感 buffer | `CT-AGENT-LIFECYCLE-001` |

公共能力必须使用 `../../specs/agent-capability-broker.md` 中的穷举工具目录、风险等级和 adapter 约束。新增工具或放宽参数不属于
实现细节；必须回到本 Work 或后续 CHG 完成规格、policy、测试和审批。

### 本次维护者增量：软件拥有 Agent 锁定状态

维护者要求 MCP 不再暴露 `vaultmesh_session_status` 或 `vaultmesh_access_lock`。两者已从公共 registry、MCP shim
和 broker dispatch 移除，不再作为解锁绕过或调用锁定入口；MCP 调用在需要 Vault 时继续由软件返回 typed
`mcp-locked`，Agent 解锁窗口、idle/absolute lock、Vault lock 和管理页锁定仍由 VaultMesh 本地软件控制。
内部 broker lifecycle 与 `agent.access.lock-client` 保留，用于软件侧清理调用连接 authority/resource。

### 本次维护者增量：移除冗余能力枚举工具

维护者确认所有公共 MCP 工具 schema 已通过稳定的 `tools/list` 注入 Agent；独立的 capability metadata 工具不再
承担授权或执行职责，且实现只重复 registry。因此从 v2 registry、broker dispatcher、Agent unlock exception 和
相关测试移除。当前公共目录为 32 个工具；实际授权仍只由每次 `tools/call` 在 broker 内按 pairing、session、
account、permission、policy、risk 和 confirmation fail closed 裁决。除本地 UI 请求外，所有 MCP tool 继续要求当前
连接自己的 Agent unlock lease。

### 本次维护者增量：移除低收益固定 CLI 代理

维护者确认常用 Agent 已具备 GitHub、HTTP、网页和本地文件等连接能力，固定 CLI 代理的公共工具与专用
supervisor 不再带来足够收益。因此移除其 registry、dispatcher、policy、operation plan、adapter、账户发现
和执行测试链路。旧 CLI/format-2 记录不再反序列化或投影，并在 envelope 版本检查阶段 fail closed。

### 2026-08-05 维护者增量：移除低收益凭据生命周期工具

维护者确认 `vaultmesh_credential_generate_and_store`、`vaultmesh_credential_test`、
`vaultmesh_credential_rotate` 与 `vaultmesh_credential_revoke` 的使用面过窄，不值得继续维护远端事务、补偿、
双 Secret 管理和专用 fixture。因此从 v2 公共 registry、账号 action 投影、ActionPlan、permission/policy、executor、
Core/FFI 写入 API 与测试脚本中完整移除，公共工具目录收敛为 28 个。凭据 CRUD、生成、轮换和撤销只由本地 UI
拥有；普通 direct HTTP 保持不变，但不提供 lifecycle transaction。既有开发 Vault 的 revoked/needs-review
reserved scope 只保留 renderer-hidden、fail-closed 读取，禁止因移除 writer 而恢复 Agent authority。

## 非目标

- 不提供任何 secret getter、明文导出、Vault dump、恢复后门或 Agent 侧 reveal/copy。
- 不允许 Agent 或 MCP tool 提交主密码/PIN/biometric；MCP Vault access 只能由用户在独立、最小权限的
  原生 Agent 解锁窗口中建立，factor 不进入 MCP/Agent IPC。
- 不提供任意 binary、任意 shell 加 secret env、任意 curl、任意网页 DOM 或任意数据库 SQL。
- 首版不提供云端 Agent、网络监听 MCP、VaultMesh 服务端、账号系统、同步或分享。
- 不承诺远程命令/API/网页返回的业务数据全部非敏感；它们必须有独立 output policy。
- 不把已批准但恶意的远端服务、HTTP/TLS 网络攻击、被替换的本地 binary、被攻陷 OS/process/browser 纳入可由客户端
  绝对防御的凭据保密保证；对已选 HTTP 账户只保证 exact account/origin 绑定、最小权限与有界结果。
- 不复用 Chromium extension 的配对、unlock 或 Browser RPC session 作为 Agent 授权。

## 影响范围

- Desktop：新增原生 Agent 配对、授权、Vault 账号活动、审计和紧急撤销 UI。
- Desktop：新增独立 `agent-unlock` 系统窗口与 Agent-only Vault runtime；配对、MCP 解锁和动作授权
  使用三个不同 capability、状态机和 UI 路由。
- Desktop：默认以 connector-specific builder 和动态权限卡片替代手写 JSON；JSON 只保留高级受校验入口。
- Tauri Rust runtime：新增 broker、owner-only IPC、policy engine、MCP tool dispatcher、adapter 和 cleanup owner。
- Core/payload：新增 default-empty 的 Rust-owned internal ConnectorDefinition collection、validation 和原子 mutation。
- MCP：升级 local stdio adapter 和 MCP tool contract v2；adapter 不拥有秘密或策略，也不在每次调用前轮询 session。
- SSH：复用 Rust SSH service 的认证与 host fingerprint 基础；Agent 路径不得复用外部终端临时私钥文件。
- HTTP/managed web：新增固定 adapter；生产依赖与许可必须在 Accepted 后单独评审。
- Browser extension/native host：不作为 Agent transport；现有 Browser RPC 行为不得改变。
- Passkey/Email OTP：复用 Rust-owned service，但使用独立 Agent policy 和 native confirmation。
- Vault envelope：只创建、写入和读取 format 3；所有其他版本在 KDF 前拒绝，不存在旧格式 reader、迁移、
  降级或专用备份入口。
- ABI：不向 C ABI 或 renderer 暴露 Agent secret operation；如实现需要变更公共 ABI，必须拆出新 CHG/ADR。
- 发布：macOS 与 Windows packaged app、Codex 和 OpenCode E2E、依赖/sandbox/安装卸载均进入 Gate。

## 实现约束

架构与协议细节由 `../../specs/agent-capability-broker.md`、`ADR-0007` 和 `ADR-0008` 约束。实施必须遵守以下不可协商条件：

1. Tauri Rust privileged runtime 是 Agent authorization、secret use、policy、audit 和 cleanup 的唯一 owner。
2. MCP adapter 只能做 stdio framing、schema negotiation 和 owner-only IPC forwarding；崩溃或被读取不能得到 secret。
3. 工具 registry、request schema、risk tier 和 policy 必须由一个机器可读 owner 生成 MCP list、Rust dispatch、UI 文案和 parity tests，禁止复制枚举漂移。
4. `account_ref` 是 opaque local ID；Agent 不得按 title 模糊选择生产账号。歧义必须打开 VaultMesh native picker 或拒绝。
5. fresh confirmation 绑定 canonical request hash；确认后改变任何 account/target/method/command/body digest 必须拒绝。
6. secret 只在 adapter 的最小同步作用域内解密，使用 zeroizing buffer；不得跨 `await` 长期持有，必须在 terminal path 清理。
7. SSH 认证不得通过 shell、PTY、命令参数、环境或临时 private-key 文件完成；sudo 不自动输入密码。
8. HTTP exact account/origin、DNS 当次连接固定、redirect、method/path/body/response schema 每次检查；
   IP 地址类别与 TLS 证书异常不拒绝账户保存的 exact target，credential 不跨 origin。
9. managed web 的 credential entry/login submit 是 broker-owned 原子阶段；Agent 不能在该阶段访问 CDP、DOM、Cookie、storage 或 network headers。
10. 固定 CLI 与旧 Agent 账号配置已从公共能力、数据模型和执行边界移除；format 2 必须在 KDF 前 fail closed，
    不得通过只读兼容路径恢复。
11. final lock、revoke 和 session expiry 必须先阻断新请求，再取消/关闭所有 child resource，最后清除 core authorization；重复 cleanup 幂等。
12. Agent audit 只记录非秘密 envelope：client key、session、account label/opaque ID、capability、target class、risk、decision、timing、result class 和 bounded counts。
13. Agent 只引用发现目录中的 exact Vault account 并直接调用动作工具；Broker 从 Vault 字段、内置规则或内部
    ConnectorDefinition 编译 Canonical ActionPlan。Agent 不能定义 display/target/schema/risk/scope，缺失规则默认
    Ask；R2–R4 继续逐次 canonical confirmation。
14. SSH exec 只引用 exact SSH Vault item；命令使用结构化 program/arguments，exact/safe/all-command scope 与
    once/connection/persistent lifetime 正交。持久权限进入 OS-key-protected AEAD owner-only store并绑定 Vault namespace。
15. Agent Vault access 必须由独立 runtime 与 per-connection unlock lease 拥有；runtime 每次解锁必须绑定桌面
    当前选中的 Vault 路径，但 desktop/browser 解锁不能
    创建 Agent lease，Agent 锁定不能改变 desktop/browser。真实断连、pairing revoke、系统锁定、退出和最后一个
    Agent lease 消失必须清除 Agent runtime、ActionPlan、permission、confirmation 与子资源。

## 任务

| Task | Requirement | 可验证输出 | Test | 状态 |
| --- | --- | --- | --- | --- |
| `AGENT-000` | N/A | 产品负责人接受/拒绝本 Draft；安全负责人接受/拒绝 ADR-0007；所有非目标和风险陈述无歧义 | Review checklist | Pass（2026-07-25 维护者实施指令；接受 Draft 清单与 ADR-0007） |
| `AGENT-001` | `REQ/NFR-AGENT-*` | 接受后新增 Agent 专项 Spec，把保留 Requirement/Test 合并到功能需求、Scope、Security、Architecture、Data、Test 与 Traceability；YAML 路由更新并进入 Implementing | `pnpm docs:check` | Pass（2026-07-26；71 Markdown / 38 YAML / 42 Requirements / 99 Test IDs / 7 ADRs / 25 routed Changes） |
| `AGENT-002` | `REQ-AGENT-001`–`003` | MCP/IPC v1 schema、生成式 registry、stdio shim、owner-only socket/pipe、client pairing、connection session、metadata-only list 与 native revoke UI | `CT-AGENT-PROTOCOL-001`、`CT-AGENT-AUTH-001`、`CT-AGENT-POLICY-001` | Pass（2026-07-25；macOS 自动化与 Windows MSVC target 源码编译；真实 Windows packaged AT 归 `AGENT-012`） |
| `AGENT-003` | `REQ-AGENT-003`、`NFR-AGENT-001` | Historical encrypted account configuration slice | `CT-AGENT-ACCOUNT-001`、`CT-AGENT-AUDIT-001` | Superseded before release by `AGENT-018`/`ADR-0012`；实现与 format 2 compatibility 已删除 |
| `AGENT-004` | `NFR-AGENT-001`、`002` | secret canary harness、redaction/output budget、cancel/revoke/final-lock cleanup、malformed/replay/expiry suite | `CT-AGENT-SECRET-001`、`CT-AGENT-LIFECYCLE-001` | Implementing（broker 累计输出、SSH/HTTP/managed-web canary、slowloris、disconnect/expiry cancel、file/result/PTY/tunnel/browser/OTP/Passkey request cleanup CT Pass；packaged client/platform matrix 待完成） |
| `AGENT-005` | `REQ-AGENT-004` | SSH non-PTY exec vertical slice：host-key pinning、password/key/agent auth、template commands、bounded stream、timeout/cancel | `CT-AGENT-SSH-001`、`AT-AGENT-SSH-001` | Implementing（SSH item direct ActionPlan 已覆盖 structured exec、SFTP upload/download、公钥安装、本地 file/result handle、固定 target/fingerprint、Vault auth、输出边界与 cancel；CT 及本机真实 OpenSSH integration Pass，packaged AT 待完成） |
| `AGENT-006` | `REQ-AGENT-005` | HTTP adapter：exact account/origin、auth injection、HTTP/HTTPS、全地址类别、self-signed TLS、DNS connection pin、redirect deny 与 schema output | `CT-AGENT-HTTP-001`、`AT-AGENT-HTTP-001` | Implementing（direct access-token Secret 的 HTTP/HTTPS、loopback/private/link-local/metadata literal target、self-signed TLS、Bearer、redirect deny 与有界 JSON CT Pass；packaged AT 待完成） |
| `AGENT-007` | `REQ-AGENT-007` | Removed before release：固定 CLI 代理公共能力、数据模型与执行链路删除 | N/A（旧 CLI 测试 ID retired） | Removed（历史 CLI 记录读取 fail closed） |
| `AGENT-008` | `REQ-AGENT-004`、`NFR-AGENT-002` | SSH PTY/SFTP/tunnel 可选能力、ANSI/OSC sanitization、session quota、foreground revoke | `CT-AGENT-PTY-001`、`AT-AGENT-SSH-001` | Implementing（PTY open 使用 R3 exact ActionPlan，read/write/resize/close 由绑定 client/session/account 的 sessionRef 派生且不重复授权；固定 tunnel 仅从唯一匹配 ConnectorDefinition 投影，实际 PTY/SFTP/direct-tcpip、sanitization、quota、cancel/cleanup CT Pass；packaged AT 待完成） |
| `AGENT-009` | `REQ-AGENT-006` | isolated managed-web runtime、per-account session、atomic login、bounded action/extract/download、session destruction | `CT-AGENT-WEB-001`、`AT-AGENT-WEB-001` | Implementing（typed recipe、incognito hidden WebView、exact-origin navigation、native eval callback、atomic login、typed extract/action/download、opaque protected target、expiry/revoke/final-lock cleanup CT Pass；真实网站 packaged AT 待完成） |
| `AGENT-010` | `REQ-AGENT-008` | OTP/recovery consume 与 Passkey/sign；无 secret response；credential lifecycle 工具保持移除 | `CT-AGENT-AUTHN-001`、`AT-AGENT-AUTHN-001` | Implementing（TOTP/Email OTP/recovery 与 broker-owned Passkey requestRef producer CT Pass；四个 credential lifecycle 工具、ActionPlan、执行链、Core/FFI writer、HTTP protected body 和 fixture 已移除并通过回归；真实站点与 packaged app `AT-AGENT-AUTHN-001` 待完成） |
| `AGENT-011` | `REQ-AGENT-001`–`008` | Codex/OpenCode 安装、工具发现、approval/revoke、重启/锁定和多账号 E2E；无客户端专属安全旁路 | `CT-AGENT-CODEX-001`、`CT-AGENT-OPENCODE-001` | Implementing（真实 stdio shim process 对 owner-only UDS 的稳定 28-tool list、session-gated call/revoke、native confirmationRef→confirmationTicket 重试与本地 UI 唤起 E2E Pass；本机 Codex/OpenCode 配置解析 Pass；真实客户端 restart/lock/multi-account E2E 待完成） |
| `AGENT-012` | 全部 | macOS/Windows packaged AT、依赖许可/supply-chain、升级/降级、卸载清理、独立安全评审与 release evidence | `AT-AGENT-MACOS-001`、`AT-AGENT-WINDOWS-001` | Implementing（unsigned macOS `.app` 内容/sidecar identity 与生产 pnpm 依赖审计 Pass；签名 macOS、Windows packaged AT、RustSec 残留、开发工具链残留及独立安全评审待完成） |
| `AGENT-013` | `REQ-AGENT-002`、`009` | Historical persisted account-builder slice | `CT-AGENT-ACCOUNT-001`、`CT-AGENT-PERMISSION-001`、`AT-AGENT-PERMISSION-001` | Superseded before release by `AGENT-018`；builder、CRUD、renderer/API 与 compatibility 全部删除 |
| `AGENT-014` | `REQ-AGENT-009` | Historical memory-only generated account-configuration slice | `CT-AGENT-ACCOUNT-001`、`CT-AGENT-PERMISSION-001`、`AT-AGENT-PERMISSION-001` | Superseded before release by direct Vault-item ActionPlan and `AGENT-018`；bridge/fallback 已删除 |
| `AGENT-015` | `REQ-AGENT-001` | 首次未配对连接显示独立系统配对窗口且不打开主窗口；配对窗口只确认 integration identity，不要求、继承或提交任何 Vault 解锁 factor；独立最小 capability、MCP probe 断开后有界保留、批准后当前/下一连接继续、拒绝/关闭终止，设置页只保留配对管理 | `CT-AGENT-AUTH-001`、`AT-AGENT-PAIRING-001` | Implementing（配对与解锁已由 `AGENT-017` 分离；packaged AT 待完成） |
| `AGENT-016` | `REQ-AGENT-010`、`011` | accounts 搜索/筛选→SSH direct exec；移除 permission/Profile 前置链路、shim session 预轮询、重复 parse/fake executor；实现 Canonical ActionPlan、typed lease、safe catalog、持久授权库和统一授权 UI，并映射 upload/HTTP/Web | `CT-AGENT-DISCOVERY-002`、`CT-AGENT-AUTHZ-002`、`CT-AGENT-SSH-SAFE-001`、`AT-AGENT-AUTHZ-002` | Implementing（SSH 全工具与 local file/result 已接入 direct itemRef ActionPlan；HTTP、managed-web、OTP/recovery/Passkey 已接入 ActionPlan；固定 CLI 与 credential lifecycle 公共链路已移除；统一目录、system Profile bridge 删除、exact/同 capability 持久权限及执行前重验证 CT Pass；packaged AT 待完成） |
| `AGENT-017` | `REQ-AGENT-001`、`002`、`NFR-AGENT-002` | 配对、MCP 解锁和动作授权三层隔离；Agent-only runtime、per-connection unlock lease、独立解锁窗口、专用 PIN namespace、caller-only/idle/absolute lock、最后 lease/final-lock cleanup 与 desktop/browser 隔离 | `CT-AGENT-UNLOCK-001`、`CT-AGENT-LIFECYCLE-001`、`AT-AGENT-UNLOCK-001` | Implementing（独立 runtime/lease/gate/window/PIN、空闲/最长连续解锁策略、活动计时和 timeout-next-retry CT Pass；packaged Codex/OpenCode AT 待完成） |
| `AGENT-018` | `REQ-AGENT-003`、`007`、`010`、`NFR-COMPAT-001` | 删除 AgentProfile/权限/CRUD/read API/HTTP connector compatibility；只保留 Rust-owned managed-web recipe 与 fixed SSH tunnel definition；format 2 pre-KDF refusal，v1/v3 format contract | `CT-AGENT-ACCOUNT-001`、`CT-AGENT-DISCOVERY-002`、`CT-AGENT-AUTHZ-002`、`CT-COMPAT-001` | Superseded by `AGENT-019` 的单一 format 3 契约；Agent Profile 清理结果继续有效 |
| `AGENT-019` | `REQ-AGENT-003`、`NFR-COMPAT-001` | Historical：Vault 统一写入 format 3，并曾保留一次性 development format 1 迁移 | `CT-AGENT-ACCOUNT-001`、`CT-COMPAT-001` | Superseded by `AGENT-020`；单一 writer 结果继续有效 |
| `AGENT-020` | `REQ-AGENT-003`、`NFR-COMPAT-001` | format 3 成为唯一 create/write/read 格式；删除所有旧格式 reader、迁移、专用备份、quick-unlock 特判与 fixture | `CT-AGENT-ACCOUNT-001`、`CT-COMPAT-001` | Pass（Core/FFI 严格 reader 与全非当前版本 pre-KDF refusal 通过；完整 Gate 证据见下） |
| `AGENT-021` | `REQ-AGENT-004`、`NFR-AGENT-001` | R3 exact-only OpenSSH host setup：软件内加密 SSH key/binding、只读 alias 卡片/编辑表单、专属 ED25519 key、远端安装/验证、pending recovery、无 manifest、managed alias/config 与 no-secret response | `CT-AGENT-PROTOCOL-001`、`CT-AGENT-SSH-001`、`CT-AGENT-SECRET-001`、`AT-AGENT-SSH-001` | Implementing（registry/ActionPlan、Vault 原子写/重启恢复、安全 alias 投影、卡片/编辑页、本地 owner-only create-new、无 manifest、alias/config/symlink/target drift、pending reuse 与无 key/path response 自动化 Pass；真实服务器 packaged `ssh <alias>` AT 待完成） |
| `AGENT-022` | `REQ-AGENT-001` | 独立 Agent Touch ID provision/失效、每 request 单次自动提示、错误反馈与主密码 Enter/按钮 fallback | `CT-AGENT-UNLOCK-001`、`AT-AGENT-UNLOCK-001` | Implementing（自动化 Pass；packaged Touch ID AT 待执行） |

依赖顺序固定为：`AGENT-000 → 001 → 002 → 003 → 004 → 005`。HTTP 可以在 SSH non-PTY
稳定后并行；PTY 必须晚于 SSH non-PTY，managed web 必须晚于 HTTP/output policy；客户端 E2E 和
平台 Gate 最后执行。任何阶段失败不得以 mock、TODO、静态成功响应或降低测试代替。

### 实施证据

- `AGENT-022` MCP Touch ID 优先解锁（2026-09-09）：新增独立 `agent-biometric-unlock.json` 与
  `com.vaultmesh.desktop.agent-biometric` OS credential namespace；桌面 Touch ID enable/成功 unlock 或主密码
  unlock 会在 Rust privileged runtime 内幂等 provision，disable、create、restore、改密与 Vault drift 同步失效。
  `agent-unlock` capability 新增唯一 biometric command，renderer 对每个 `unlockRef` 自动调用一次；失败显示内联
  alert，并保留主密码 form 的 Enter/按钮路径。RED 证据为新增两条 renderer test 分别因无 biometric invoke、无
  alert 失败；GREEN 为 desktop Vitest 30 files / 142 tests、TypeScript typecheck、Rust focused capability test 与
  已编译 Tauri Rust test binary 243 passed / 1 ignored。直接 `cargo test -p vaultmesh-tauri-desktop` 的静态库归档因
  主机仅余约 660 MiB 报 `No space left on device`；真实 packaged Touch ID `AT-AGENT-UNLOCK-001` 待执行，Work 保持
  Implementing。

> 2026-07-27 及更早的条目记录当时已被 `ADR-0012` 取代的实现证据，不代表当前兼容面；当前结果以
> `AGENT-020`、`AGENT-021` 和下方清理证据为准。

- Credential lifecycle removal（2026-08-05）：从公共 v2 registry、MCP tools/list、账号 action catalog、
  permission/policy、Canonical ActionPlan、executor、Rust HTTP protected-body 分支、Core/FFI mutation API 与
  专用 Python fixture 完整移除 generate/test/rotate/revoke，公共目录由 32 收敛为 28。Secret summary/detail
  不再暴露 lifecycle state；既有开发 Vault 的 revoked/needs-review reserved scope 仍由 Core 内部隐藏并在
  direct HTTP/ApiEnvironment authority 判断中 fail closed，没有 writer 或恢复入口。验证：desktop Vitest
  29 files / 127 tests；Core 10 unit + 38 integration；FFI 39 tests；Tauri 213 passed / 1 ignored（既有本机
  OpenSSH daemon integration）；Agent MCP 4 unit + 6 stdio E2E；TypeScript typecheck、四 package all-target
  Clippy `-D warnings`、`pnpm docs:check` 与 `git diff --check` Pass。当前 rustfmt 1.9 的全库 check 只报告未修改
  `vaultmesh-native-host.rs` 的既有 import-order 差异，本次修改文件没有格式差异。

- `AGENT-021` OpenSSH host setup（2026-07-29）：新增
  `vaultmesh_ssh_host_setup(accountRef, alias)` 与 `ssh-host-setup` capability；Agent 只提交小写受限 alias，
  broker 固定 exact SSH item/target/Host Key、R3 exact-only risk、ED25519 generator、bootstrap credential、
  key-login verification 和安全 action display。Rust 先通过 Core/Runtime 原子事务把专属 key 与 managed binding
  保存为软件内加密 SSH key 记录，再在 `~/.ssh/vaultmesh/hosts/<alias>` 以 staging-directory rename 发布
  owner-only key；不创建 manifest。远端验证通过后才创建独立 fragment，并原子把唯一 managed Include
  提升到 `~/.ssh/config` 首个有效项；既有 Host、文件、symlink、account/target/Host Key drift 均 fail closed。
  远端失败/取消/结果不确定保留不进入 config 的 exact pending identity，显式重试先用同一 key 验证并幂等恢复。
  MCP 只返回 alias、`ssh <alias>`、opaque credentialRef、公共 fingerprint 和状态，不返回 key、host、username 或 path。
  软件卡片独立显示 `ssh <alias>`，编辑页只读显示 alias 并隐藏托管 key replacement/clear。验证：
  Tauri Rust 206 passed / 1 ignored、MCP 4 unit + 6 stdio E2E、desktop Vitest 26 files / 114 tests、
  TypeScript typecheck、docs check、Rust fmt、Tauri all-target Clippy `-D warnings` 与 `git diff --check` Pass。
  ignored 项是需要本机 OpenSSH daemon 的既有 integration；签名 macOS/Windows packaged app + 真实服务器
  `AT-AGENT-SSH-001` 未执行，因此 Change 保持 Implementing。

- `AGENT-020` format-3-only reader（2026-07-28）：删除 Core format-1 常量、迁移 reader、fixture feature 和 session
  migration API；删除 FFI/Tauri migration helper、`.format1.bak` writer、主密码/quick-unlock 特判和相关迁移测试。
  主密码、Vault Key quick unlock、Agent、Browser 与 restore 统一走严格 format-3 reader，所有其他版本在 Argon2 前
  拒绝且不修改文件。验证：Core 8 unit + 28 integration、FFI 24 unit + 11 contract、Tauri 199 passed / 1 ignored、
  MCP 4 unit + 6 stdio E2E、desktop Vitest 24 files / 111 tests、TypeScript typecheck、docs check、Rust fmt、
  四 package all-target Clippy `-D warnings` 与 `git diff --check` Pass。签名 macOS/Windows packaged AT 仍归
  `AGENT-012`，因此 Change 保持 Implementing。

- `AGENT-019` single format 3 writer and format-1 migration（2026-07-28）：Vault create/write/normal-read、内部
  ConnectorDefinition 和持久 audit 统一使用 format 3；Core/FFI 删除 format 1 默认、条件写入/降级和临时 audit
  分支，renderer status 不暴露 Vault format。Tauri 主密码路径对 format 1 先认证，再创建同目录、owner-only、
  不可覆盖且内容一致的 `.format1.bak`，确认源未漂移后原子重写 format 3；错误密码、备份/写入失败保持原文件。
  PIN/biometric quick unlock 明确要求改用主密码。format 2/unknown 在 Argon2 前拒绝。验证：Core 10 unit + 28
  integration、FFI 27 unit + 11 contract、Tauri
  199 passed / 1 ignored、MCP 4 unit + 6 stdio E2E、desktop Vitest 24 files / 111 tests、TypeScript typecheck、
  docs check、Rust fmt 与四 package all-target Clippy `-D warnings` Pass。签名 macOS/Windows packaged AT 尚未完成，
  因此 Change 保持 Implementing。

- `AGENT-018` Agent Profile removal（2026-07-28，已由 `AGENT-019` 的格式契约取代）：删除 Core/FFI/Tauri/renderer/MCP 中的旧模型、payload 字段、
  CRUD/read/status contract、permission rule、Broker fallback、HTTP connector 与 Basic/OAuth/upload/download 执行链；
  MCP/renderer 不暴露 internal definition ID 或 CRUD。SSH/HTTP 直接使用 exact Vault item，只有 managed-web recipe
  与 fixed SSH tunnel endpoint 使用 Rust-owned `AgentConnectorDefinition`。当时采用 format 1/3 双格式，现已由
  `AGENT-019` 删除。自动化：Core 8 unit + 29 integration、FFI 23 unit + 11 contract、
  Tauri 199 passed / 1 ignored、MCP 4 unit + 6 stdio E2E、desktop Vitest 24 files / 111 tests、TypeScript typecheck、
  docs check、Rust fmt 与四 package all-target Clippy `-D warnings` Pass。签名 macOS/Windows packaged AT 尚未完成，
  因此 Change 保持 Implementing。

- `AGENT-005/008/016` complete direct SSH tool chain（2026-07-27）：SSH Vault item 继续作为唯一 Agent
  account/credential owner，账号目录现在安全投影 structured exec、upload/download、公钥安装、PTY 以及本地
  file select/result save；tunnel 只有存在与该 item、host/port 和 Host Key 完全匹配的唯一内部
  ConnectorDefinition 固定 endpoint 时才投影。exec 之外的每个入口也会按
  `(client, accountRef, tool, canonical parameters digest)` 编译独立 immutable ActionPlan；upload/download 路径、
  file/result/public-key handle、PTY terminal 与 tunnel endpoint 不能跨工具或参数复用。R1/R2 支持 exact/all
  action scope，R3 保持 exact-only 并逐次确认。Executor 在秘密使用前重验 SSH item target/auth，tunnel 还逐字段
  重验辅助 ConnectorDefinition；PTY 只在 open 授权，后续 read/write/resize/close 由绑定 client/session/account
  的 sessionRef 派生，disconnect/expiry/revoke/final lock 清理。PTY write 与公钥安装补齐 cancellation 检查和有界
  写入。新增完整目录、七类 direct SSH 非 exec ActionPlan、PTY 子操作不重复授权，以及 transfer/key/PTY/fixed
  tunnel secret-use collector 回归。验证：Tauri Rust 204 Pass / 1 ignored（单线程全量）、MCP 4 unit + 6 stdio
  E2E、renderer 24 files / 112 tests、Clippy `-D warnings`、TypeScript typecheck、fmt 与 diff check Pass；签名
  macOS/Windows packaged `AT-AGENT-SSH-001` 仍待执行。

- `AGENT-016` HTTP ConnectorDefinition ActionPlan extraction（2026-07-27）：既有 encrypted
  `AgentProfile` 只作为 format 2 内部 ConnectorDefinition 兼容记录读取；`vaultmesh_http_request`、
  `vaultmesh_http_upload` 与 `vaultmesh_http_download` 在授权前均编译 session-bound
  `AgentDirectHttpPolicy`，并以 client、opaque account、具体 tool 与完整 canonical parameters digest 隔离活动
  ActionPlan，上传、下载及不同 operation 不得串用。ActionPlan 固定 origin、auth strategy、credential refs、
  method/path/body mode、schema/risk、private-host/TLS pin 与 output policy；executor 在解密 credential 前重新从
  ConnectorDefinition 编译并逐字段比较，漂移时 fail closed。旧 Profile permission rules 仍不参与新授权，
  exact/同 target capability 的 connection/persistent lease、R2 fresh confirmation 与 broker-owned file/result
  handle 语义保持不变。新增 request compatibility extraction、upload/download distinct ActionPlan、永久 exact
  restore、R2 remembered permission 回归。验证：Tauri Rust 200 Pass / 1 ignored（单线程全量；并行 suite 的既有
  CLI stdin 用例单独运行 Pass）、MCP 4 unit + 6 stdio E2E、renderer 24 files / 112 tests、Clippy
  `-D warnings`、typecheck、production renderer build 与 fmt Pass。

- `AGENT-016` managed-web ConnectorDefinition ActionPlan extraction（2026-07-27）：
  `vaultmesh_web_session_open/navigate/extract/act/download/session_close` 在授权前从内部 ConnectorDefinition 编译 session-bound
  `AgentDirectConnectorPolicy`。ActionPlan 固定 opaque account、connector kind、具体 tool、命名 recipe/operation、
  canonical parameters digest、risk、用户可读 target 与完整 target/credential/capability/output policy digest；
  executor 在打开隔离 Web session、导航、提取、动作、下载、关闭或启动 pinned binary 前重新编译并逐字段比较，
  connector、recipe、参数 grammar、binary identity、credential ref 或 output policy 漂移时 fail closed。connection
  exact/all 与 persistent exact/all 只恢复授权裁决，每次调用仍按当前参数生成独立 immutable ActionPlan；R2+ 仍要求
  fresh confirmation。账号目录从 ConnectorDefinition 推导 Web download 的 `vaultmesh_result_save`，并沿用 HTTP
  upload/download 的 local-file/result helper 投影，不向 Agent 返回 path、selector、binary 或 secret。新增 Web/CLI
  direct plan、CLI all-scope 参数隔离、目录 action/helper 投影及 secret-use 重验证回归。验证：Tauri Rust 208 Pass /
  1 ignored、MCP 4 unit + 6 stdio E2E、renderer 24 files / 112 tests、Clippy `-D warnings`、TypeScript
  typecheck 与 fmt Pass。

- `AGENT-010/016` protected action direct ActionPlan extraction（2026-07-27）：managed-web 的
  `vaultmesh_otp_fill`、`vaultmesh_recovery_code_consume`、`vaultmesh_passkey_request_begin/perform`
  以及 HTTP credential lifecycle 的 generate/test/rotate/revoke 均在授权前编译
  `AgentDirectConnectorPolicy`。OTP/recovery 的随机 `targetRef` 与 Passkey 的 `sessionRef + recipe` / 单次
  `requestRef` 进入 canonical parameters digest；ActionPlan 同时固定 connector kind、完整 recipe/operation table、
  credential refs、risk ceiling、target 和 output policy digest。Executor 在填入 OTP/recovery、捕获/完成 Passkey
  request 或读取 managed/admin Secret 前重新编译并逐字段比较；缺少 direct plan、opaque ref 格式错误或 connector
  漂移全部 fail closed。既有 protected target/request 的 client/session/account/origin/expiry/single-use 校验、recovery
  success 后 compare-and-consume、Passkey 页面 Promise completion 与 credential apply/test/commit/rollback/revoke
  补偿事务保持原所有者。目录按 typed recipe 投影 OTP、recovery 与 Passkey 两阶段工具，按 credential lifecycle
  policy 投影四种动作，并过滤未被 capability policy 允许的 recipe action。新增 protected direct authorization、资源
  引用校验、目录投影、lifecycle risk 与 secret-use 前 target drift 回归。验证：Tauri Rust 209 Pass / 1 ignored、
  Clippy `-D warnings` 与 fmt Pass；packaged real-site AT 待执行。

- `AGENT-017` independent MCP unlock（2026-07-27）：配对窗口已移除主密码/PIN 输入，只负责持久
  integration identity；首个需要 Vault 的 MCP 调用由 broker 返回 typed `mcp-locked` 并打开独立、预热、
  content-protected 的 `agent-unlock` 原生窗口。Agent 使用与 desktop/browser 分开的 `DesktopRuntime`、PIN
  keyring service/record 和 per-transport UUID lease；解锁读取桌面当前选中的 Vault 路径，但不借用其解锁
  session。全部 Vault-backed 工具在 dispatch 与 executor 两层检查 lease；VaultMesh 软件侧 Agent lock 只锁调用连接，
  安全中心的 Agent 摘要卡片进入独立 `/vault/security/agent` 管理路由，不再通过安全中心弹窗承载 MCP
  解锁、PIN、授权规则、客户端和审计管理；管理页可锁定单条或全部 MCP 连接，并独立配置默认 15 分钟空闲
  锁定（5/15/30/60 分钟）和默认 8 小时最长连续解锁（1/4/8 小时）。owner-only 非秘密设置原子持久化；每条
  lease 记录创建、最后活动和执行中状态，活动只刷新空闲计时，绝对时限不会延长。到期按 client 撤销 session、
  permission、continuation 与子资源，最后 lease 到期锁定 Agent runtime。已实现的断连、配对撤销、Vault switch/restore、应用退出及最后 lease
  消失会取消 session、清除
  ActionPlan/permission/confirmation/资源并锁 Agent runtime，桌面锁定不再清理 Agent runtime，Agent 锁定也不改变
  desktop/browser。传输调用等待 30 秒后返回稳定 timeout，但原生申请有界保留，用户稍后完成解锁可供下一次
  MCP 重试；并发 unlock request 在同一原生窗口中逐个推进；主密码/PIN 从不进入 MCP 或 broker IPC。验证：
  `CT-AGENT-UNLOCK-001` 覆盖 runtime/选中 Vault/多连接隔离、并发请求队列、软件触发的 Agent lock、timeout-next-retry
  与最小 capability；renderer 独立窗口测试覆盖 connection label、factor 提交和超时保留。验证：Tauri Rust
  189 Pass / 1 ignored（单线程全量）、vault-ffi 34 个 unit/ABI/
  contract tests、MCP 4 unit + 3 stdio E2E、renderer 23 files / 100 tests、strict clippy、typecheck、docs/fmt/
  diff check 和 production Web build Pass；unsigned macOS `.app`/DMG 打包成功且 app 内包含 release MCP sidecar，
  本机 Codex/OpenCode 配置解析通过。真实 Codex/OpenCode 的 factor/timeout/caller-lock 流程以及 system lock/sleep
  cleanup 仍由 `AT-AGENT-UNLOCK-001` 保持 Not Run。

- `AGENT-004/011` transparent connection-session rotation（2026-07-27）：维护者否决把 15 分钟内部安全 TTL
  解释为 MCP transport 寿命。现已配对且仍存活的连接在旧 session 到期后先清除 lease/pending/direct policy/
  resource，再按同一已验证 client 原子签发新基础 session，不再返回 `session-required` 或要求重连。Vault final
  lock 改为清除 authority、derived account policy 与敏感资源但保留 transport identity；锁定期间 direct action/
  account discovery 返回 retryable `vault-locked`，解锁后同一连接按需获得新基础 session。Pairing revoke 与真实
  disconnect 仍不恢复旧 session。新增 expiry rotation、lock transport preservation 与 typed lock error 回归。
  验证：Tauri 180 Pass / 1 ignored（单线程全量）、MCP 4 unit + 3 stdio E2E、renderer 22 files / 95 tests、
  clippy `-D warnings`、typecheck、production renderer build、docs/fmt/diff check Pass。

- `AGENT-002/004` App restart transport recovery（2026-07-27）：修复 stdio MCP shim 只在进程启动时连接
  broker、VaultMesh App 重启后永久持有旧 socket/pipe 并返回泛化 `broker-unavailable` 的生命周期错位。Shim
  现保留稳定 client key，在 owner-only IPC 失败后进行有界重新连接和 hello；新 broker 创建全新 verified
  transport/session，只复用持久 pairing proof 与 persistent permission rule，不恢复 unlock/connection/once
  authority。请求 frame 未完整送达时以同一 request ID 重送；完整送达后响应丢失只对 registry R0 幂等操作
  安全重放，SSH exec/upload 等 R1–R4 动作返回 `execution-unknown`、禁止 Agent 自动重试，避免远端副作用重复。
  broker 尚未就绪返回 retryable `broker-restarting`，shim 保持存活供后续调用恢复。新增真实 shim process E2E，
  分别证明 broker 晚于 shim 启动仍可恢复、App 重启后 R0 同 request ID 重放成功，以及已送达 SSH action
  不会在新连接静默重放；当前 MCP 自动化为 4 unit + 6 stdio E2E Pass，MCP all-targets Clippy `-D warnings`、Windows MSVC source check、
  docs/fmt/diff check Pass；签名 packaged App 的真实 Codex/OpenCode restart AT 仍待执行。

- `AGENT-016` repeated authorization busy-state repair（2026-07-27）：授权 WebView 为隐藏复用而非销毁；首次
  resolve 成功后 renderer 未清除 `busy`，导致第二次请求虽已刷新但全部按钮仍保持 disabled。现于成功路径在隐藏
  窗口前重置加载状态，并新增“首次允许→隐藏→第二次请求→三个动作按钮恢复可用→再次提交”的 renderer 回归。

- `AGENT-016` unified 30-second MCP authorization deadline（2026-07-27）：维护者要求 MCP response timeout、
  broker 本次授权等待、fresh confirmation TTL 与授权窗进度统一为 30 秒。授权窗可能晚于 MCP 调用显示，因此
  broker 在实际等待到期时按当前 authorization reference 发出独立 expired 事件；只有正在展示同一 reference 的
  窗口才立即将进度归零并切换为“授权作用于下一次调用”，避免本地倒计时漂移和旧请求误伤新请求。窗口继续
  保留完整 exact/safe/all × once/connection/persistent allow/deny；超时后 once Allow 只由下一次匹配调用原子消费。

- `AGENT-016` post-timeout lease correction（2026-07-27）：维护者澄清授权窗必须保留原有 exact/safe/all scope
  与 once/connection/persistent lifetime，不应收敛为三选项。现恢复原选择器和允许/拒绝/永久拒绝按钮；30 秒内
  resolve 继续当前调用，30 秒后 resolve 同一 permission pending 并从下一次调用生效，其中 once Allow 只由
  下一次匹配调用原子消费一次。撤销 once 禁用及即时 exact 限制，fresh confirmation 的 30 秒失效规则不变。

- `AGENT-016` retained authorization result window / pairing CPU repair（2026-07-27）：实机反馈配对窗口打开后
  CPU 升高，且动作授权尚未处理便在等待截止时自动消失。根因是同一 pending pairing 会在 hello 与后续工具错误上
  重复执行 show/focus/event，授权实现同时把“Agent 本次等待时限”错误当成 permission pending 与窗口生命周期。
  现有可见配对窗口对重复通知幂等，不再重复聚焦或刷新；独立 renderer 的异步 event listener 可在卸载竞争中可靠
  释放，并去掉开发态 StrictMode 双 effect。动作授权窗改为 30 秒 Progress：时限内批准继续同一调用，超时只返回
  `authorization-timeout`，窗口保留并明确显示本次失败；permission pending 保留到 connection session 结束，用户
  随后授权可供 Agent 重试使用，fresh confirmation 仍在 30 秒后失效。后续澄清恢复完整 scope/lifetime 选择，
  超时后的 once Allow 只授权下一次匹配调用。
  验证：Tauri 177 Pass / 1 ignored（单线程全量）、MCP 4 unit + 3 stdio E2E、renderer 22 files / 94 tests、
  clippy `-D warnings`、typecheck、production renderer build、docs/fmt/diff check Pass。默认并行 Tauri suite 中既有
  `agent_cli::pinned_binary_runs_from_verified_descriptor_without_shell_or_secret_output` 两次出现 `cli-stdin-failed`，
  该测试单独运行与单线程全量运行均 Pass，未修改其断言或实现。

- `AGENT-016` isolated authorization window（2026-07-27）：维护者要求动作授权与配对一样使用全局
  独立弹窗，并将 MCP/Agent wait 与窗口显示统一为 30 秒。现新增启动后隐藏预热的 `agent-authorization` WebView；
  它始终置顶、content-protected，仅有 status/resolve permission/resolve confirmation 三个 typed capability，主窗口
  没有这些命令，也不再因授权请求被显示、聚焦或导航安全中心。`open-local-ui` 已拆为第三条 `LocalUi` 路由，
  不会误开授权窗；授权窗抢焦点期间也不会触发主窗口 blur lock。Broker 原始调用与 fresh confirmation 等待
  为 30 秒，transport 在原始 `tools/call` 上等待本地裁决；允许后以不可外部调用的 native continuation 复用
  同一 request ID、参数与 ActionPlan 继续执行，拒绝/关窗返回 `authorization-denied`，超时返回
  `authorization-timeout`。MCP broker read timeout、broker 授权 TTL 与窗口进度统一为 30 秒；后端实际等待结束时
  主动通知窗口归零。UI 按实机反馈保留超时状态，同时保留 exact/safe/all × once/connection/persistent 选择。
  验证：此前 `pnpm tauri:test`（Tauri 176 Pass / 1 ignored、MCP 4 unit + 3 stdio E2E、renderer 22 files /
  93 tests）Pass；独立 capability、同 request continuation、30 秒调用/confirmation TTL、拒绝/过期与默认
  exact-once UI 均有定向回归。`cargo clippy -D warnings`、Tauri typecheck、docs check、fmt、diff check 及
  `vaultmesh-agent-mcp` Windows target check Pass；完整 Tauri Windows 交叉检查在 macOS 构建机因缺少 Windows SDK
  头文件（`windows.h`、`stdlib.h`）停在 `aws-lc-sys` / `ring`，需在 Windows 目标机完成 packaged AT。

- `AGENT-016` account capability contract repair（2026-07-27）：实机反馈 MCP 会话正常但
  `vaultmesh_accounts_list` 对 Unraid 返回 0 个“具备 ssh-exec 权限的账户”。根因是目录 schema 把筛选字段命名为
  `capabilities`，公开 registry 使用 semantic capability `ssh-exec`，而 broker 却用工具名
  `vaultmesh_ssh_exec` 做筛选和返回；同时无意义的 `permission=ask` 筛选与 `permissionSummary` 诱导 Agent 把
  “可发现”误解为“必须预授权”。现统一规定 `capabilities[]` 只使用 semantic capability，`actions[].tools` 才返回
  可调用工具名；删除账号权限筛选/摘要，账号未预授权仍可发现，未知 capability 明确返回
  `invalid-parameters`，MCP instructions 明确要求取得 `accountRef` 后直接调用动作触发授权。Unraid 回归覆盖
  `kinds=[ssh] + capabilities=[ssh-exec]` 返回唯一账号、无秘密/权限状态，以及误传工具名不再静默返回 0。
  验证：`pnpm tauri:test`（Tauri 174 Pass / 1 ignored、MCP 4 unit + 3 stdio E2E、renderer 21 files /
  92 tests）、目标 crates 全 targets clippy `-D warnings`、TypeScript typecheck、docs check、fmt/diff check、
  renderer production build 与 Windows MCP shim cross-check Pass。

- `AGENT-015/016` pairing/action authorization window routing（2026-07-27）：实机反馈 SSH exec 等待授权时只
  看到系统配对窗。根因是 transport 将 hello pairing、direct permission、authorization、fresh confirmation 和
  open-local-ui 全部送入同一个无类型回调，而应用端固定执行 `show_agent_pairing_window`；同时未配对工具调用
  退化为泛化 `session-required`，导致 Agent 把配对描述为命令授权。现以 typed `AgentNativeUiSurface` 隔离路由：
  只有 `pairing-required/approve-pairing` 打开独立配对窗；permission/authorization/confirmation 打开主窗口，
  发出独立 `agent-authorization-requested` 事件，导航安全中心并自动展开待处理授权。MCP instructions 与 error
  message 明确区分“客户端配对”和“动作授权”；配对成功后同一工具可原样重试并继续到 ActionPlan 裁决。
  验证：`pnpm tauri:test`（Tauri 174 Pass / 1 ignored、MCP 4 unit + 3 stdio E2E、renderer 21 files /
  92 tests）、目标 crates 全 targets clippy `-D warnings`、TypeScript typecheck、docs check、fmt/diff check 与
  renderer production build、Windows MCP shim cross-check Pass。完整 Tauri Windows cross-check 在 macOS 因当前环境缺少 Windows SDK
  `windows.h/stdlib.h` 停在第三方 `aws-lc-sys/ring` C build，真实 Windows packaged AT 仍保持 Not Run。

- `AGENT-016` direct action authorization（2026-07-26）：维护者确认用“工具目录→账号搜索/筛选→直接动作→
  原生授权→执行”替代 Profile-first 链路，并要求复用有效 adapter、清理 session 预轮询、独立 permission tool、
  system Profile、重复 request parse、fake executor 与相应 UI/测试。`ADR-0008` 冻结 Canonical ActionPlan、
  exact/safe/all typed predicate、connection/persistent allow 与 request/persistent deny、SSH structured argv、版本化 safe catalog、
  OS-key-protected AEAD 持久规则库及 HTTP/Web ConnectorDefinition 与 permission 分离。旧 `AGENT-013/014`
  段落以下仅作为已实现历史证据，不再定义当前目标行为。

- `AGENT-016` v2 discovery/direct-SSH vertical slice（2026-07-26）：共享 registry 与公开 MCP 目录从 37 个
  工具收敛为 36 个，独立 `vaultmesh_permission_request` 已从 schema、broker dispatch 与 MCP 删除；shim 对每个
  `tools/call` 只发送一次 Agent IPC v2 action，不携带
  `sessionId`、不轮询 allowed-tools snapshot，Codex/OpenCode/custom-client stdio E2E 均验证 wire transcript。
  `vaultmesh_accounts_list` v2 新增 query、kind/capability/environment filter 与 query-bound v2 cursor，
  只返回 Vault `accountRef`、label、kind、environment、semantic capabilities 和命名 action/tool，不再
  返回 Profile/source/target/permission 状态。`vaultmesh_ssh_exec` v2 使用 `program + arguments[]`，新增唯一 canonical serializer
  与 `ssh-safe-v1` catalog/risk classifier，拒绝 shell syntax/control/NUL 并对 argument 做确定性 quoting。首次 direct
  SSH action 从 Vault item 构建 target/Host Key policy并打开原生授权；批准后 Agent 仍以原 item `accountRef`
  重试执行，不发现或传递 Profile/session。Unix broker 与 shim frame reader 改为 8 KiB buffered read，保留
  size/deadline/idle-stop 边界。权限解析已改为正交的 `effect × scope × duration` typed choice；session grant
  分别实现 exact 参数摘要、绑定 `ssh-safe-v1` 的 safe predicate 和 all structured-command predicate。安全目录
  跨 `whoami/hostname` 命令生效但不覆盖 `rm`，R2/R3 动作仍进入独立 canonical confirmation。原生 UI 直接
  展示“当前命令/安全命令/所有命令 × 一次/当前连接”，不再让用户选择或创建 Profile。生产 dispatch 不再用
  fake executor 捕获授权动作，授权结果直接生成 `AuthorizedAgentAction`。独立授权库使用每个 Vault canonical
  path namespace 与 OS user 派生 credential ref，随机 256-bit key 保存到 Keychain/Credential Manager；owner-only
  `agent-authorizations.v1` 只保存 AES-256-GCM ciphertext，AAD 绑定 store/protocol/Vault/user。永久 exact/safe/all
  Allow/Deny 可跨连接恢复；target digest、safe catalog、参数或 namespace 漂移、key/file 缺失/损坏全部回到 Ask，
  同精度 Deny 优先，配对撤销同步删除 client rules。Security Center 提供完整永久选择、规则枚举和删除；规则删除
  会重启 connection session 以清除已签发 grant。SSH system-Profile compatibility bridge 已删除：broker 以
  `(connection session, Vault SSH accountRef)` 持有 immutable direct SSH ActionPlan，executor 接收原始 item ref，
  在读取 credential 前重验当前 host/port/username 与获批 target，并由 SSH service 对实际 Host Key fingerprint
  fail closed；权限快照/API 同步改为 `activationRequired` 与 `agent.permission.action.resolve`，不再泄漏旧 Profile
  概念。`vaultmesh_http_request` 也已迁移为 session-bound `AgentDirectHttpPolicy`：login/secret Vault item 直接
  编译 HTTPS origin、path、auth strategy、operation schema、risk 与 output policy，授权和跨连接永久 exact rule
  均使用原始 item ref；取用 password/token 前重验当前 origin/path 与 Basic username，且不调用 Profile installer。
  已配置 HTTP request/upload/download 与 managed-web 的 encrypted Profile compatibility record；固定 CLI 公共能力与数据模型已移除，历史记录读取 fail closed。
  已按内部 ConnectorDefinition 编译 direct ActionPlan。账号目录现已将这些 persisted connector 投影为普通 opaque account：只返回 label、
  credential kind、environment、允许的工具与命名 action/risk；不返回 Profile/source/target/selector/binary path/
  command body。目录 cursor digest 同时绑定完整安全投影，connector action 或 policy revision 变化会使旧 cursor
  失效。protected actions 与 credential lifecycle 也已完成 direct ActionPlan 提取；packaged real-site/platform AT
  仍未完成，因此不能把本 Change 标记为 Verified。
  验证：`cargo test -p vaultmesh-agent-mcp --all-targets`（4 unit + 3 stdio E2E Pass）、
  `cargo test -p vaultmesh-tauri-desktop --lib --tests`（170 Pass / 1 ignored）、renderer 21 files / 90 tests 与
  `pnpm tauri:typecheck` Pass。

- `AGENT-016` system Profile bridge cleanup（2026-07-27）：删除 broker 中已不可达的 system Profile factory、
  ephemeral installer、pending Profile、candidate→Profile bind 和 source item→Profile 映射，删除管理端
  `agent.permission.profile.create` 与 renderer API；`agent.permission.action.resolve` 只激活 broker-owned direct
  SSH/HTTP policy。Vault item 缺少 direct policy 时返回有界 `action-input-insufficient`、
  `action-rule-unavailable` 或 `action-target-unavailable`，不得回退创建隐式 connector。模块同步从
  `agent_system_profile` 更名为 `agent_direct_policy`。内部 ConnectorDefinition 的 connection/persistent
  exact Allow/Deny 统一使用独立 AEAD authorization store；旧 encrypted Profile `permission_rules` 仅兼容展示/
  删除，不匹配、不放行、不再写入。ConnectorDefinition 同时开放绑定 exact account/target/tool 的 capability
  predicate，UI 以“此网站此能力/此连接器此能力”提供当前连接和永久允许/拒绝；跨 operation 命中 capability
  rule 后，R2–R4 仍必须完成独立 fresh confirmation。SSH safe/all scope 在 advanced 管理提供 connection/persistent 选择。HTTP/SFTP/Web 现有
  upload/download 工具与 adapter 均为既有能力，本切片未新增网络或文件能力。验证：Tauri Rust 171 Pass /
  1 ignored，MCP 4 unit + 3 stdio E2E、renderer 21 files / 91 tests、TypeScript、Clippy `-D warnings` 与 docs check Pass。

- `AGENT-014` SSH system Profile 回归修复（2026-07-26）：修复 SSH Vault 候选的 discovery
  `permissionScopes` 为空、system Profile 工厂仅支持 HTTP，导致 MCP Agent 在发现 SSH 凭据后错误要求用户
  手工创建 Profile/命令模板。SSH account 候选现在发布内置 `vaultmesh_ssh_exec/hostname`；broker 只从条目
  已有 host/port/username、固定 `hostname` R1 规则和 broker-owned 主机密钥探测生成 session-bound
  memory-only Profile，原生授权卡展示 exact endpoint 与完整 fingerprint，输出固定为 bounded
  `exit_status/stdout/stderr`。MCP 初始化指引同时明确禁止回退到 Profile、命令模板、target、policy、JSON 或
  Vault format 编辑。新增 discovery、permission request、Profile no-write/field binding 与 client instruction
  回归。验证：`pnpm tauri:test`（Tauri 160 Pass / 1 ignored、MCP 4 unit + 3 stdio E2E、renderer 21 files /
  88 tests）、`pnpm tauri:typecheck`、目标 crates 全 targets Clippy `-D warnings`、`pnpm docs:check`、fmt 与
  diff check Pass。`pnpm tauri:build` 生成 x86_64 `.app`/DMG；主程序 SHA-256 为
  `7db3b797d22b36f0fec882ac468daa8080164cef5e7ea9657c3491172cd8004f`，packaged shim 与 release sidecar
  均为 `acee5df2d273872716d584d8aab5505fa757b3cfcfb662b49f0a55f184c94a65`，DMG 为
  `43e2d070f97a98749033a06d7353669f137b0b58b9842473f8f098939010c596`。`codesign --verify --deep --strict`
  明确报告未签名，因此只作为本机 repair package evidence，不计 `AT-AGENT-MACOS-001`，也未覆盖或重启
  `/Applications/VaultMesh.app`。

- `AGENT-002/013/015` pairing/session simplification（2026-07-26）：删除客户端 `requestedTools`、`--workspace`、
  `workspaceDisplay/workspaceHash`、手工 session create/revoke/status 列表和用户可见 task-lease 模型。公开 IPC/MCP
  统一使用 `sessionId` 与 `vaultmesh_session_status`；每个已配对 stdio connection 只由 broker 自动创建一个
  connection session，重连复用 pairing 但生成全新 session。持久 permission rule 只匹配
  `clientKey × Profile × tool × operation`；旧 binary/workspace-bound rule 可读取但 fail closed，重新批准时清除
  旧字段。配对索引不再写入 executable/binary metadata，配对窗口只显示自报 integration key；PID/path/hash
  仅保留在 owner-only IPC 的当前连接校验。安全中心只允许撤销持久 pairing，不提供 session 管理。验证：
  Agent MCP 3 unit + 3 stdio E2E、vault-core 15 unit + 30 integration、Tauri Agent 51 CT、renderer 21 files /
  88 tests、TypeScript typecheck、docs check、目标 crates 全 targets clippy `-D warnings`、fmt 与 diff check Pass。

- `AGENT-015` system pairing window（2026-07-26）：首次未配对连接不再显示或聚焦主窗口，也不再要求用户
  进入安全中心批准；Rust 创建独立置顶、不可调整大小、content-protected 的 `agent-pairing` 系统窗口。该窗口
  使用独立 capability，只允许 safe status、主密码解锁、PIN 解锁和 exact pending client approve/deny 四个
  command，不获得 `desktop_invoke`。锁定状态在同一窗口输入主密码或已启用 PIN，成功后只显示稳定 client key
  与能力仍需单独授权的边界。经实机发现 Codex 的 MCP probe 可能在用户解锁前
  退出，broker 现按已验证身份把 pending request 在内存中保留 10 分钟，同一身份重连只刷新申请；批准时有
  当前连接则立即签发 initial connection session，无当前连接则要求 pairing proof 成功持久化供下一连接继承。拒绝或
  关闭窗口撤销同一身份 pending client；approve/deny invoke 先返回再由 renderer 关窗，避免 WebView 提前销毁
  导致按钮永久 loading。解锁失败则清空输入并保留窗口重试。
  安全中心移除首次批准按钮，只保留连接与撤销管理。验证：
  `pnpm tauri:test`（Tauri 155 Pass / 1 ignored，含 probe disconnect 后保留并由下一连接继承 pairing 的回归；
  MCP 5 Pass、renderer 21 files / 88 tests）、
  `cargo clippy -p vaultmesh-tauri-desktop --all-targets -- -D warnings`、`pnpm tauri:typecheck`、
  `pnpm --filter @vaultmesh/tauri-desktop build:web`、`pnpm docs:check` 与 `cargo fmt --all -- --check` Pass；
  真实 packaged 系统窗口、主窗口保持隐藏和 Codex 无重启续接仍由 `AT-AGENT-PAIRING-001` 跟踪。

- `AGENT-014` system Profile（2026-07-26）：普通用户的“加密账号 Profile · Vault format”及 HTTP/JSON/
  format 编辑入口已移除；权限卡固定提供“配置并运行一次/当前连接”，由 Rust broker 从 exact Login/Secret 的
  已有字段与内置 `vaultmesh_http_request/read` 规则生成 session-bound memory-only Profile。规则固定 exact HTTPS
  origin/path、Basic/Bearer credential source、GET、R1 与 status-only output；URL 含 userinfo/query/fragment、
  缺 username、reprompt、字段不足或没有规则均 fail closed。MCP 返回 retryable
  `profile-input-insufficient`/`profile-rule-unavailable`、安全 `missingFields`、`allowedSources` 与 retry hint，
  Agent 只能补全 Vault 条目或改用 discovery 已公开 operation 后重试。测试证明 Profile 不改变 Vault 文件，
  session 撤销后不可读取；锁定、断连、过期与 revoke 复用 terminal cleanup。验证：
  `pnpm tauri:test`（Tauri 153 Pass / 1 ignored、MCP 5 Pass、renderer 21 files / 88 tests）、
  `cargo test -p vaultmesh-core -p vaultmesh-ffi`、`pnpm tauri:typecheck`、`pnpm scripts:test`、
  `pnpm docs:check`、`cargo fmt --all -- --check` 与 `git diff --check` Pass。

- `AGENT-011/013` Codex MCP discovery repair（2026-07-26）：修复按 session 动态过滤 `tools/list` 却声明
  `listChanged: false` 导致 Codex 只看到 5 个 discovery 工具的问题。stdio shim 现在稳定声明 registry 的 37 个
  公共工具 schema，broker 仍在每次调用时强制 pairing/session/account/permission/risk/confirmation；revoke 后
  工具仍可发现但调用返回 `session-required`。Shim 只额外转发 broker allowlist 中的 `retryable`、
  `nativeActionRequired`、opaque `confirmationRef`，以及有界 `missingFields/allowedSources/retryHint`，使原生批准
  后可用同值 `confirmationTicket` 重试、system Profile 失败后可按规则重试，且不扩大 secret/error surface。
  `vaultmesh_request_local_ui` 现在通过 macOS/Unix 与 Windows transport 共同路径唤起
  本地窗口并返回 `{accepted:true}`。修复前 stdio 回归观察到 1 个 session-filtered tool；修复后 Codex/OpenCode
  process E2E 均验证 37-tool 稳定目录、confirmation round-trip、revoke fail-closed 与无 secret transcript。
  验证：`cargo test -p vaultmesh-agent-mcp -p vaultmesh-tauri-desktop --lib --tests`（shim 4 Pass；Tauri
  144 Pass / 1 ignored）、`cargo clippy -p vaultmesh-agent-mcp -p vaultmesh-tauri-desktop --all-targets -- -D warnings`
  、`cargo fmt --all -- --check`、`cargo check -p vaultmesh-agent-mcp --target x86_64-pc-windows-msvc`、
  `pnpm tauri:typecheck`、`pnpm tauri:test`（Rust 同上；renderer 20 files / 87 tests）、
  `pnpm scripts:test`（11/11）、`pnpm docs:check` 与 `git diff --check` Pass。
  `pnpm tauri:build` 生成 `.app`/DMG，bundle shim 与 release sidecar SHA-256 均为
  `4367bbc6c3f58e047a49b19e70c7a9995b1492c40aec87f6b554def82e50a946`；本机构建未签名，不计
  `AT-AGENT-MACOS-001`，也未覆盖或重启 `/Applications/VaultMesh.app`。

- 格式裁决（2026-07-25）：维护者明确批准 Vault format 2。采用 v1/v2 reader、首次 profile 前主密码
  re-prompt 与完整 rewrap、非空 profile 禁止 v1 save、unknown-v2 old-writer fail-closed、空 collection+
  encrypted backup+主密码的显式降级；ADR-0007 与主规格同步修订。

- 动态权限裁决（2026-07-26）：维护者确认用系统权限式申请替代普通用户手写 JSON。Agent 只能申请
  既有 typed Profile/tool/named operation；Profile 内持久规则绑定 stable client key/Profile/tool/operation，默认 Ask，
  Automatic 仅 R0/R1。R2 最多 connection session scope 且仍 fresh confirm，R3/R4 只允许单次 privileged confirm；
  现有 Profile 迁移为 Ask，旧 v2 writer 丢规则也只回到 Ask。

- `AGENT-013`（2026-07-26）：format-2 Profile 新增 additive encrypted permission rule；规则精确绑定
  client key、Profile、tool 与 named operation。配对自动签发最多
  15 分钟的 initial connection session，只暴露 metadata/本地 UI/权限申请；Agent 通过第 37 个 typed tool
  `vaultmesh_permission_request` 申请，broker 从 Profile 重建 target/risk/display。Security Center 提供允许一次、
  当前连接、始终允许、拒绝与始终拒绝，并可把持久规则恢复为 Ask；R0/R1、R2、R3/R4 scope gate 与后续
  canonical confirmation 独立强制。Profile 编辑清空旧规则，Profile/tool/operation drift 回到 Ask；HTTP 新建使用
  connector builder，完整 JSON 仅保留为高级入口。Core encrypted round-trip/atomic mutation、broker default Ask/
  one-shot/session/persistent/risk/drift、typed IPC contract 与 adapter route 回归均 Pass。

- `AGENT-013` account discovery/profile-on-demand 修复（2026-07-26）：`vaultmesh_accounts_list` 不再把空
  Agent Profile collection 误报成“Vault 没有账号”，而是在已解锁 Vault 上分页派生 Login、SSH account 和
  developer/service secret 的安全候选 metadata；游标绑定目录摘要，目录漂移 fail closed。候选 permission
  request 只能携带 opaque item ID 与兼容 tool，进入 `pending-profile` 后不能直接 allow；原生 UI 创建并原子
  保存绑定 source item 的 Profile，broker 重验 tool/唯一 named operation 后才签发所选权限，取消、校验、
  写盘或绑定失败均不留下授权。MCP 不返回 username、URL、host、notes 或受保护字段。验证：
  `pnpm tauri:test`（Tauri 149 Pass / 1 ignored、MCP 4 Pass、renderer 87 Pass）、
  `cargo clippy -p vaultmesh-tauri-desktop -p vaultmesh-agent-mcp --all-targets -- -D warnings`、
  `pnpm tauri:typecheck`、`pnpm docs:check`、`cargo fmt --all -- --check` 与 `git diff --check` Pass。

- `AGENT-002`（2026-07-25，macOS 基础切片；2026-07-26 Passkey/permission producer 扩展）：单一 JSON registry 生成/验证 37 个 MCP v1 tool；Rust broker
  实现 strict envelope、peer UID/PID/executable SHA-256、pairing、短时 session、replay/expiry/unknown 拒绝、
  metadata-only dispatch、owner-only UDS、final-lock cleanup；Tauri 安全中心提供独立配对、基础 connection session 与
  紧急撤销；packaged stdio shim 遵循 MCP 2025-06-18 initialize/tools stdio 合约并在签名前注入 app bundle。
- `AGENT-002` pairing persistence（2026-07-26，通用 MCP identity 修订）：`--client` 接受长度/字符受限的
  任意稳定自定义 key，不再使用 Codex/OpenCode 产品枚举。规范化 client key、当前 OS 用户与 protocol epoch
  共同派生 OS-protected pairing proof key；PID、路径与 shim SHA-256 只用于当前连接校验，不写入 pairing 或
  permission。macOS Keychain/Windows Credential Manager 保存随机 proof。相同 client key 建立的新
  stdio 连接直接恢复 `Paired` 并只新建 initial connection session，不恢复旧 connection session，也不再次弹出 pairing UI；
  同一客户端已有多个 connection 时，批准任一连接会同时配对全部匹配连接，紧急 revoke 也会
  同时取消全部匹配 client/session。私有原子 `agent-pairings.json` 只保存可枚举的非秘密稳定身份索引，授权
  仍必须由对应 Keychain/Credential Manager proof 证明；旧 v1 path/hash-bound record 不自动提升到 v2，
  首次连接必须按 client key 重新配对。
  安全中心把同一稳定客户端合并为一张持久卡片，在卡片内只显示当前 PID/session 活动；最后一个
  connection 断开后保留 `0` 个活动的已配对记录，离线状态也可 revoke。proof 缺失或撤销后继续回到
  `Pending`；credential storage 不可用时批准失败关闭。client key 是配置中的公开自报集成 ID，不是 bearer
  proof，也不声称认证宿主产品。`CT-AGENT-AUTH-001` 覆盖自定义 key 校验与隔离、持久索引/proof 双重校验、
  损坏失败关闭、跨 broker instance/进程变化聚合重连、离线 revoke、connection session 不恢复、revoke
  后重新配对与真实 owner-only UDS 重连不重复通知。
  验证：`cargo test -p vaultmesh-tauri-desktop --lib` 144 Pass / 1 ignored、renderer 19 files / 86 tests、
  `cargo clippy -p vaultmesh-tauri-desktop --all-targets -- -D warnings`、`cargo fmt --all -- --check`、
  `pnpm tauri:typecheck`、`pnpm docs:check` 与 `git diff --check` Pass。macOS 上的完整 Windows target check
  仍在进入本次源码前被既有 `aws-lc-sys` 缺少 MSVC/Windows SDK `stdlib.h`/`windows.h` 阻断，不替代
  `AT-AGENT-WINDOWS-001`。

- `AGENT-002/011/015` generic MCP client key revision（2026-07-26）：删除 Rust/TypeScript 中的
  Codex/OpenCode client 枚举限制，`vaultmesh-agent-mcp --client <client-key>` 接受 `3..128` 字节的稳定 ASCII
  自定义 key，并以 `clientKey` 进入 IPC（旧 `kind` 只作兼容 alias）。pairing v2 只以 client key、OS user 与
  protocol epoch 派生 ref；PID、shim path/hash 不再触发重配，MCP hello 与配置不再包含 workspace。不同 key 的 proof、活动连接、撤销和
  permission rule 相互隔离；旧 binary-bound permission rule 可读取但不命中 Automatic，必须回到 Ask 后以
  client key 重存。配对窗口与安全中心直接显示自报 key，并明确它不是宿主产品认证。
  验证：Agent MCP 3 unit + 3 stdio E2E、vault-core 15 unit + 30 integration、Tauri Agent 51 CT、renderer
  21 files / 88 tests、TypeScript typecheck、`cargo clippy ... -D warnings`、`cargo fmt --check`、
  `pnpm docs:check` 与 `git diff --check` Pass。
- `AGENT-004` idle CPU regression（2026-07-26）：Unix connection disconnect monitor 的 level-triggered
  `POLLIN` 路径增加强制退避，idle poll 从 50 ms 调整为 250 ms，listener 无连接时从 10 ms 调整为
  100 ms；Windows pipe disconnect monitor 同步改为 100 ms 有界轮询。断连、revoke 与 shutdown cleanup
  语义不变。`CT-AGENT-LIFECYCLE-001` 新增 readable-but-connected socket 退避回归，完整 Tauri Rust suite、
  Clippy 与 fmt Pass。
- `AGENT-004` Unix idle CPU event-driven follow-up（2026-07-26）：macOS/Unix broker 的每连接 disconnect
  monitor 与 listener 不再执行周期性 idle poll。Disconnect monitor 同时阻塞等待 peer HUP/EOF 和私有 wake
  socket；普通 `POLLIN` 只触发一次并暂时 disarm，request owner 消费完整 frame 后才显式 rearm，因而未读 frame
  不能形成 level-triggered 热循环。Listener 也通过私有 wake socket 立即停止，不再每 100 ms 唤醒。HUP 在
  read-disarmed 状态继续被监视，disconnect 仍会取消 active executor。新增
  `ct_agent_transport_disconnect_monitor_parks_until_a_frame_is_consumed` 和
  `ct_agent_transport_disconnect_monitor_detects_hup_while_read_is_disarmed`；两项新回归、既有 disconnect active
  executor 与 owner-only UDS lifecycle 测试 Pass；完整 `cargo test -p vaultmesh-tauri-desktop --lib` 145 Pass /
  1 ignored，`cargo clippy -p vaultmesh-tauri-desktop --lib` 与 `cargo fmt --all -- --check` Pass。
  `pnpm tauri:build` 生成修复后的 x86_64 `VaultMesh.app`/DMG；主程序 SHA-256 为
  `48769418c229b34b6dbad50745014e09f2aa638e7787372c72af79bed98024fc`，packaged shim 为
  `f9a1ebe47623c440a1680d56cb56762b179428696d2acc327e6ea2d74cbd44ad`，DMG 为
  `c0baa8405aaeda258760106d0957965f0dc569cfef53ba34821981de33a08774`。`codesign --verify --deep --strict`
  明确报告未签名，因此只作为本机 CPU repair package evidence，不计 `AT-AGENT-MACOS-001`，也未覆盖或重启
  `/Applications/VaultMesh.app`。
- `AGENT-004` accepted-socket idle CPU follow-up（2026-07-26）：真实 Codex 账号配置/调用场景中，7 条
  Agent connection 使 `vaultmesh-tauri-desktop` 达到约 688% CPU；5 秒 `sample` 把 7 个热点线程定位到
  `serve_connection → read_line → UnixStream::read/recvfrom`，listener/monitor 则阻塞在 `poll`。根因是 macOS/BSD
  上 nonblocking listener 接受的 socket 保留 `O_NONBLOCK`，原有 `read_line` 对立即返回的 `WouldBlock` 直接
  重试。`serve_connection` 现在先显式 `set_nonblocking(false)`，再设置 200 ms read timeout；`WouldBlock` 分支
  另加 10 ms 防御性退避，避免未来调用方遗漏配置时重新热循环。新增
  `ct_agent_transport_clears_inherited_nonblocking_mode_before_idle_read`，同时验证 `O_NONBLOCK` 已清除且空闲读取
  至少阻塞 100 ms。`cargo test -p vaultmesh-tauri-desktop --lib` 150 Pass / 1 ignored，
  `cargo clippy -p vaultmesh-tauri-desktop --lib` Pass。`pnpm tauri:build` 生成修复包；主程序 SHA-256 为
  `bda00d8cb3a5bcc3a984ef44747fb7d120f3752836554b96f856904c223c529d`，packaged shim 为
  `828bb61d383ca7fbcd33dac207122cb72a0699b5ec5a148a521266d283b118cc`，DMG 为
  `0136e4226d63b018f6799df899f92a6445de3b709c42c66d1543d4b1a7eb856d`。构建未签名，不计
  `AT-AGENT-MACOS-001`。随后在保留 `/Applications/VaultMesh.app.before-cpu-fix-20260726-2` 可恢复备份后
  安装该构建并启动；
  以 packaged shim 建立 4 条同时活动的真实 broker UDS connection，`top` 连续 5 次采样主进程为
  0.1–0.3% CPU，而修复前同一 packaged Codex 场景为约 688%。测试 shim 已终止；该 unsigned 本机 smoke
  只证明 idle CPU repair，不替代签名 packaged `AT-AGENT-MACOS-001`。
- `AGENT-002/004` repair package（2026-07-26）：`pnpm tauri:build` 生成包含持久 client/活动聚合、跨 workspace
  pairing 与 idle CPU 修复的 x86_64 `VaultMesh.app`/DMG；主程序 SHA-256 为
  `70728da2df7503919240fe61f05f9cbb0259fb0ec577711a759aa4504baa6c37`，packaged shim 保持
  `7d57cb9c4b471bbe0bf8309b46fc94fbb0af02d48017eb0eb5b35924752bcdbb`，DMG 为
  `11053df71d49971af3c4c2a16712a896f66f1e8815161964d2140fe5532afe56`。`codesign --verify --deep --strict`
  明确报告未签名，因此只作为本机 repair package evidence，不计 `AT-AGENT-MACOS-001`。
- 自动化（2026-07-26 动态权限回归）：workspace `cargo test` 全部 Pass / 1 ignored；其中 Tauri Rust 138 Pass /
  1 ignored（真实 OpenSSH integration 由下述独立命令执行），Agent shim 2 unit + 2 process E2E Pass；桌面
  Vitest 19 files / 85 tests、extension 37 files / 227 tests；
  `cargo clippy --workspace --all-targets -- -D warnings`、
  `pnpm tauri:typecheck`、`pnpm scripts:test`
  （现为 11/11）、`pnpm verify:tauri-source`、`pnpm docs:check` Pass。
- Windows IPC 依赖评审：选择仓库锁文件中已存在的 `windows-sys 0.61.2`，上游为 Microsoft
  `windows-rs`，许可证 `MIT OR Apache-2.0`；只启用 Foundation/Security/Authorization/FileSystem/
  IO/Memory/Pipes/Threading feature，用于当前用户 ACL、client PID/image/token SID 与 named-pipe 生命周期，
  不引入运行时下载、网络服务或第二套策略 owner。命名管道使用当前用户显式 DACL、拒绝远程 client、
  first-instance anti-hijack，并重验 client PID/token SID/executable SHA-256；Windows stdio shim 复用同一 MCP
  实现且只能连接固定 pipe。
- Windows 源码级验证：用只包含实际 `agent_broker.rs`、`agent_broker_windows.rs` 与
  `vaultmesh-agent-mcp.rs` 的最小检查包执行 `cargo check --target x86_64-pc-windows-msvc`，broker 与 shim
  均 Pass。完整 desktop package 在 macOS 交叉检查会先被 `aws-lc-sys` 缺少 MSVC/Windows SDK headers 阻断；
  按发布规则不把该限制或交叉编译当作 `AT-AGENT-WINDOWS-001`，真实 Windows packaged AT 仍为 Gate。
- Packaged shim：无秘密 shim 独立为 `crates/agent-mcp` package，避免 Tauri `build.rs` 与 `externalBin`
  的循环依赖；`prepare-agent-sidecar.mjs` 生成 target-triple 命名产物，release overlay 交给 Tauri bundler。
  macOS x86_64 release app bundle 实测包含同 SHA-256、可执行的 `Contents/MacOS/vaultmesh-agent-mcp`；安全中心
  只展示官方 Codex `config.toml` / OpenCode `opencode.json` 所需的安装路径和非秘密 `--client` 参数。
- 客户端过程证据：`crates/agent-mcp/tests/stdio_e2e.rs` 分别以 `--client codex` 与 `--client opencode`
  启动真实 release shim，连接 0700 临时目录中的 0600 UDS，完成 MCP initialize、strict tools/list、tools/call
  与 revoke 后空目录；mock broker 仅替代尚需原生 UI 的授权端，收到的 action 不含 password/private key/
  credential。`pnpm agent:client-probe` 在 Codex CLI 0.137.0 与 OpenCode 1.17.9 上验证官方 stdio 配置可解析；
  这两项不能替代 packaged app 上由真实客户端驱动的 approval/restart/lock/multi-account E2E。
- `AGENT-003`：connector-specific Profile 已写入 format 2 encrypted payload；native CRUD 复用原子事务，真实
  写盘失败测试证明磁盘字节、内存 Profile 与 format version 同时回滚。Reader 支持 v1/v2，unknown version
  在 KDF 前拒绝，v2 tamper、backup/restore、password rotation 与显式备份降级均有回归。Session 只接受存在且
  enabled 的 opaque Profile，并逐请求重验 capability/risk；confirmation 绑定 canonical action，60 秒单次使用。
- `AGENT-003/004` 审计：账号动作最多产生 500 条 encrypted safe audit，不记录参数、body、header、command/
  output、credential 或本地路径。写盘失败返回 `audit-unavailable`；显式降级前 backup 保留历史，v1 rewrite
  清除 Agent audit。安全中心提供确认、审计查看/清除与 Profile CRUD。
- `AGENT-004/005/008` SSH 执行面：authorization 与网络 executor 分成两阶段，执行不持有 broker mutex；item
  metadata 只返回 `itemRef/kind/label`。SSH exec 使用 Profile 固定 target、`SHA256:<base64>` host-key pin、
  命名 command template/风险与 Vault password/private-key/SSH Agent auth，输出按 byte budget 截断并扫描
  direct/base64/hex credential canary。SFTP 以 canonical prefix、普通文件、随机 0600 临时文件和原子 rename
  约束 upload/download；本地文件与结果只经 session/account/purpose 绑定 opaque handle。PTY 使用独占 session、
  sequence/quota/resize/close，并剥离 CSI/OSC/DCS/OSC52；tunnel 只能从 Profile 命名 loopback bind、固定目标、
  连接数和 TTL 后使用 direct-tcpip。独立 ignored integration test 启动本机临时 `sshd`，实测错误 host key
  拒绝、公钥首次/重复安装、真实 key-login exec、SFTP 原子往返、PTY resize/write/read/exit 与 loopback
  direct-tcpip tunnel 均 Pass；该证据不替代签名 packaged app 的 `AT-AGENT-SSH-001`。
- `AGENT-006` HTTP 执行面：Profile 以命名 operation 固定 method/path/request fields/response fields/风险；Broker
  用 operation 风险决定 fresh confirmation。Adapter 禁用 proxy/redirect，连接前解析并固定最多 16 个地址，默认
  拒绝 loopback/private/link-local/CGNAT/metadata/non-public IP，只允许 Profile 精确私网 host；WebPKI 不可关闭，
  可选 SPKI SHA-256 pin。Basic/Bearer 从 Vault 内部注入；OAuth refresh 固定同源 token path/client ID，以两个
  Secret ref 在 Rust 内换取短时 Bearer。JSON response 只重建双重 allowlist；file upload/download 使用同一网络
  policy 与 opaque handle，全部检测 direct/base64/hex credential reflection。运行时生成证书的本地 TLS 测试覆盖
  auth、OAuth、pin、redirect、SSRF、typed upload/download 与 output schema；`rcgen`/`rustls` 仅为 test dependency，
  均为 `MIT OR Apache-2.0`，不进入产品包。
- `AGENT-007` CLI 执行面：Profile 命名 operation 把 argv 固定为 internal literal 与 Agent 只能从 allowlist 选择的
  choice position，operation 风险进入确认 digest；binary/cwd 必须是无 symlink 的 canonical absolute path，进程不经 shell、环境清空，Login/Secret 只走长度前缀
  private stdin。macOS 从已 hash 的打开句柄复制到 128-bit 随机、不可枚举目录，spawn 成功后立即 unlink，避免
  原路径替换；Windows 保持拒绝 write/delete sharing 的打开句柄跨 CreateProcess。测试覆盖 hash substitution、
  real child、grammar substitution、cancel kill、output bound 与 credential canary；实际 Windows source target check Pass，
  packaged macOS/Windows AT 待完成。
- `AGENT-009` managed-web 执行面：format-2 Profile 使用 tagged typed recipe，而不是 Agent 提交 selector/script；
  hidden incognito Tauri WebView 不获得 `main` capability，不开放 popup/remote-debugging，逐导航重验 exact HTTPS
  origin。登录的 username/password fill+submit 在 Rust owner 内完成；后续 navigate/extract/action/download 只按
  recipe 执行并重建 typed result。页面结果改用 Tauri 原生 `eval_with_callback` 直接回到 Rust，未使用可由页面
  观察或伪造 nonce 的 title/DOM/IPC 回传；输出执行 password/login canary，href 去 query/fragment，download 只
  写 broker 随机私有目录并转 opaque result handle。session/target 绑定 client/connection/account/expiry，close/revoke/
  final lock 删除 browser 与 download state；持久 Cookie 仍 fail closed。
- `AGENT-010` OTP/recovery/Passkey/credential lifecycle 切片：managed-web Profile 的 `totp`、`email-otp`、`recovery-code` recipe 在 session open
  时生成随机一次性 `targetRef`，Agent 不提交 selector 或 code。TOTP 在剩余 5 秒内拒绝，Email OTP 按 exact
  Email account 选择最新未过期候选并在尝试前移除；recovery code 仅在页面 success selector 满足后，以提交值
  SHA-256 compare-and-consume 并通过 Vault transaction 原子写盘，失败不移除另一条 code。所有 MCP response
  只含 submitted/consumed/status/remaining，不含 OTP 或 recovery code。Passkey 已采用 typed registration/assertion
  recipe：Rust 在 session 内捕获并验证 WebAuthn request，Agent 只见 opaque `requestRef`，perform 直接完成原页面
  Promise。credential lifecycle 已采用 typed HTTPS policy，固定 managed/admin Secret ref、apply/test/rollback/revoke
  operation、credential field 与 32–64 byte 生成器；update/revoke 执行补偿事务，回滚/恢复失败时 fail closed 禁用
  Profile。两条路径都已移除自由文本 `connectorAction`，且 Agent response 不返回 request challenge 或凭证值。
  `CT-AGENT-AUTHN-001` 覆盖 request capture/页面 Promise completion、session/origin/account/expiry/single-use 绑定、
  document navigation 后 request 拒绝、指定 Passkey item 的 create/get roundtrip、typed policy 拒绝 generic HTTP、raw response credential canary、
  apply→test→commit 顺序、apply 不确定性回滚、rollback failure disable，以及 revoke/restore/fail-closed 顺序。
- `AGENT-012` package/supply-chain（2026-07-26）：`pnpm tauri:build` 生成 macOS x86_64 `VaultMesh.app` 与
  `VaultMesh_0.1.0_x64.dmg`；bundle 内 shim 与 release sidecar SHA-256
  均为 `5148c69415fe7cfbc3a62b215388a8bb2e925d03828dbc61ee9e6fb0cb578446`，DMG SHA-256 为
  `8408578ad221b18bead5831f979dc5c6c49b8581b067dd30d8a5ab6c46c6ea4c`；`codesign --verify --deep --strict`
  明确报告未签名，因此只算 package-content evidence，不计 `AT-AGENT-MACOS-001`。`shadcn` 升级到 4.14.1
  并归入 build-only devDependency，`fast-uri` 3.1.4、`brace-expansion` 5.0.8 定向 override 后
  针对 production dependency 的包管理器审计（high threshold）为 0。完整 dev audit 仍由 WXT 0.20.27 固定的 browser-runner 链报告
  1 Critical/4 High/2 Moderate，未用 ignore 掩盖。RustSec `cargo-audit 0.22.2` 已消除 Linux-only
  `quick-xml` 两项 High（`wayland-scanner` 0.31.11）；仍报告 IMAP `rustls-connector 0.19.2` 带来的
  `rustls-webpki 0.102.8` 四项 advisory，以及 `ssh-key 0.6.7`/`rsa 0.9.10` 的无稳定修复 timing advisory。
  它们属于既有依赖路径但仍阻止本 Work 的 supply-chain/独立安全 Gate；不得以本地自动化通过改写为 Pass。

- `AGENT-005`–`AGENT-010/016` direct-chain final audit（2026-07-28）：对共享 registry 的 31 个工具逐项核对
  discovery、permission compiler、dispatch、executor 与 audit owner。4 个 broker/local helper、10 个 SSH/PTY、
  1 个 direct Secret HTTP、6 个 managed-web、8 个 protected-auth/credential-lifecycle 及 2 个 R0 metadata 工具均有
  唯一执行路由；PTY read/write/resize/close 继续以已批准 `sessionRef` 作为派生权限，
  其余账户工具缺少与 `client + accountRef + tool + canonical parameters digest` 精确匹配的 SSH/HTTP/Connector
  ActionPlan 时统一返回 `action-plan-unavailable`。生产 executor 已删除 SSH exec/transfer/key/PTY/tunnel、HTTP、Web、
  CLI 与 file helper 的旧 Profile collector fallback；broker 已删除 generic Profile permission fallback 和 dispatch
  Profile authorization/risk fallback。Audit 现在只从 active/pending direct ActionPlan 或 PTY 派生 session 构造安全
  envelope，不再从 Profile 反推 target/risk；旧 SSH/HTTP collector 仅在历史兼容单元测试下 `cfg(test)` 保留。
  验证：`pnpm tauri:test`（Tauri 209 Pass / 1 ignored、MCP 4 unit + 6 stdio E2E、renderer 24 files /
  112 tests）、两个目标 package 全 targets clippy `-D warnings`、Tauri typecheck、renderer production build、
  docs/fmt/diff check 全部 Pass；packaged macOS/Windows 与真实站点 AT 仍未完成，因此 Change 保持 Implementing。

## 验收与证据

### 2026-07-28 契约与 SSH 动作目录核对

- `vaultmesh_items_list_metadata` 与 `vaultmesh_item_get_metadata` 的 registry 契约保持 `requiresAccount: false`，且
  `kind`/`itemRef` 是它们各自的完整参数；二者已加入 connection session 的 R0 基础工具集合。真实
  connection-managed session 的回归验证确认带 `kind` 的 metadata 请求不再要求 `accountRef`。
- SSH `program` 未命中 safe catalog 时仍按当前已接受的“所有结构化命令”范围升级为 R2；没有 exact/All 显式授权时，
  `program: "not-allowed"` 返回 `authorization-required`，不会进入 SSH executor。已有 All-command 授权允许任意通过结构化
  serializer 的命令，这是 `REQ-AGENT-011` 的明确行为；远端返回 127 只能说明调用已获得该范围授权并由目标端报告命令不存在。
- 定向证据：`cargo test -p vaultmesh-tauri-desktop metadata --lib`（4 passed）；
  `cargo test -p vaultmesh-tauri-desktop ct_agent_authz_direct_ssh_safe_scope_spans_catalog_commands_but_not_other_programs --lib`
  与 safe catalog policy test（均 passed）。

### 2026-07-28 direct Secret HTTP 与 credential lifecycle

- 维护者收敛网络边界后，direct access-token Secret 不再要求 HTTPS、公网 IP、WebPKI 或额外信任配置。
  HTTP adapter 现按账户 exact `website` 接受 HTTP/HTTPS、localhost、private/loopback/link-local/metadata literal
  地址与自签名/证书异常 TLS；DNS 仍在当次连接前解析并固定，Agent 仍无法提交 origin、port、
  header 或 redirect policy。该修订不增加 Vault 字段、format 迁移、EndpointTrust、private-host allowlist 或
  direct Secret certificate pin，旧 ConnectorDefinition 字段只保留为历史兼容数据。
- 新增/修订 `CT-AGENT-HTTP-001` 回归：地址类别表验证 HTTP/HTTPS 与 IPv4/IPv6 非公网 literal 均进入
  exact target；真实 loopback HTTP server 验证 Bearer 只注入绑定 origin；真实运行时自签名 TLS server 在不注入
  CA root 或 certificate pin 时可执行；redirect、path escape、origin drift 与 secret canary 仍 fail closed。
- 验证：`cargo test -p vaultmesh-tauri-desktop agent_http --lib` 24 Pass；
  `cargo test -p vaultmesh-tauri-desktop ct_agent_authn_lifecycle_direct_secrets_bind_transactions_and_commit_without_exposure --lib`
  1 Pass；`cargo test -p vaultmesh-tauri-desktop --lib -- --test-threads=1` 209 Pass / 1 ignored；
  `pnpm tauri:test` 为 Tauri 209 Pass / 1 ignored、Agent MCP 4 unit + 6 stdio E2E、renderer 24 files /
  113 tests；`cargo clippy -p vaultmesh-tauri-desktop --all-targets -- -D warnings` 与
  `cargo fmt --all -- --check` Pass。
- `vaultmesh_http_request` v2 只接受 `method/path/query/body/responseMode`；账号必须是 access-token Secret，
  `website` 固定 exact HTTP(S) origin/base path，Rust 只在有界执行阶段注入 Bearer。Agent 不能提交 URL、header、
  auth strategy 或匹配规则。公共 registry 在该实施阶段移除 HTTP upload/download、加入 OpenSSH host setup 后为 32 个工具；历史 HTTP/lifecycle
  Profile 不进入 discovery、permission 或 executor。
- `http-path-v1` 先规范化 exact path，再只支持 whole-segment `*` 与 terminal `**`。授权窗口仅展示由 Rust 从
  当前 path 派生的 exact/parent-star/parent-double-star 候选；connection/permanent rule 绑定 client、Vault、Secret、
  target digest、tool、HTTP method、pattern 和 matcher revision。GET/HEAD 为 R1、POST 为 R2、PUT/PATCH 为 R3、
  DELETE 为 R4；R2–R4 即使命中 remembered rule 仍要求 fresh confirmation，Deny 优先。
- credential generate/test/rotate/revoke v2 直接引用 managed/control access-token Secret 和 exact transaction
  method/path；固定生成 32-byte credential，并在 Rust 内执行 apply→test→atomic commit、rollback 与 revoke/restore。
  Secret-owned `active/revoked/needs-review` 保存在加密 payload 的 renderer-hidden reserved scope；普通 Secret 编辑保留
  状态，失败补偿不确定时 fail closed，MCP/renderer/audit 均不返回 credential。
- 自动化证据：`cargo test -p vaultmesh-tauri-desktop --lib -- --test-threads=1` 为 209 passed / 1 ignored；
  `cargo test -p vaultmesh-core` 为 45 passed；Agent MCP 为 4 unit + 6 stdio E2E；desktop Vitest 为 24 files /
  113 tests；TypeScript typecheck、
  `cargo clippy -p vaultmesh-tauri-desktop --all-targets -- -D warnings`、Rust fmt 与 `pnpm docs:check` Pass。
  signed packaged macOS/Windows 和真实站点 `AT-AGENT-HTTP-001`/`AT-AGENT-AUTHN-001` 仍待执行，Change 保持
  Implementing。
- 新增标准库 Python lifecycle fixture：从环境读取测试 admin/managed Token 且不回显，提供
  `/credentials/test`、`/credentials/current`、`/credentials/restore` 与无秘密 `/test-state`，支持按 operation/ordinal
  注入 before/after HTTP failure，以复现远端未变更、远端已变更但响应不确定、补偿成功和补偿失败。脚本默认仅
  loopback HTTP；它现在可以直接作为 exact 账户 HTTP 目标的 packaged E2E fixture。Python fixture 4 tests Pass。

### 接受 Draft 的门禁

- 产品负责人确认本地 Agent、能力范围、多账号语义、业务结果披露和非目标。
- 安全负责人确认 ADR-0007、威胁模型、信任假设、managed web/CLI 限制和不可绝对保证项。
- 维护者确认可接受 encrypted payload additive collection 与 downgrade 写保护。
- 生产依赖保持未选择；dependency/许可决策在对应 adapter 开始前形成可定位证据。
- Change 状态只改为 Accepted，不同时修改产品代码。

### 进入 Implementing 的门禁

- Agent 专项 Spec 成为跨模块行为唯一 owner。
- `REQ/NFR-AGENT-*` 和 `CT/AT-AGENT-*` 已写入主规格与 Traceability；本 YAML 同步填充。
- Scope Matrix 明确 local MCP client 是 Required 目标、remote MCP/cloud agent 是 Out。
- Architecture/Security/Data/Test 文档合并 accepted delta；ADR-0007 状态为 Accepted。
- `pnpm docs:check` 通过；协议版本、migration、rollback 和依赖无 TBD。

### Verified 门禁

- 所有适用自动化包括失败、取消、重复、锁定、过期、重放、参数替换、重定向、DNS rebinding、
  output truncation、binary replacement、PTY escape、child crash 和 final-lock cleanup。
- secret canary 在 MCP/IPC responses、stdout/stderr、audit、日志、crash fixture、snapshot、环境、命令行、
  临时目录和 managed-browser 可导出状态中均无命中。
- macOS/Windows packaged app 均完成 Codex/OpenCode、多账号、SSH/HTTP/managed web 适用 AT。
- 恶意 MCP client、恶意/畸形 IPC、慢客户端、断连和资源配额测试通过。
- 独立安全评审确认不存在 raw-secret tool、通用执行绕过、policy/dispatch drift 或 downgrade 丢失。

证据必须写回本 Work 的任务/命令/CI/平台记录；“代码存在”“编译通过”或 MCP client 自身 approval
不能替代 Verified。

## 安全与数据生命周期

- Secret owner：`vault-core` unlocked session；仅 Tauri Rust adapter 的最小作用域可以取得值。
- MCP/IPC：只传 opaque IDs、规范化业务参数、非秘密 policy metadata、结果 envelope 和错误码。
- 内存：secret 使用 zeroizing buffer；connection session、authorization、SSH/PTY、direct HTTP、managed-web
  session、OTP/recovery selection 都有 owner、quota、expiry 和 terminal cleanup。
- 持久化：Vault item 与 Rust-owned internal ConnectorDefinition 存 encrypted payload；client permission 只进入独立
  OS-key-protected AEAD rule store；client pairing credential 使用 OS-protected storage；UI 偏好可以进入非秘密
  desktop settings；MCP adapter 不持久化 Vault response。
- 日志/audit：禁止 credential、OTP、Cookie、Authorization、private key、passphrase、request body 原文、
  response body 原文、PTY transcript 和 DOM snapshot。只允许经过 schema 的非秘密摘要。
- 临时文件：默认禁止 secret 临时文件；受控 download/upload 使用 broker-owned handle 和独立目录，路径
  不返回 Agent，清理失败只记录非秘密状态。
- 锁定：最后一个 desktop/browser/agent authorization 消失时，沿用全局 final-lock 语义并增加全部 Agent resource cleanup。

## 兼容与迁移

- 所有 Reader 只接受 envelope format 3；Writer 只创建和保存 format 3，内部
  `agent_connector_definitions` 是否为空不改变版本。
- 所有其他版本在 KDF 前拒绝；Core、FFI、Tauri、renderer、Agent、Browser、quick unlock 与 restore 不提供旧格式
  reader、迁移、降级或专用备份 API。
- 禁用/卸载 MCP adapter 必须 revoke session、关闭资源；内部 definition 仍作为 Vault-owned adapter policy 保留。
- IPC/MCP unknown version 或 capability 必须 fail closed。
- Release 不支持回滚到只识别旧开发格式的构建；Release 记录必须声明 format 3 最低可读版本。
- Browser RPC 继续为 v2 且语义不变；Agent IPC/MCP 使用独立版本和 pairing namespace。
- 无 Native ABI 计划；若实现发现必须修改 ABI，暂停相应任务并建立新 Work/ADR。

## Bug 根因（仅 type=bug）

N/A；这是新功能与安全边界变更。
