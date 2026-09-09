# 架构

## 运行时拓扑

```text
Chromium page
  ↕ content script（field metadata / one-use assignments）
MV3 background worker ↔ popup
  ↕ authenticated native messaging RPC v2
Rust native-host（仅 transport）
  ↕ owner-only local socket / Windows named pipe
Tauri privileged process
  ├─ capability + typed command → sandboxed React renderer
  ├─ Rust desktop/browser authorization and services
  └─ vault-ffi shared Rust operation → vault-core → atomic encrypted vault file
```

对应当前决策：`ADR-0001`、`ADR-0003`、`ADR-0005`、`ADR-0006`。Electron 与
SwiftUI/WinUI presentation 仅存在于历史 ADR/Change，不是当前可构建运行时。

## 依赖方向

```text
Tauri React renderer → typed API adapter → capability/command → Rust desktop runtime → vault-core
browser UI/content → background RPC → Rust native-host → Rust broker → shared operation/core
```

依赖不得指回 presentation layer。`vault-core` 不知道 Tauri、浏览器、剪贴板、对话框或平台
凭证库。renderer 不得直接 import Tauri API；只有 `apps/tauri-desktop/src/tauri-api.ts` 可以把
编译期已知 operation 映射到 `desktop_invoke`。

## 所有权

| Concern | 唯一所有者 | 禁止所有者 |
| --- | --- | --- |
| Encryption、envelope、payload、mutation rollback | `vault-core` | TypeScript renderer、native host |
| Service record、typed relationship、aggregation plan、trash/history 与纠错决定 | `vault-core` | renderer、extension、Vault 外 sidecar |
| ApiEnvironment target/config、auth/Header binding、credential relationship、revision/digest 与 trash/history | `vault-core` | Agent、renderer persistence、ConnectorDefinition、credential value snapshot |
| Desktop API request canonical plan、live Environment/credential revalidation 与 protected material projection | `vault-core` + Rust-native `DesktopRuntime` | renderer、Agent broker、Browser RPC、generic invoke |
| Desktop API DNS pin、TLS/target policy、native confirmation、HTTP IO、response reconstruction 与 cancellation | Tauri Rust privileged runtime | renderer、Profile、Agent permission store、system proxy |
| Atomic Vault persistence、desktop/browser authorization | Tauri Rust runtime + shared Rust operation | renderer、extension storage |
| Desktop typed API/schema | `apps/tauri-desktop/src/shared` | ad-hoc renderer contract |
| Browser RPC operation/policy | `apps/tauri-desktop/src/shared` + Tauri Rust broker | content script、native host、临时私有枚举 |
| Browser RPC authentication/replay/expiry | Tauri Rust broker | extension storage、renderer |
| Agent pairing、independent Vault unlock lease、connection session、policy、confirmation、audit、resource cleanup | Tauri Rust Agent broker + Agent-only runtime | MCP shim、desktop/browser runtime、renderer、Agent client |
| Agent access-token Secret lifecycle state、credential mutation rollback 与 internal connector validation | `vault-core` | MCP shim、protocol adapter、renderer |
| Agent MCP framing 与本地 IPC forwarding | packaged stdio shim | `vault-core`、remote/network listener |
| Native-messaging long-lived port | extension background worker | popup、content script |
| Page discovery/write | content script | desktop renderer |
| Clipboard、dialog、recovery-code file read/delete、biometric、SSH、email IO | Tauri Rust/platform adapters | renderer、extension |
| Quick-unlock wrapper | platform credential integration | Vault format |
| LAN peer discovery、TLS identity、short-code pairing、peer trust index 与 lifecycle | Tauri Rust LAN pairing service | vault-core、renderer、Agent broker、Browser RPC |

## Tauri 边界

- `apps/tauri-desktop/src/renderer/` 是无 Node/filesystem 权限的 React UI。
- `apps/tauri-desktop/src/shared/` 拥有 Zod contracts、API types 和 Browser RPC policy。
- `apps/tauri-desktop/src/tauri-api.ts` 是 renderer 唯一 transport adapter。
- `apps/tauri-desktop/src-tauri/capabilities/` 只绑定主窗口和显式 command。
- `apps/tauri-desktop/src-tauri/src/` 拥有授权、生命周期、browser broker 和平台服务。
- Desktop API workbench 只通过 `api-requests.prepare/execute/cancel` 三个显式 operation 进入 Rust；prepare 产生短时
  single-use execution reference，execute 重新编译 live core plan，renderer 不持有 credential 或任意 URL transport。
- `crates/vault-core` 是 crypto/format/model/session 的唯一 owner；`crates/vault-ffi` 当前提供
  Tauri 使用的共享 Rust operation/runtime，不能把 C ABI 暴露给 WebView。

## 授权生命周期

## LAN peer pairing

LAN pairing 是与 Vault unlock 独立的短时设备信任服务。非秘密的附近设备页面在 Vault 因窗口失焦而锁定后仍可保持，且只能通过 typed desktop operation 启动服务；真正离开页面、系统会话锁定、睡眠、退出或十分钟发现期结束时必须清除 listener、mDNS、TLS、配对码和未完成会话。配对状态机依次为发现并生成本机码、对端选择并输入码、TLS 内 PAKE 与双向 key confirmation、原子持久化和已连接；认证通过后不再等待第二次 UI 确认。双方同时发起时，Rust service 使用临时实例 ID 确定唯一 TLS client，只让一条规范会话进入 PAKE。持久化 peer trust 不授予任何 Vault、Agent 或 Browser 权限。

Desktop 与 browser authorization 独立。任一授权存在时 core 可以保持解锁；最后一个授权锁定后，
Rust runtime 必须清除 core、email connection/candidate、import/SSH session、pending fill、Passkey
proxy、desktop API request/response 和其他敏感瞬态状态。

Browser operation 被分类为 metadata、mutation、privileged-copy、system-dialog 或 page-disclosure。
Gesture/confirmation 要求由共享 policy 和 Rust broker 一致执行；confirmation token 和 request ID
短时、单次使用。

Agent authorization 与 desktop/browser authorization 相互独立。Pairing 只识别本地 client，不解锁 Vault 或授予操作。
默认每个真实 stdio transport 必须经独立原生 Agent 解锁窗口取得 memory-only unlock lease；用户可以显式选择
同一 pairing identity 的并行 transport 共享一个 lease。desktop/browser、不同 client 和不同 Vault 的已解锁状态
不能借用。Agent-only runtime 只在至少一个有效 lease 存在时保持解锁；最后 lease、系统锁定或退出必须清除该
runtime。内部 connection session 轮换不改变 unlock lease；connection scope 的真实断连立即清除，client scope
只在同身份最后一条真实 transport 断开时清除共享 lease，单条断开仍清理其自身 session/authority/resource。
每条 lease 由 Rust 记录创建时间、最后活动时间和执行中计数；独立 owner-only 设置限定空闲 5/15/30/60 分钟
与最长连续 1/4/8 小时或直到关机。“直到关机”只取消绝对截止时间，lease 仍只存在于内存并受空闲时限、
系统锁定/睡眠、真实断连、撤销、Vault 锁定/切换和进程退出清理。周期清理按 client 撤销过期
authority/resource，最后 lease 过期时锁 Agent runtime。
解锁范围设置为 connection/client；切换范围先撤销全部现有 lease 与 authority，再按新 owner 创建 lease。
Pairing、unlock 与 action authorization 使用三个不同 typed capability 和窗口。

每个 connection session、permission request、confirmation 状态、continuation 和 child resource 都绑定 client/account/target/capability/
expiry。Connection permission lease 绑定真实 Agent transport，而不是内部 15 分钟防重放 session；短时 session 到期时，
Rust broker 清除旧 session authority/resource、保留同一存活 transport 的 connection permission lease，并按需轮换基础 session。
真实断连、App restart、revoke 或 final lock 必须清除 connection lease。final lock 必须清除全部 Agent authority/resource 并拒绝 Vault 动作，但不把内部 session
到期或 Vault 锁定伪装成 transport 断开；revoke 或真实连接终止才移除连接 identity。

Agent 使用 exact Vault account 直接提交动作。Broker 从 Vault 条目、版本化内置规则或各 capability 的 typed internal
definition 编译 Canonical ActionPlan；SSH 与 direct compatibility HTTP/access-token 使用对应 Vault item。结构化 HTTP 的
target/config 由 ApiEnvironment 拥有，Login/Secret 只拥有 credential value；当前切片把全部 live Environment 投影到
安全目录，执行由 `CHG-2026-028` 接入。Direct Secret HTTP origin/base path 来自 Secret `website`，method/path 来自当前
精确工具参数，pattern 只由原生授权 UI 生成。ActionPlan 与 connection lease 只在 Rust 内存，持久规则
进入 OS-key-protected 本地 AEAD store，不进入 renderer state 或 Vault payload。生成失败在 MCP 边界返回有界缺失
字段和重试提示；Agent 只能调整工具 schema 允许的业务参数，不能成为 target/policy/scope 作者。

## Agent broker 拓扑

任意本地 MCP client（Codex/OpenCode 仅作为兼容性验收客户端）只通过 packaged stdio MCP shim 连接
owner-only Unix domain socket 或 Windows named pipe。每个配置通过稳定自定义 client key 标识本地集成；
产品名、PID、路径、binary hash 与 `clientInfo` 不作为持久配对身份；MCP hello 不携带 workspace。
Shim 不链接解密 core、不打开 Vault，也不解释 policy；每次工具调用直接转发，不提交任何 unlock factor、
不预轮询 session 或自行裁决
allowed tool。Tauri Rust runtime 是 Agent policy、secret use、
adapter execution、safe output、audit 和 cleanup 的唯一 owner。`vault-core` 拥有 Vault item、内部 ConnectorDefinition、
validation、受保护值 lookup、Secret lifecycle state 和原子 mutation，不依赖 MCP、client 或协议 adapter。

VaultMesh App 重启会销毁旧 broker transport/session，但不要求重启仍存活的 stdio shim。Shim 使用原 client key
重新连接并 hello，broker 只复用有效 pairing proof 与持久 rule，随后创建全新 transport/session。Shim 只在 frame
未完整送达时重送同一 request，或对 R0 幂等请求在响应丢失后安全重放；动作已送达但结果未知时返回 typed
`execution-unknown`，不得把自动重连变成隐式二次执行。

公共 Agent tool registry、request schema、risk 与 confirmation policy 只有一个机器可读 owner，并生成或
验证 MCP list、Rust dispatch、native UI 和 parity tests。Unknown version/tool/field、registry/policy/dispatch
漂移和未授权 target 必须 fail closed；Agent IPC 与 Browser RPC v2 使用独立版本、identity 和 namespace。

Pairing 后自动创建的 connection session 可以搜索安全账号 metadata 并直接提交动作。Broker 从已解锁 Vault
按查询/筛选/cursor 派生 Login、SSH account、developer/service secret 与 live ApiEnvironment 的 opaque metadata，
再把具体工具请求
编译为 Canonical ActionPlan；permission engine 只接受 broker 推导的 target、risk、display 与 typed predicate。
SSH item 直接拥有 SSH account；`access-token` Secret 暂时直接拥有兼容 HTTP/lifecycle account；ApiEnvironment 是新结构化
HTTP target/config owner，但在本切片不创建可执行 ActionPlan。Environment 的 `environmentRef` 是 opaque accountRef，
目录只投影 label/kind/http capability/可选 openapiUrl，cursor digest 额外绑定未投影的 revision/policy digest。
Managed-web recipe 与固定 SSH tunnel 作为 capability-specific internal definition 保留，但不拥有 client
permission。持久 lease 存在 OS-key-protected AEAD 本地
授权库，绑定 Vault namespace、client、account、target、capability 与 predicate；R2–R4 confirmation 继续独立执行。

## 持久化分类

- Vault envelope：所有 item、Service、ApiEnvironment、trash/history、Passkey secret 和有界 audit metadata。
- Desktop user-data：非秘密 policy；OS-protected pairing/quick-unlock wrapper 可位于 Vault 外。
- Extension storage：仅非秘密 preference，不保存 Vault response、assignment、decrypted item、pairing secret 或 OTP。
- Memory only：recovery-code file bytes/path、import/SSH preview、page discovery/assignment、email body/candidate、OAuth state、clipboard value。

Electron/Native 源码删除不授权删除旧 Electron 加密 user-data；其保留与未来清理由
`CHG-2026-008` 和 Release rollback window 管理。
