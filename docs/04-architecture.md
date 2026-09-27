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

Android 使用独立平台拓扑：

```text
Jetpack Compose → Kotlin ViewModel/platform lifecycle → narrow JNI operation
  → vault-android-runtime → vault-core → app-private atomic encrypted vault file
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
| Android Activity、lifecycle、系统服务与 app-private path | Kotlin Android shell | Compose state、Tauri desktop runtime、`vault-core` |
| Android JNI operation、进程内会话与原子持久化 | `vault-android-runtime` | Kotlin UI、raw JNI pointer、Tauri desktop runtime |
| LAN peer discovery、TLS identity、short-code pairing 与 peer trust state machine | `vault-lan-pairing` Rust crate | vault-core、renderer、Agent broker、Browser RPC |
| LAN pairing 平台凭据、网络权限与页面生命周期 | Tauri Rust runtime / Android Kotlin + narrow JNI adapter | 共享配对协议、Vault Key、renderer |

## Android 边界

- 系统 Autofill 由 Kotlin 平台服务解析与绑定系统表单；非导出认证 Activity 仅处理安全候选与用户输入，固定 JNI 将最终值直接交给 Dataset 构造器。Rust 持有隔离的短期单请求授权与原子保存，具体边界见 `ADR-0040`。
- 本机号码是 Kotlin 平台所有的独立 Autofill Dataset，仅关联用户名字段；SIM 读取和手动备用号码分别受运行时电话权限、Android Keystore 私有密文保护，均不经过 Vault JNI，见 `ADR-0043`。

- `apps/android` 是唯一 Android 产品 shell；Compose 只持有 renderer-safe 状态和当前用户输入，不持有 Vault Key 或 core 对象。
- `crates/vault-android-runtime` 是 Kotlin 与 `vault-core` 之间的唯一 JNI owner；公开函数必须是固定 operation，返回稳定错误码或按 operation 定义的脱敏 DTO，不允许通用 JSON method router。
- Android 主密码轮换独立于 Item payload mutation：Rust runtime 用旧磁盘 Vault 建立候选 session，并在 core rewrap 与原子文件提交成功后替换当前 session；失败不得发布候选 header。
- Android 受保护字段复制由 core 按字段鉴权、固定 JNI 返回有界值，再由 Kotlin 特权剪贴板服务直接写入标记 sensitive 的系统 clip；Compose 只保存目标字段与短期主密码输入，不持有复制值。
- Android 受保护字段查看复用同一固定字段鉴权；仅用户显式查看后当前前台 Compose 弹窗短时持有一个值，30 秒或生命周期失效即清除，不构成普通详情或通用 reveal JNI。
- Android 四类条目历史只经各类型固定 JNI 投影安全摘要；恢复和清空由 core 校验条目/版本并复用 Android runtime 原子提交，Compose 确认不持有旧秘密。
- Android Login TOTP seed 仅作为固定设置/替换 mutation 的短期输入，core 负责归一化与持久化；固定复制操作由 core 在当次主密码复验后生成短期代码，Kotlin 只写特权剪贴板。
- Android Login 恢复码通过固定 JNI 在 Rust/core 解析、验证并原子替换；普通摘要只含存在性。查看和逐码复制各自重新验证主密码；`content:` 文件选择跨越后台锁定，只暂存 URI，解锁后把有界 UTF-8 内容读入当前草稿，不创建明文 staging。
- Android 加密备份使用固定应用私有 staging 文件跨越文件选择器的后台锁定；Kotlin 仅通过系统 `content:` 文档 URI 搬运有界密文，Rust/core 验证恢复格式与主密码、重置同步 epoch/授权并原子替换本机 Vault。JNI 不接收外部 URI、路径或 Vault 字节。
- Android 密码健康由 core 在用户主动请求时计算，固定 JNI 只投影分数和 Login ID；Kotlin 用当前安全摘要显示标题，不读取密码或复制判定算法。
- Android 凭据生成器是 Kotlin 当前会话内的显式 UI 操作，使用平台安全随机源和与桌面一致的字符规则；结果仅供当前草稿填入或特权剪贴板复制，不持久化。
- Android 卡片完整编辑只在明确打开时通过固定详情读取补充字段，完整卡号/CVV/PIN 继续省略；基础与补充字段由固定完整卡片 JNI 在单次 core mutation 中原子提交，不以两次写盘拼接。
- Android 普通 Secret 完整编辑也只在明确打开时读取不含值的补充字段；固定完整操作单次原子提交，core 负责保留内部生命周期 Scope，Passkey 继续排除。
- Android 普通 SSH 完整编辑只在明确打开时读取不含认证值的补充字段；固定完整操作单次原子提交，桌面托管的 OpenSSH alias 继续只读。
- Android Identity 完整编辑只在明确打开时读取结构化个人资料；多值字段 ID 随严格有界 DTO 原样提交，由 core 完整验证并单次原子替换，普通列表仍只持有安全摘要。
- Android Login 常规补充字段只在明确编辑时读取；固定完整操作单次原子提交，core 保留未替换密码、TOTP seed 和恢复码，后两者继续通过独立受保护操作管理。
- Android 生物识别快捷解锁由 Rust/core 用随机包装秘密加密 Vault Key；Kotlin 仅用强生物识别逐次授权的 Keystore 密钥封存该随机秘密。固定 JNI 只交付短期包装秘密，不交付 Vault Key；Rust 验证当前加密 Vault 后才发布 session。
- Android PIN 快捷解锁由 Kotlin Keystore 封存独立设备秘密，Rust 把六位 PIN 与设备秘密经 scrypt 派生包装密钥，原子记录五次失败限制；固定 JNI 不输出 Vault Key，主密码解锁重置 PIN 失败次数。
- Kotlin 拥有 `Activity`、`Application`、Android lifecycle、`FLAG_SECURE`、系统服务、瞬态编辑/搜索状态和 app-private 路径选择；Rust runtime 拥有解锁 session、各 Item 基础 mutation 与适用回收站的回滚、原子 Vault 文件提交和显式 lock。Card/SSH/Secret 的受保护值只允许作为当前固定 mutation 的输入，列表只能投影安全摘要；Android 不编辑 core 中未提供的元数据。
- Android 不依赖 `apps/tauri-desktop/src-tauri`。前台短时 LAN 配对共用独立 Rust protocol crate；系统 Autofill 与后台 LAN 同步各按独立 Requirement 注册；Credential Manager、Passkey 在独立受控切片前不得注册。

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

LAN pairing 是显式十分钟的短时设备信任服务，desktop 锁定、离开页面、系统锁定、睡眠和退出以及 Android Activity 暂停关闭配对发现。桌面与 Android 共用 Rust protocol 2.0 的发现、TLS 内 PAKE、身份固定、碰撞仲裁和原子信任持久化；平台凭据存储分别接入 OS credential store 与 Android Keystore，见 ADR-0018、ADR-0038。新配对明确授权当前 Vault 同步，旧信任须双方补充确认；Android 同步由独立 Kotlin 服务管理，见 ADR-0039。

同步拥有独立的已授权密文 mDNS/listener 与持续连接协议；共享 Rust LAN sync service 拥有 transport 与 peer pin，平台 shell 拥有生命周期，shared runtime 拥有授权绑定、密文缓存和原子提交，Core 拥有逐连接方向密钥、密文封装、记录投影、验证、HLC 合并、历史与 tombstone。renderer 仅操作 typed 控制接口，无法获取同步 payload；Browser/Agent 不获得网络控制接口，但其已授权 core 会话可以验证合并本机收件箱。完全锁定的后台只搬运密文，不保留方向密钥；冷启动路由须验证 OS-protected 证明与 Vault 指纹，见 ADR-0020。配对服务与同步服务的页面生命周期相互独立。详细行为由 `specs/lan-vault-sync.md` 所有。

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

## 已配对设备填充互通

REQ-DEVICE-ASSIST-001 / REQ-ANDROID-026 与 [独立互通规格](../specs/device-fill-assist.md) 定义逐设备一次授权、锁屏号码/短信交付及短时秘密生命周期。既有禁止 RECEIVE_SMS 的条款限于手机本地 Autofill；独立互通服务仅在用户主动启用后可以请求 RECEIVE_SMS，不使用 READ_SMS。短信正文仅本机瞬态解析，验证码不进入 Vault、备份、日志、同步或普通 DTO。系统限制自动读取时使用显式手动交付。
