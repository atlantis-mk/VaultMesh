# 测试与发布计划

## 测试层次

1. Rust core unit/integration：format、model、session、rollback、兼容和秘密 redaction。
2. Tauri runtime：capability、typed command、Rust service、WebView isolation 和 cleanup。
3. Renderer/shared contract：纯 UI helper、schema/policy、selection、generator、virtualized list 和敏感展示。
4. Extension：protocol、connection、discovery、fill、capture、policy、Passkey routing。
5. Native host：frame、pairing key 和 RPC forwarding。
6. 平台验收：macOS/Windows packaged app、browser registration、lock/clipboard/biometric、upgrade/rollback。
7. Agent broker：MCP/IPC schema、pairing/session/policy、secret canary、adapter、lifecycle、Codex/OpenCode 与 packaged platform E2E。
8. Android：host Rust runtime 单元测试、Android target JNI 编译、JVM/仪器化 lifecycle 与 Manifest contract、arm64 真机 create/unlock/lock/重启验收。

## 常用命令

从仓库根目录执行最窄相关 Gate：

```sh
pnpm docs:trace
pnpm docs:check
cargo fmt --all -- --check
cargo check -p vaultmesh-core -p vaultmesh-ffi
cargo test -p vaultmesh-core -p vaultmesh-ffi

pnpm tauri:typecheck
pnpm tauri:test
pnpm tauri:build
pnpm extension:typecheck
pnpm extension:test
pnpm extension:build
pnpm extension:release:zip:all
pnpm verify:browser-parity
pnpm verify:tauri-source
pnpm scripts:test

pnpm test
pnpm typecheck
```

开发/打包命令：`pnpm tauri:dev`、`pnpm tauri:build`、`pnpm browser:dev`、
`pnpm ffi:build`、`pnpm ffi:test`。`desktop:dev`、`desktop:build`、`local:package` 和
`local:launch` 是明确的 Tauri aliases；浏览器 Host 卸载使用
`pnpm tauri:macos:browser-host:uninstall`。

## 测试 ID 定位

| Test family | 主要实现 |
| --- | --- |
| `CT-VAULT-*`、`CT-ITEM-*`、`CT-RECOVERY-*`、`CT-REL-*`、`CT-COMPAT-*` | `crates/vault-core/tests/vault_session.rs` |
| `CT-SERVICE-001`、`CT-SERVICE-AUTO-001` | `crates/vault-core/tests/vault_session.rs` 的 Service CRUD/typed relationship/trash/history/format-3 round-trip、safe-metadata deterministic plan/catalog drift/idempotent apply/rollback；Tauri Rust typed operation、renderer contract 与 Service Hub UI tests |
| `CT-API-PROFILE-001` | `crates/vault-core/tests/vault_session.rs` 的 ApiEnvironment CRUD/trash/history/format-3 round-trip、origin/base-path/Header/auth/reference adversarial validation、revision/digest 与 credential/Service lifecycle；vault-ffi typed operation/backup/atomic rollback；Tauri renderer contract/editor、全部 live Environment 的 Agent allowlist 与 cursor drift tests |
| `CT-API-REQUEST-001` | Core canonical request/immutable live plan、none/Bearer/Basic/API-key/fixed protected Header 注入、single-use prepare/execute/cancel、profile/credential drift、GET/POST JSON/text、stable result 与 mutation `execution-unknown` tests |
| `CT-API-REQUEST-SEC-001` | Tauri Rust WebPKI、public/private/loopback/metadata/link-local/mixed DNS 分类与固定、native-confirmation predicate、redirect/proxy/compression/header smuggling denial、timeout/quota/JSON depth、secret canary、lock/window/exit cleanup tests；无生产凭据本地 fixture |
| `CT-SEC-*`、`CT-IMPORT-*`、`CT-SSH-SCAN-*` | Tauri Rust runtime/command tests；`CT-SEC-003` 解析全部产品窗口配置并拒绝 renderer 关闭内容保护 |
| `CT-BROWSER-*` | Tauri shared policy/capability、Rust broker + extension non-secret preference tests；Bitwarden 实验副本的 `src/vaultmesh/*.spec.ts`、`src/background/vaultmesh-rpc.background.spec.ts` 和 `src/platform/services/vaultmesh-browser-rpc.service.spec.ts` 覆盖 callback transport、popup 来源、解锁/锁定 gesture、实际登录摘要投影、清理和迟到响应拒绝；`CT-ITEM-001` 同时覆盖 Login 编辑字段保留、特权详情短期草稿、确认删除、防重复写入和结果不确定时不重试 |
| `CT-BROWSER-PACKAGE-001` | WXT Chrome MV3/Firefox MV2 manifest 与 ZIP contract、固定双 identity、macOS/Windows browser-specific Native Messaging manifest/注册/卸载、Rust Host Chrome origin 与 Firefox manifest-path/Gecko-ID 启动参数拒绝测试、Review workflow 六资产同 source gate，以及两个 ZIP 的不可变 R2 路径与公网逐字节校验；实验副本的 `apps/bitwarden-browser/scripts/local-dependencies.test.mjs` 与 `vaultmesh-branding.test.mjs` 单独验证依赖路径隔离和品牌，不替代发布验收 |
| `CT-AUTOFILL-*` | Tauri Rust broker tests + `apps/browser-extension/src/lib/*.test.ts`；实验副本的 `apps/bitwarden-browser/src/vaultmesh/native-fill.spec.ts` 复用真实 Bitwarden collector/generator/executor 验证空值投影、受控 input、逐写入校验、重复与迟到响应；`apps/bitwarden-browser/scripts/vaultmesh-contract-parity.test.mjs` 验证隔离副本契约与共享 owner 一致；Rust native Login plan parser/authenticated broker tests 验证来源、handle、gesture、锁定和单次 assignment |
| `CT-AUTHENTICATOR-*` | extension QR target/UI/protocol/background tests + Tauri Login update/autofill broker regression |
| `CT-RECOVERY-CODES-*` | core Login payload/reauth/redaction + Tauri typed operation/clipboard/file parse（逐行与 Google 编号双栏）-confirm-delete/foreground-parenting + desktop/extension editor 逐次查看/复制复验和瞬时状态 contract tests |
| `CT-PASSKEY-*` | Tauri Rust passkey service/presentation tests |
| `CT-EMAIL-*` | Tauri Rust email service tests；Gmail OAuth 必须只请求 `gmail.readonly`、拒绝实际授予 scope 缺失的部分授权并通过 Gmail Profile 读取邮箱地址；所有可分发 Tauri package workflow 必须从 GitHub repository Secret 注入已接受的 Gmail Desktop OAuth Client ID 与 Provider 签发的 Client Secret，并在 Client 属于其他 Google 项目、缺失、格式无效、Provider 不存在或 credential pair 不匹配时于编译前 fail closed；Client 绑定、scope 校验与 Provider 预检不得输出 Client ID、Client Secret、Token 或响应正文 |
| `CT-AGENT-PROTOCOL-001`、`CT-AGENT-AUTH-001`、`CT-AGENT-UNLOCK-001`、`CT-AGENT-POLICY-001`、`CT-AGENT-ACCOUNT-001`、`CT-AGENT-DISCOVERY-002`、`CT-AGENT-AUTHZ-002`、`CT-AGENT-AUTHZ-003`、`CT-AGENT-SSH-SAFE-001` | 机器可读 Agent registry parity、Tauri Rust owner-only broker、自定义 client key 的格式/隔离/重连/撤销、App 重启后 shim 重新 hello 与新 transport/session、frame delivery-safe/R0 同 request ID 重放和动作 `execution-unknown`、pairing/Agent unlock/action authorization 三窗口与三状态机隔离、desktop/browser/other-client unlock 不可借用、Agent-only runtime、默认 per-transport 与显式 client-shared unlock scope、相同 pairing identity 共享及不同身份隔离、同 scope 并发 pending 合并/多 waiter 一次唤醒/已显示窗口幂等、displayed transport 断开转移、已完成 request 不复用、单条并行/最后 transport 断连语义、scope 切换 fail-closed、独立持久化的空闲/最长连续解锁策略、“直到关机”只关闭绝对截止且 lease 不持久化、活动刷新与执行中/有限绝对到期语义、空闲及强制终止清理不受“直到关机”影响、主密码/PIN 不进入 MCP/IPC、VaultMesh 软件触发的 Agent lock、MCP 无 session 状态/锁定工具、最后 lease cleanup、独立最小权限且预热置顶的 action authorization window、30 秒 MCP wait/进度、broker 实际超时事件立即归零与同 request native continuation、超时保留窗口和 permission pending、账号非秘密索引的搜索/筛选/cursor、semantic capability 与 action tool 名分离、未预授权账号可见且未知 capability 明确拒绝、shim 单次请求构造、broker 单次解析与 connection-owned session、Canonical ActionPlan、typed predicate/lifetime/effect、一次 lease 原子消费及超时后下一次调用消费、connection permission 跨内部 session 轮换并在真实断连/锁定/重启/撤销清理、持久 AEAD 规则库、SSH exact/safe/all-command scope、R1 safe+connection 推荐、R3 exact-only、R4 exact+once Allow、R2/R3 同窗逐次 fresh confirmation、safe catalog 版本漂移、target/Host Key/policy 漂移、broker-owned actionDisplay、风险着色及无独立 action confirmation tests；`CT-AGENT-ACCOUNT-001` 同时证明 format 3 是唯一 create/write/read 格式、所有其他版本 pre-KDF refusal、不存在迁移或降级 API、connector-definition 原子 mutation/rollback 与生产代码不存在 Profile API；`CT-AGENT-PERMISSION-001` 只保留为历史证据 |
| `CT-AGENT-SECRET-001`、`CT-AGENT-LIFECYCLE-001`、`CT-AGENT-AUDIT-001` | Agent secret canary/redaction/audit allowlist、cancel/revoke/final-lock/crash/expiry cleanup、15 分钟内部 session 在同一 transport 透明轮换且不继承 authority、App 重启后新 transport 不恢复旧 authority 且不重复结果未知动作、final lock 保留 transport identity 并返回 typed lock error tests |
| `CT-AGENT-SSH-001`、`CT-AGENT-PTY-001`、`CT-AGENT-HTTP-001`、`CT-AGENT-HTTP-PATH-001`、`CT-AGENT-WEB-001`、`CT-AGENT-AUTHN-001` | Tauri Rust adapter contract/adversarial tests；HTTP CT 覆盖 exact 账户 origin、HTTP/HTTPS、public/private/loopback/link-local/metadata literal target、self-signed TLS、DNS 当次连接固定、redirect/cross-origin denial、Bearer 注入与有界输出；HTTP path CT 额外覆盖 access-token Secret direct schema、method risk floor、base-path confinement、单次 canonicalization、encoded separator/dot 拒绝、exact/`*`/terminal `**` predicate、method 隔离、Deny 优先与 matcher revision；protected-auth CT 覆盖 OTP、recovery code 与 Passkey 的 opaque target、single-use、成功提交和清理；固定测试 server/browser fixture，不使用生产凭据 |
| `CT-AGENT-CODEX-001`、`CT-AGENT-OPENCODE-001` | packaged stdio shim 的 tools/list/call/cancel/revoke/multi-account client E2E |
| `CT-TAURI-SHELL-*`、`CT-TAURI-COMMAND-*` | `apps/tauri-desktop` config/adapter/Rust command 与 Electron data migration contract tests |
| `CT-LAN-PAIRING-001` | Tauri Rust LAN advertisement parser、protocol/version/size rejection、同链路双栈 listener、随机六码生命周期、TLS 内 SPAKE2/key-confirmation、错误码/尝试上限/timeout/replay、单端发起与双端同时发起的唯一会话仲裁、双方 persistence acknowledgement、credential/index rollback、revoke/restart/lock cleanup 与 renderer-safe typed operation tests；renderer 真实路由覆盖锁定时直接访问拦截、解锁后显示、手动锁定/锁定事件/聚焦刷新后的页面卸载、配对码与设备列表清除和停止发现 |
| `CT-TAURI-VAULT-*`、`CT-TAURI-DESKTOP-*` | Tauri Rust runtime integration tests + shared renderer tests |
| `CT-TAURI-TRAY-THEME-001` | Windows light/dark/unknown 主题选择、黑白托盘资源尺寸/解码、macOS Retina 模板资源保持测试 |
| `CT-DESKTOP-STARTUP-*` | Tauri Rust autostart owner、固定参数、初始化标记、隐藏窗口配置、主窗口关闭销毁 WebView 与托盘重建、typed adapter 与设置 UI contract tests |
| `CT-UPDATE-001` | Rust-owned updater/no-renderer-capability、release-only HTTPS config、macOS/Windows 原生“检查更新…”菜单、主动/自动检查互斥、主动检查无更新/失败反馈、用户确认、安装前 lock/exit cleanup、Windows NSIS 覆盖复制前 Native Host 注销/停止与安装后恢复注册，以及标准 GitHub-hosted `macos-15` ARM64、`macos-15-intel` x86_64、`windows-2025` x64 原生目标/host 架构绑定、精确 Rust toolchain、按 OS/arch/target 隔离且忽略 workspace-only 版本变化的 dependency-only Cargo cache、workspace release object/编译期 credential 保存前清理、矩阵 `fail-fast: false`、上游失败时 publisher 明确失败并通过同 run “Re-run failed jobs”复用成功 artifact、发布 workflow 无 `self-hosted` 标签、manifest 的 SemVer/platform/signature/不可变 URL/三平台完整性与 latest-last publish contract tests；Windows target experimental package 必须只发布 immutable objects、保持 test channel 不变且不计入 Windows AT |
| `CT-UPDATE-REVIEW-001` | `0.0.1-review` fresh-install baseline 与当前 `0.0.10-review` build 的 workspace/Rust/Tauri/extension 版本一致性；Review workflow 固定使用 `channels/review/latest.json`，保留完整发布的三目标、签名、immutable、latest-last、精确 toolchain、dependency-only Cargo cache、workspace object 清理与失败任务同 run 恢复约束，并为 Windows同时生成 NSIS/MSI；Chrome/Firefox ZIP 必须进入同版本不可变 R2 路径并通过公网内容校验，R2 成功后只创建不含 Git Tag 的 GitHub Draft Prerelease并上传两个 DMG、Windows NSIS/MSI 与两个 ZIP；任一 prerequisite 失败时 Draft job 明确失败并可随失败任务重跑；阶段性 manifest 只引用已发布的 signed immutable artifact、首次从 `.1` 创建且后续严格递增，并允许在相同 current version 下只追加一个缺失平台，同时保持顶层字段、既有平台和 test channel 不变；阶段性清单和 Draft Prerelease 均不得计为完整正式发布或平台 AT |
| `CT-OSS-001` | 历史证据：`scripts/open-source-metadata.test.mjs` 保留原 AGPLv3-or-later 标准正文、首次公开 Work 封存记录和精确秘密扫描例外；该 ID 不再代表当前版本的许可元数据 |
| `CT-LICENSE-001` | `scripts/source-license-metadata.test.mjs` 验证 PolyForm Noncommercial 1.0.0 标准正文、Rust/pnpm SPDX、source-available/非商业表述、商业授权入口、历史 AGPL 权利与第三方权利边界一致，并保持 workspace package `private: true` |
| `CT-HISTORY-001` | `scripts/repository-history-policy.test.mjs` 验证当前 Git refs 不再包含已知 AGPL 发布提交、`main` 根快照使用 PolyForm Noncommercial，并保留当前许可证元数据 |
| `CT-REPOSITORY-001` | GitHub API、`git ls-remote` 与本地 SHA-256 清单验证同名 Public 仓库使用新的 repository identity、只包含当前 PolyForm `main`、不迁移旧 PR/Actions/Draft Release，并恢复 secret scanning、push protection、private vulnerability reporting、description 与 topics |
| `CT-TAURI-BROWSER-*` | Tauri broker/Rust native-host cross-process contract + RPC parity |
| `CT-BROWSER-001`（development startup） | `scripts/tauri-browser-dev.test.mjs` 的 key→ID→Host origin、专用 profile、debug Host→Tauri dev→WXT 顺序与双进程清理 contract |
| `CT-FEEDBACK-*` | Tauri renderer 与 extension popup 的 Toaster 位置、toast 触发和 Alert 静态合约测试 |
| `CT-TAURI-SOURCE-*` | Tauri owner path、workspace/lockfile、禁止 Electron/Native build reference 扫描；`CT-TAURI-SOURCE-002` 额外拒绝已退休的 C ABI header、artifact、export 与专属测试 |
| `CT-ANDROID-RUNTIME-001` | `vault-android-runtime` 的 create 不覆盖、format 4、unlock/wrong-password、status、幂等 lock、原子写入失败不发布会话、drop 清理与进程重建保持锁定测试 |
| `CT-ANDROID-JNI-001` | Android target JNI 固定符号与稳定非秘密结果、无 raw pointer/通用 router、Manifest 禁止 backup/cleartext/network 且 Activity 启用 `FLAG_SECURE`、Compose 后台锁定与密码状态清理 contract 测试；真机 instrumentation 在独立 cache 目录验证 create/wrong-password/unlock/lock、窗口保护 flag 与 `onStop` lock，不读取或清除用户 Vault |
| `CT-ANDROID-JNI-002` | Android Login 固定 JNI operation、脱敏 summary、编辑保留未替换密码、删除确认、原子提交失败回滚的 Rust/contract/instrumentation 测试；只使用独立 cache Vault 和合成凭据 |
| `CT-ANDROID-JNI-003` | Compose 对脱敏摘要本地搜索，Login 回收站固定 JNI operation、安全摘要、恢复、单项永久删除、清空确认，以及写盘失败回滚的 Rust/contract/instrumentation 测试 |
| `CT-NATIVE-*` | 历史 Native Preview 证据只保留在 Rejected Change；当前源码不再执行 |
| `AT-*` | packaged/manual user-visible acceptance；证据写入对应 Change/Release |
| `AT-SERVICE-001`、`AT-SERVICE-AUTO-001` | macOS/Windows packaged Tauri 的网站/服务 CRUD、原 item 导航、锁定清理，以及约 1000 条记录的预览、批量应用、待确认、merge/split/move/ignore、重跑和 rollback |
| `AT-API-PROFILE-001` | macOS/Windows packaged Tauri 在同一 Service 配置 Production/Staging/Local、none/Bearer/Basic/API Key、literal/protected Header、delete/restore/lock cleanup，并由真实 Codex/OpenCode 验证全部 live Environment 只投影 opaque ref/label/kind/http capability/可选 openapiUrl，不能读取 detail；后续执行仍需独立 Agent unlock 与 Action Lease |
| `AT-API-REQUEST-001` | macOS/Windows packaged Tauri 使用无生产凭据 fixture 验证 none/Bearer/Basic/API-key GET/POST JSON/text、canonical preview、原生 mutation/private/HTTP 确认、public HTTP/self-signed/metadata/redirect/oversize/canary 拒绝、cancel/timeout/lock/window close/Vault switch cleanup 与 `execution-unknown`；目标 OS 分别执行，不以交叉编译替代 |
| `AT-TAURI-MACOS-002`、`AT-TAURI-WINDOWS-002` | packaged Tauri 主窗口的系统截图/录屏内容捕获保护；macOS 记录 best-effort 结果，Windows 10 2004+ 必须从公共捕获路径排除 |
| `AT-TAURI-WINDOWS-003` | packaged Windows Tauri 在系统 light/dark 启动、运行中双向主题切换、Explorer/应用重启及主题读取失败回退时的托盘图标可读性和即时更新 |
| `AT-UPDATE-MACOS-001`、`AT-UPDATE-WINDOWS-001` | 目标 OS/architecture 从旧版安装开始验证无更新、取消、离线、篡改拒绝、已解锁确认后的 lock/cleanup、R2 test channel 成功更新，以及 Windows installer exit/macOS restart；macOS 分别覆盖 aarch64/x86_64，两平台均从原生应用菜单验证主动检查的无更新、失败与发现更新路径 |
| `AT-UPDATE-REVIEW-MACOS-001`、`AT-UPDATE-REVIEW-WINDOWS-001` | 目标 OS/architecture 全新安装 `0.0.1-review`，验证 Review endpoint、无更新和后续更高 Review 版本更新；已有 `0.1.x` test 安装验证不会自动降级，并按说明手动重装且保留 Vault 数据 |
| `AT-RECOVERY-CODES-*` | packaged Tauri/插件的 Login 恢复码粘贴、文件导入/确认删除、保存、逐次主密码查看/复制与锁定清理验收 |
| `AT-AGENT-PAIRING-001` | packaged Tauri 的自定义 client key、通用 stdio client、主窗口保持隐藏、配对不要求或继承 Vault 解锁、批准后无需客户端重启、deny/close/revoke/restart 验收 |
| `AT-AGENT-UNLOCK-001` | packaged Tauri + 真实 Codex/OpenCode 的独立 Agent 解锁窗口、窗口内 connection/client scope 切换、主密码/Agent PIN、desktop/browser/other-client 隔离、同调用继续/超时重试、VaultMesh 软件触发的 Agent lock、disconnect/revoke/system-lock/last-lease cleanup 验收 |
| `AT-AGENT-AUTHZ-002` | packaged Tauri + 真实 Codex/OpenCode 的账号搜索/筛选→直接动作→独立全局授权窗→同一调用在 30 秒内继续；验证及时置顶、顶部贴边进度、broker-owned 风险/目标/工具/actionDisplay、SSH Markdown code block、R1–R4 Allow 着色且无第二个 action confirmation、R1 safe+connection 推荐、R3 exact-only、R4 exact+once Allow、R2/R3 同窗逐次确认、超时后 once 仅允许下一次调用、connection permission 跨内部 session 轮换且真实断连/锁定/重启/撤销清理、主窗口不打开、持久规则重启/撤销/损坏回 Ask |
| `AT-AGENT-PERMISSION-001` | 历史 Profile-first 权限验收证据；当前行为由 `AT-AGENT-AUTHZ-002` 替代 |
| `AT-AGENT-SSH-001`、`AT-AGENT-HTTP-001`、`AT-AGENT-WEB-001`、`AT-AGENT-AUTHN-001` | packaged app 的动作 adapter、多账号、失败/取消/锁定与无 secret response 验收；HTTP 额外验收 exact 账户绑定的 HTTP/HTTPS、localhost/私网/link-local/metadata literal target 与 self-signed TLS，以及 Agent 不能替换 origin/port/base path |
| `AT-AGENT-MACOS-001`、`AT-AGENT-WINDOWS-001` | 签名 packaged app 的 socket/pipe ACL、shim identity、OS pairing proof、Codex/OpenCode、sleep/system lock、upgrade/uninstall 与 child cleanup |
| `AT-NATIVE-MACOS-*` | 历史 Native Preview AT；不再作为当前产品验收入口 |
| `AT-LAN-PAIRING-001` | packaged macOS↔macOS、Windows↔Windows、macOS↔Windows 同一 LAN 的显式发现、本机展示码→对端输入码→自动完成、错误码/尝试上限、重连、撤销、超时、系统锁定/睡眠与 firewall rejection 验收 |
| `AT-ANDROID-001` | arm64 真机的 fresh create、正确/错误密码 unlock、显式和后台 lock、任务划除/进程终止/冷启动保持锁定、`FLAG_SECURE` 截屏与最近任务保护、应用数据 backup exclusion；交叉编译和模拟器不得替代真机验收 |
| `AT-ANDROID-002` | arm64 真机使用合成数据完成 Login 新增、脱敏列表、空密码编辑保留、删除确认、锁定后拒绝和冷启动持久化；不得读取、覆盖或清除产品 application ID 的用户 Vault |
| `AT-ANDROID-003` | arm64 真机使用合成数据验证 Login/回收站搜索、恢复、永久删除和清空确认；后台锁定后查询与回收站摘要必须清除，重新解锁从加密 Vault 刷新 |

## LAN 同步验收

- `CT-LAN-SYNC-001`：Core 版本/墓碑/合并/历史、format 3→4 安全升级与恢复、真实 Rust 双实例 TLS、授权与锁定清理、重试与原子回滚、renderer-safe contracts。同步还必须覆盖锁定密文收发、逐设备合并收据、错通道/重放/篡改、队列满与缓存失败、三台以上并发及乱序收敛、持续 TLS 推送与退避。
- `AT-LAN-SYNC-001`：packaged macOS↔macOS、Windows↔Windows、macOS↔Windows，双端独立主密码、离线修改与删除、重连、系统锁定/睡眠、防火墙、备份升级恢复及新旧 Passkey；至少三台设备覆盖锁定接收后插件解锁、睡眠恢复、逐边撤销与在线秒级生效延迟。

## 发布门禁

### GATE-1 规格与追踪

- `pnpm docs:check` 通过。
- Direct change 或适用 Work 状态允许实施/发布；Requirement、Spec、ADR 和生成的 Traceability 一致。
- 所有新增公开行为有稳定 Requirement/Test ID。
- 没有未解释的范围或兼容空白。

### GATE-2 Core 与格式

- Rust fmt/check/test 通过。
- 旧 Vault Fixture、恶意 KDF/长度、wrong password、mutation rollback、password rotation 通过。
- Format migration/rollback 在 Release 中明确。

### GATE-3 Desktop runtime

- Tauri typecheck、Rust tests、capability/command rejection、final-lock cleanup 和 package build 通过。
- `CT-SEC-003` 证明全部声明产品窗口从创建起启用内容保护，且 renderer capability 不能关闭保护。
- `CT-TAURI-SOURCE-001` 证明 Electron/Native build owner 已移除且 Tauri 自包含；`CT-TAURI-SOURCE-002` 证明不再声明或构建已退休的 C ABI。
- `CT-DESKTOP-STARTUP-001` 证明首次默认注册、用户关闭保持、固定参数、登录项静默锁定启动、主窗口
  关闭后 WebView 销毁且托盘可重建窗口，以及 renderer 无直接插件 capability；macOS/Windows packaged app 分别执行登录项 AT。
- `CT-TAURI-TRAY-THEME-001` 证明 Windows 主题选择和资源契约；`AT-TAURI-WINDOWS-003`
  在 packaged Windows 验证运行中主题切换和失败回退。
- Tauri packaged app 在目标 OS 冒烟。

### GATE-3A Android runtime

- `cargo test -p vaultmesh-android-runtime` 和 `CT-ANDROID-JNI-001`、`CT-ANDROID-JNI-002`、`CT-ANDROID-JNI-003` contract test 通过。
- Android arm64/x86_64 target 必须编译固定 JNI exports；首切片 Manifest 不得声明网络、外部存储、biometric、Autofill、Credential Manager 或后台服务权限。
- Debug APK 可以在模拟器验证布局与基本 lifecycle，但 `FLAG_SECURE`、后台/系统锁定、任务划除、进程终止、backup exclusion 和 release JNI 必须由 `AT-ANDROID-001` 在 arm64 真机验收。
- 未完成 `AT-ANDROID-001`、签名、依赖审查与独立发布记录前，Android 保持 Partial 且不得描述为已发布。

### GATE-4 Browser

- 当前 WXT 原插件的 `CT-BROWSER-001/003` 必须覆盖至少 500 条摘要的 25 条分页、跨页搜索与页码收敛，Broker 权威 Login/Secret/SSH 建议及无字段上下文时 card/identity 不误标，桌面锁定/撤销/停止后的 popup 全量瞬态清理，以及生成结果/历史 60 秒与隐藏清理和桌面受控复制。`CT-ITEM-001/002/003/004/005` 与 `CT-RECOVERY-001` 必须覆盖按实际存在值生成复制菜单、单条删除的可恢复/永久语义、四类安全恢复摘要和类型/目标绑定；编辑草稿必须覆盖隐藏、5 分钟期限、迟到详情及恢复码文件框 45 秒例外。
- `CT-AUTOFILL-001` 必须验证多字段表单按 scope 单次自动目标采集、已尝试 scope 不重新采集、100 毫秒 mutation 调度不饥饿、collector 忙与销毁、并发 focus/capture、重复候选点击以及 profile/DOM 并行后的失效拒绝。构建后运行 `npm --prefix apps/bitwarden-browser run test:content-build`，验证实际压缩 content 的无值采集、有效 assignment 写入和失效 assignment 拒绝；`CT-BROWSER-002` 同时验证 Rust 轻量授权检查前后锁定语义不变。
- `CT-BROWSER-001` / `CT-SEC-002` 必须验证无变化轮询只读状态且复用当前摘要，版本/连接/数量变化、旧协议、手动刷新、锁定与销毁后重新读取；验证两项解锁状态并发、在途事件检查合并、写操作互斥、防重放、过期及迟到清理。构建页面必须验证加载反馈即时显示且不存在人为延迟样式；性能对比仅记录耗时、请求数、产物大小，不记录真实条目或秘密。
- `CT-SEC-002` / `CT-BROWSER-001` 必须覆盖解锁页无快捷方式、仅 PIN、仅生物识别、两者均可用、未启用/不可用/PIN 锁定、状态读取失败/超时及迟到响应；验证默认优先级、切换清空、6 位 PIN 单次提交、失败次数刷新、生物识别取消、主密码回退与隐藏/销毁清理。系统指纹弹窗仍须真机验收。
- `CT-BROWSER-001` 必须覆盖连接即时反馈、重复点击、权限/状态无回调超时、后台无响应、Native Host 安全错误分类、断连与迟到状态竞争；诊断不得回显原始错误或改变 mutation 重试语义。
- 初始化回归必须覆盖状态成功而列表无响应的超时，以及连续刷新与轮询复用同一轮读取；授权失效后的新轮次不能被旧轮次覆盖。
- `CT-BROWSER-001` 必须以至少 500 条虚构摘要验证分页渲染上限、末页可达、跨页搜索、列表缩短与锁定清理；浏览器构建后运行 `npm --prefix apps/bitwarden-browser run test:popup-build`，验证产物不会一次性创建全量条目的操作控件。
- 原生页面恢复必须验证真实构建中的底部导航、页头、紧凑条目/菜单、摘要查看不读秘密、显式编辑及离页清理、生成器/设置/保险库往返；普通及独立窗口路由不得改变精确文档 URL 或持久化 popup workspace。其他类型列表同样验证 25 条上限及跨页搜索；不得重新引入上游账号/云服务启动入口。
- `CT-BROWSER-001` 的 PopupPage 与构建产物回归必须覆盖首次异步插入筛选区、移除、再次插入及 loading 切换；未触发任何滚动事件前，有内容可见、无内容不占位。构建产物同时核对空区域收起样式已生成；目标浏览器补验首次打开的实际布局。
- `CT-ITEM-003/005`、`CT-AUTOFILL-001/002` 必须覆盖原生 SSH 公钥/标题及特有凭据 custom-field 匹配、无关字段与 Login 误捕获排除、HTTPS/空字段/Secret 子类型/Passkey/二次验证、部分更新秘密保留及单次确认；必须运行实际 core/Broker assignment 测试，不能只用传输 mock 证明授权成立。

- `CT-AUTOFILL-001/002` 与 `CT-ITEM-002/004` 覆盖原生 card/identity 计划、字段限定格式化/select、主密码、捕获部分更新、歧义拒绝和取消/重放；`CT-BROWSER-003` 覆盖生成器插入及桌面受控复制的目标/授权/期限和清理。
- `CT-AUTOFILL-001` 必须验证页内图标出现即为当前短期目标预取候选，点击复用同一在途请求并立即显示加载态；失焦、导航、只读变化、目标过期和销毁必须丢弃结果且清除迟到 OTP，不得跨目标复用。
- `CT-BROWSER-001` 必须验证实验副本的可调用会话/工具入口不包含 Vault 备份/恢复、批量文件导入或 SSH 扫描导入。按 Scope Matrix 留在桌面的工作流不再作为该副本迁移完成的验收缺口；既有恢复码编辑辅助与桌面/原插件兼容测试保留。
- 实验副本新增类型与工具必须覆盖 `CT-ITEM-002/003/004/005` 的完整编辑元数据、未读秘密保留、类型限定复制、trash/history 与永久删除区别；`CT-SEC-002` 和 `CT-BROWSER-003` 覆盖独立安全偏好、PIN/生物识别与四模式生成参数。`CT-PASSKEY-001` 覆盖原生事件入口、并存冲突、取消/锁定及 Login 归属删除；Firefox 仍无 proxy。
- `CT-AUTHENTICATOR-001` 覆盖 QR 可见性、受支持 profile、frame 单次校验、候选选择/覆盖确认、迟到清理与不自动保存；`CT-EMAIL-002/003` 覆盖真实原生 planner/executor 的 4–8 位与分格 OTP、非空字段、candidate 过期/导航、无 code audit 和 90 秒有界监听。`CT-VAULT-001/002` 覆盖创建防覆盖、轮换确认、密码输入清理及不重放未知结果。
- 实验性 Bitwarden 副本必须单独运行 native fill/capture/page/password-generation、独立 popup
  rendering、RPC 生命周期、Login clipboard/trash/history/恢复码和上游 generator/collector/executor 回归；`CT-BROWSER-001` 验证
  两个 Broker 的 HMAC 与 unlock owner 隔离，`CT-BROWSER-PACKAGE-001` 验证独立开发 ID、
  Host 注册计划和无云服务启动入口。macOS 上执行 Rust 两个 Native Host binary 的 launch tests；
  Windows 计划测试不能替代目标 OS 的 Host 启动与安装验收。
- `CT-RECOVERY-CODES-001` 覆盖独立窗口精确绑定/重载撤销、45 秒及原草稿期限、普通失焦清理、
  导入取消/迟到结果、原样保存与清理许可绑定、响应丢失不删除，以及桌面清理句柄的期限/单次/文件变化/撤销。
  原生文件框期间窗口焦点与隐藏事件仍须由 `AT-RECOVERY-CODES-001` 在目标浏览器和 OS 验收。

- Extension typecheck/test/build、Rust native-host test 和 browser parity 通过。
- Chrome/Chromium MV3 与 Firefox MV2 ZIP 必须由同一 source/version 构建；ZIP CRC、内部 manifest、固定
  identity、浏览器特定 permission 和无秘密/环境/source-map 文件校验通过。Firefox 不得包含
  `webAuthenticationProxy` 或宣称 Passkey proxy。
- Review ZIP 必须发布到同版本的不可变 R2 路径；Chrome/Firefox 公开下载内容必须与本次构建产物
  逐字节一致，Actions 摘要必须输出两个直接下载链接。
- 固定 ID、native-host install/uninstall、pair/revoke、RPC mismatch、navigation/replay/expiry 和 page fill 验收通过。
- Firefox 必须额外验证固定 Gecko ID、Mozilla `allowed_extensions` manifest、macOS 用户级目录或
  Windows HKCU registry、Host manifest path/ID 启动参数、pair/revoke、浏览器重启和卸载清理；使用
  `AT-BROWSER-FIREFOX-001` 记录目标 OS 证据。
- Windows 安装态在桌面运行时执行 `pnpm tauri:windows:browser-at`，必须同时验证 Chrome/Edge
  HKCU manifest registration、固定 extension origin、packaged Host 路径和真实 `vault.status` 往返；
  卸载后执行 `pnpm tauri:windows:browser-uninstall-at`，必须确认 registry、manifest 和非秘密 Host
  config 已清除。两个命令都必须在目标 Windows 执行，不能以交叉编译代替。
- 本地目标机测试包使用 `pnpm tauri:build` 与 `pnpm extension:zip`，两者默认绑定同一固定 sideload ID。
  只供本地解压安装的 Review Draft 必须显式设置 `VAULTMESH_EXTENSION_DISTRIBUTION=sideload-review`，
  复用仓库内公开且固定的 sideload key；该 key 不是商店凭证。商店或正式公开发布必须在同一环境
  提供独立 `WXT_CHROME_EXTENSION_KEY`，分别执行
  `pnpm tauri:release:build` 与 `pnpm extension:release:zip:all`；两条命令必须从 key 派生同一
  `VAULTMESH_BROWSER_EXTENSION_ID`，同时固定 Firefox Gecko ID；未显式选择分发模式、显式 ID 不匹配、
  未授权身份回退或 Firefox ID 漂移时必须在构建前失败。

### GATE-5 安全与依赖

- 仓库/fixture/log 扫描无真实秘密。
- 首次把源码仓库切换为 Public 前，当前树和全部可达 Git 历史必须完成凭据与私钥模式筛查；失败时保持 Private，疑似秘密值不得写入证据日志。
- 密码学、内存、Windows security 和 supply-chain blockers 已关闭或明确阻止公开发布。
- OAuth provider release configuration 和权限审查完成。

### GATE-6 平台发布

- macOS 签名/notarization、DMG/ZIP、Touch ID、sleep/system lock、best-effort window capture、browser host 验收。
- Windows installer、DPAPI/Hello 决策、lock/clipboard、Windows 10 2004+ window capture exclusion、browser host、uninstall 验收。
- macOS/Windows 登录项分别验证默认注册、静默托盘、锁定状态、关闭、重新启用和卸载清理。
- Upgrade、downgrade refusal、backup/restore、不可逆 migration 和 rollback compensation 验收。
- Test channel 必须完成三目标 updater artifact、Tauri 签名、R2 latest-last 发布及 `AT-UPDATE-*`；该证据不替代正式发布所需的 Apple notarization 或 Windows Authenticode。
- Test 与 Review 的完整三目标构建必须使用标准 GitHub-hosted 原生架构 Runner；发布 workflow 不得依赖 `self-hosted` 或自定义 Runner 标签。
- Review 发布必须使用独立 channel；`0.0.1-review` 作为 fresh-install 基线，不得覆盖 test channel 或对已有 `0.1.x` 安装启用 downgrade。
- Review GitHub Draft Prerelease 可以在 R2 完整发布后创建，但两个 DMG、Windows NSIS/MSI、Chrome ZIP
  与 Firefox ZIP 必须来自同一 source SHA，且两个 ZIP 已通过 R2 公网下载校验；Draft 必须保持 Draft、不得创建 Git Tag，并且不得在平台
  AT、Work 封存、Release record 门禁完成前公开。
- Release record 与 Git Tag 存在。
- Release 中引用的 Work 均为 schema-v2 Done 或已列入 `changes/archive.json` 的 legacy Work，且 `VAULTMESH_ARCHIVE_BASE_REF` 基线校验通过。

## 完成声明

代码合并不等于完成，也不等于已发布。schema-v2 Work 只有在适用自动化和平台 AT 通过后才能标记 Done；legacy Work 仍以 Verified 并封存完成。只有 Gate 1–6 中适用于该版本的项目通过、Release 记录和 Git Tag 存在才算已发布；Release 只引用 Done schema-v2 Work 或已封存 legacy Work，不回写历史状态或正文。
