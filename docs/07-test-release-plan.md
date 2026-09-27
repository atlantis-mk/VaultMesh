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
pnpm android:release:build
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
| `CT-BROWSER-*` | Tauri shared policy/capability、Rust broker + WXT extension non-secret preference tests；`CT-ITEM-001` 同时覆盖 Login 编辑字段保留、特权详情短期草稿、确认删除、防重复写入和结果不确定时不重试 |
| `CT-BROWSER-PACKAGE-001` | WXT Chrome MV3/Firefox MV2 manifest 与 ZIP contract、固定双 identity、macOS/Windows browser-specific Native Messaging manifest/注册/卸载、Rust Host Chrome origin 与 Firefox manifest-path/Gecko-ID 启动参数拒绝测试、Review workflow 六资产同 source gate，以及两个 ZIP 的不可变 R2 路径与公网逐字节校验 |
| `CT-AUTOFILL-*` | Tauri Rust broker tests + `apps/browser-extension/src/lib/*.test.ts`，验证来源、handle、gesture、锁定、单次 assignment 与失效拒绝 |
| `CT-AUTHENTICATOR-*` | extension QR target/UI/protocol/background tests + Tauri Login update/autofill broker regression |
| `CT-RECOVERY-CODES-*` | core Login payload/reauth/redaction + Tauri typed operation/clipboard/file parse（逐行与 Google 编号双栏）-confirm-delete/foreground-parenting + desktop/extension editor 逐次查看/复制复验和瞬时状态 contract tests |
| `CT-PASSKEY-*` | Tauri Rust passkey service/presentation tests；`CT-PASSKEY-002` 为 `apps/browser-extension/src/lib/passkey-proxy.test.ts`，验证启动即挂载、worker 重启后重新挂载、锁定或桌面不可达时保持挂载并等待后继续、仅显式拒绝解锁或未配对才 detach、页面取消处理 |
| `CT-EMAIL-*` | Tauri Rust email service tests；Gmail OAuth 必须只请求 `gmail.readonly`、拒绝实际授予 scope 缺失的部分授权并通过 Gmail Profile 读取邮箱地址；所有可分发 Tauri package workflow 必须从 GitHub repository Secret 注入已接受的 Gmail Desktop OAuth Client ID 与 Provider 签发的 Client Secret，并在 Client 属于其他 Google 项目、缺失、格式无效、Provider 不存在或 credential pair 不匹配时于编译前 fail closed；Client 绑定、scope 校验与 Provider 预检不得输出 Client ID、Client Secret、Token 或响应正文 |
| `CT-AGENT-PROTOCOL-001`、`CT-AGENT-AUTH-001`、`CT-AGENT-UNLOCK-001`、`CT-AGENT-POLICY-001`、`CT-AGENT-ACCOUNT-001`、`CT-AGENT-DISCOVERY-002`、`CT-AGENT-AUTHZ-002`、`CT-AGENT-AUTHZ-003`、`CT-AGENT-SSH-SAFE-001` | 机器可读 Agent registry parity、Tauri Rust owner-only broker、自定义 client key 的格式/隔离/重连/撤销、App 重启后 shim 重新 hello 与新 transport/session、frame delivery-safe/R0 同 request ID 重放和动作 `execution-unknown`、pairing/Agent unlock/action authorization 三窗口与三状态机隔离、desktop/browser/other-client unlock 不可借用、Agent-only runtime、默认 per-transport 与显式 client-shared unlock scope、相同 pairing identity 共享及不同身份隔离、同 scope 并发 pending 合并/多 waiter 一次唤醒/已显示窗口幂等、displayed transport 断开转移、已完成 request 不复用、单条并行/最后 transport 断连语义、scope 切换 fail-closed、独立持久化的空闲/最长连续解锁策略、“直到关机”只关闭绝对截止且 lease 不持久化、活动刷新与执行中/有限绝对到期语义、空闲及强制终止清理不受“直到关机”影响、主密码/PIN 不进入 MCP/IPC、VaultMesh 软件触发的 Agent lock、MCP 无 session 状态/锁定工具、最后 lease cleanup、独立最小权限且预热置顶的 action authorization window、30 秒 MCP wait/进度、broker 实际超时事件立即归零与同 request native continuation、超时保留窗口和 permission pending、账号非秘密索引的搜索/筛选/cursor、semantic capability 与 action tool 名分离、未预授权账号可见且未知 capability 明确拒绝、shim 单次请求构造、broker 单次解析与 connection-owned session、Canonical ActionPlan、typed predicate/lifetime/effect、一次 lease 原子消费及超时后下一次调用消费、connection permission 跨内部 session 轮换并在真实断连/锁定/重启/撤销清理、持久 AEAD 规则库、SSH exact/safe/all-command scope、R1 safe+connection 推荐、R3 exact-only、R4 exact+once Allow、R2/R3 同窗逐次 fresh confirmation、safe catalog 版本漂移、target/Host Key/policy 漂移、broker-owned actionDisplay、风险着色及无独立 action confirmation tests；`CT-AGENT-ACCOUNT-001` 同时证明 format 3 是唯一 create/write/read 格式、所有其他版本 pre-KDF refusal、不存在迁移或降级 API、connector-definition 原子 mutation/rollback 与生产代码不存在 Profile API；`CT-AGENT-PERMISSION-001` 只保留为历史证据 |
| `CT-AGENT-SECRET-001`、`CT-AGENT-LIFECYCLE-001`、`CT-AGENT-AUDIT-001` | Agent secret canary/redaction/audit allowlist、cancel/revoke/final-lock/crash/expiry cleanup、15 分钟内部 session 在同一 transport 透明轮换且不继承 authority、App 重启后新 transport 不恢复旧 authority 且不重复结果未知动作、final lock 保留 transport identity 并返回 typed lock error tests |
| `CT-AGENT-SSH-001`、`CT-AGENT-PTY-001`、`CT-AGENT-HTTP-001`、`CT-AGENT-HTTP-PATH-001`、`CT-AGENT-WEB-001`、`CT-AGENT-AUTHN-001` | Tauri Rust adapter contract/adversarial tests；HTTP CT 覆盖 exact 账户 origin、HTTP/HTTPS、public/private/loopback/link-local/metadata literal target、self-signed TLS、DNS 当次连接固定、redirect/cross-origin denial、Bearer 注入与有界输出；HTTP path CT 额外覆盖 access-token Secret direct schema、method risk floor、base-path confinement、单次 canonicalization、encoded separator/dot 拒绝、exact/`*`/terminal `**` predicate、method 隔离、Deny 优先与 matcher revision；protected-auth CT 覆盖 OTP、recovery code 与 Passkey 的 opaque target、single-use、成功提交和清理；固定测试 server/browser fixture，不使用生产凭据 |
| `CT-AGENT-CODEX-001`、`CT-AGENT-OPENCODE-001` | packaged stdio shim 的 tools/list/call/cancel/revoke/multi-account client E2E |
| `CT-TAURI-SHELL-*`、`CT-TAURI-COMMAND-*` | `apps/tauri-desktop` config/adapter/Rust command 与 Electron data migration contract tests |
| `CT-LAN-PAIRING-001` | Tauri Rust LAN advertisement parser、protocol/version/size rejection、同链路双栈 listener、随机六码生命周期、TLS 内 SPAKE2/key-confirmation、错误码/尝试上限/timeout/replay、单端发起与双端同时发起的唯一会话仲裁、双方 persistence acknowledgement、credential/index rollback、revoke/restart/lock cleanup 与 renderer-safe typed operation tests；renderer 真实路由覆盖锁定时直接访问拦截、解锁后显示、手动锁定/锁定事件/聚焦刷新后的页面卸载、配对码与设备列表清除和停止发现 |
| `CT-ANDROID-LAN-PAIRING-001` | 共用 LAN protocol 2.0 桌面↔Android 双实例配对、双向发起与错误/碰撞路径；Android Keystore 封存记录、固定 JNI DTO 脱敏、Vault 同步授权与撤销回滚、设备页直接展示已配对列表/空态/重试、行内更多按钮直接打开设备设置、配置不在列表展开、按所选设备隔离且移除后关闭、配对/重命名/撤销单弹窗切换、异步配对成功依据与失败/过期输入清理、进入不自动发现、离页清理、权限拒绝、Activity 暂停与超时关闭 listener 和多播资源 |
| `CT-ANDROID-HOME-001` | Android Compose 行内复制菜单、更多菜单和选择框的可访问 UI 行为；全部页、类型页和回收站首批 30 条、接近底部再追加 30 条、搜索与切换重置；当前已展示条目的选择、全选、取消、批量删除确认、Secret 永久删除告知、托管 SSH 排除、逐项失败停止与部分完成反馈；工具/设置入口保持原有操作路由 |
| `CT-TAURI-VAULT-*`、`CT-TAURI-DESKTOP-*` | Tauri Rust runtime integration tests + shared renderer tests；覆盖已启用 Touch ID 时锁定页每次挂载自动认证一次、StrictMode 不重复弹窗及取消后的手动重试 |
| `CT-TAURI-TRAY-THEME-001` | Windows light/dark/unknown 主题选择、黑白托盘资源尺寸/解码、macOS Retina 模板资源保持测试 |
| `CT-DESKTOP-STARTUP-*` | Tauri Rust autostart owner、固定参数、初始化标记、隐藏窗口配置、主窗口关闭销毁 WebView 与托盘重建、typed adapter 与设置 UI contract tests |
| `CT-UPDATE-001` | Rust-owned updater/no-renderer-capability、release-only HTTPS config、macOS/Windows 原生“检查更新…”菜单、主动/自动检查互斥、主动检查无更新/失败反馈、用户确认、安装前 lock/exit cleanup、Windows NSIS 覆盖复制前 Native Host 注销/停止与安装后恢复注册，以及标准 GitHub-hosted `macos-15` ARM64、`macos-15-intel` x86_64、`windows-2025` x64 原生目标/host 架构绑定、精确 Rust toolchain、按 OS/arch/target 隔离且忽略 workspace-only 版本变化的 dependency-only Cargo cache、workspace release object/编译期 credential 保存前清理、矩阵 `fail-fast: false`、上游失败时 publisher 明确失败并通过同 run “Re-run failed jobs”复用成功 artifact、发布 workflow 无 `self-hosted` 标签、manifest 的 SemVer/platform/signature/不可变 URL/三平台完整性与 latest-last publish contract tests；Windows target experimental package 必须只发布 immutable objects、保持 test channel 不变且不计入 Windows AT |
| `CT-ANDROID-UPDATE-001` | Android 更新清单生成脚本的版本/versionCode/哈希/大小/URL 与严格递增或同哈希重发；Kotlin 清单解析拒绝未知 schema、跨 host、非 HTTPS、错误路径/文件名与超限；versionCode 基数比较、ABI 选择回退、24 小时节流与跳过版本；Release 固定端点、Debug 空端点、无 `REQUEST_INSTALL_PACKAGES`、不跟随重定向；workflow 在 `latest.json` 之前发布并校验 `android.json` 的 JVM/contract tests |
| `CT-ANDROID-RELEASE-001` | Android Review 打包：`build-android-release.mjs` 的 versionCode 单调派生与 ABI 个位、四个 APK 资产命名、每个 APK 仅含预期 ABI 的 JNI runtime、aapt2 包名/版本校验、apksigner 单证书一致且匹配固定指纹、缺签名配置 fail closed；Gradle splits、Rust release ABI 与脚本一致，Debug 仍为单一 APK；Review workflow 的 Android job、keystore 清理、R2 immutable/公网校验与 Draft 资产 contract tests |
| `CT-UPDATE-REVIEW-001` | `0.0.1-review` fresh-install baseline 与当前 `0.1.2-review` build 的 workspace/Rust/Tauri/extension 版本一致性；Review workflow 固定使用 `channels/review/latest.json`，保留完整发布的三目标、签名、immutable、latest-last、精确 toolchain、dependency-only Cargo cache、workspace object 清理与失败任务同 run 恢复约束，并为 Windows同时生成 NSIS/MSI；Chrome/Firefox ZIP 必须进入同版本不可变 R2 路径并通过公网内容校验，R2 成功后只创建不含 Git Tag 的 GitHub Draft Prerelease并上传两个 DMG、Windows NSIS/MSI 与两个 ZIP；任一 prerequisite 失败时 Draft job 明确失败并可随失败任务重跑；阶段性 manifest 只引用已发布的 signed immutable artifact、首次从 `.1` 创建且后续严格递增，并允许在相同 current version 下只追加一个缺失平台，同时保持顶层字段、既有平台和 test channel 不变；阶段性清单和 Draft Prerelease 均不得计为完整正式发布或平台 AT |
| `CT-OSS-001` | 历史证据：`scripts/open-source-metadata.test.mjs` 保留原 AGPLv3-or-later 标准正文、首次公开 Work 封存记录和精确秘密扫描例外；该 ID 不再代表当前版本的许可元数据 |
| `CT-LICENSE-001` | `scripts/source-license-metadata.test.mjs` 验证 PolyForm Noncommercial 1.0.0 标准正文、Rust/pnpm SPDX、source-available/非商业表述、商业授权入口、历史 AGPL 权利与第三方权利边界一致，并保持 workspace package `private: true` |
| `CT-HISTORY-001` | `scripts/repository-history-policy.test.mjs` 验证当前 Git refs 不再包含已知 AGPL 发布提交、`main` 根快照使用 PolyForm Noncommercial，并保留当前许可证元数据 |
| `CT-REPOSITORY-001` | GitHub API、`git ls-remote` 与本地 SHA-256 清单验证同名 Public 仓库使用新的 repository identity、只包含当前 PolyForm `main`、不迁移旧 PR/Actions/Draft Release，并恢复 secret scanning、push protection、private vulnerability reporting、description 与 topics |
| `CT-TAURI-BROWSER-*` | Tauri broker/Rust native-host cross-process contract + RPC parity |
| `CT-BROWSER-001`（development startup） | `scripts/tauri-browser-dev.test.mjs` 的 key→ID→Host origin、专用 profile、debug Host→Tauri dev→WXT 顺序与双进程清理 contract |
| `CT-FEEDBACK-*` | Tauri renderer 与 extension popup 的 Toaster 位置、toast 触发和 Alert 静态合约测试 |
| `CT-TAURI-SOURCE-*` | Tauri owner path、workspace/lockfile、禁止 Electron/Native build reference 扫描；`CT-TAURI-SOURCE-002` 额外拒绝已退休的 C ABI header、artifact、export 与专属测试 |
| `CT-ANDROID-RUNTIME-001` | `vault-android-runtime` 的 create 不覆盖、format 4、unlock/wrong-password、status、幂等 lock、原子写入失败不发布会话、drop 清理与进程重建保持锁定测试 |
| `CT-ANDROID-JNI-001` | 桌面品牌衍生 Android PNG 图标的 RGBA 资源、白色自适应背景与 Manifest 引用；Android target JNI 固定符号与稳定非秘密结果、无 raw pointer/通用 router、Manifest 禁止 backup/cleartext 且仅按独立受控需求开放网络、Activity 启用 `FLAG_SECURE`、Compose 后台锁定与密码状态清理；创建/主密码解锁按钮内有界加载态、初始刷新隔离，PIN 提交或生物识别验证后的打开状态、验证成功后的摘要加载动画、空列表抑制和后台清理，解锁后顶栏状态栏 Insets、底部页面/顶部类型标签、原有功能入口与切页清理的 contract 测试；真机 instrumentation 在独立 cache 目录验证 create/wrong-password/unlock/lock、同路径 initialize 幂等、窗口保护 flag、`onPause`/`onStop` lock、权限弹窗仅暂停/恢复后连续三次返回可操作锁定页、隔离应用沙箱中真实通知权限弹窗隐藏后的锁定页恢复和迟到 mutation 的 UI 状态失效，不读取或清除用户 Vault |
| `CT-ANDROID-JNI-002` | Android Login 固定 JNI operation、脱敏 summary、编辑保留未替换密码、删除确认、原子提交失败回滚的 Rust/contract/instrumentation 测试；只使用独立 cache Vault 和合成凭据 |
| `CT-ANDROID-JNI-003` | Compose 对脱敏摘要本地搜索，Login 回收站固定 JNI operation、安全摘要、恢复、单项永久删除、清空确认，以及写盘失败回滚的 Rust/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-004` | Card、SSH、Identity、Secret 固定 JNI operation 与脱敏摘要；Card/SSH/Identity 回收站；未替换秘密和未编辑元数据保留、失败回滚、Passkey 与受管 SSH 拒绝；Compose 编辑/搜索/破坏性确认与独立 cache Vault instrumentation 测试 |
| `CT-ANDROID-JNI-005` | Android 固定主密码轮换 JNI、旧密码校验、候选 session、原子提交失败时旧文件/会话保留、成功后旧密码失效和冷启动新密码有效，以及 Compose 密码清理与生命周期失效测试 |
| `CT-ANDROID-JNI-006` | 固定字段 JNI 值访问逐项重新验证主密码，Passkey/未知/缺值/锁定拒绝；Kotlin clipboard sensitive 标签与 30 秒所有权清理、替换不误删、Compose 输入与迟到结果清理的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-007` | 四类固定历史 JNI、旧秘密脱敏摘要、版本归属拒绝、恢复当前版本、清空历史、受管 SSH 拒绝及写盘失败文件/会话回滚；Compose 破坏性确认、切换与锁定失效的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-008` | Login TOTP 固定 seed mutation 与当前代码复制 JNI、seed 归一化与无效输入拒绝、摘要存在性、主密码复验、原子失败回滚、普通编辑保留和锁定/重启失效的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-009` | 固定备份 staging JNI、format 4 密文导出、`content:` 文档 Provider 有界读写与回读校验、坏文件/错误密码/超限/写盘失败不替换当前文件会话、恢复重置同步 epoch/授权、Compose 确认与后台锁定的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-010` | core 密码健康固定 JNI 安全投影只含分数/ID、弱/重复/过期分类、锁定拒绝、Compose 主动读取、关闭/切换/后台/迟到结果清理与大列表按需渲染的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-011` | Login 恢复码固定 JNI 的有界解析、Google 编号双栏、存在性摘要、逐次主密码复验、单码复制、普通编辑保留、写盘失败回滚；`content:` 文档 UTF-8/大小限制、文件框锁定后重新解锁、原样保存后单独确认且仅内容未变和提供者支持时删除的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-012` | 卡片固定编辑详情不含完整卡号/CVV/PIN，严格补充 DTO 拒绝未知/超限字段，完整新建/更新保留未替换数字秘密且单次原子提交，写盘失败旧文件/会话不变；Compose 仅显式编辑读取、取消/切换/后台/迟到结果清理的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-013` | 普通 Secret 固定编辑详情不含值并拒绝 Passkey，严格补充 DTO 拒绝未知/超限字段，完整创建/更新保留未替换值、原类型和内部 lifecycle Scopes，core 日期/网站校验及原子失败回滚；Compose 显式编辑、取消/切换/后台/迟到详情清理的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-014` | SSH 固定编辑详情不含认证值并拒绝托管 alias，严格补充 DTO 拒绝未知/超限字段，完整创建/更新保留未替换认证值、清除与替换互斥及原子失败回滚；Compose 显式编辑、取消/切换/后台/迟到详情清理的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-015` | Identity 固定完整编辑详情保留多值 UUID/标签/首选标志，严格结构化输入拒绝未知/超限字段，core 校验无效邮箱/日期/网址与首选项，完整创建/更新的失败回滚及冷启动持久化；Compose 显式编辑、取消/切换/后台/迟到详情清理的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-016` | Login 固定编辑详情包含附加 URL/自定义字段而不含密码/TOTP seed/恢复码，严格补充 DTO 拒绝未知/超限字段；完整创建/更新保留未替换密码、TOTP seed 和恢复码并原子失败回滚；Compose 显式编辑、取消/切换/后台/迟到详情清理的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-017` | 随机包装秘密只经固定 JNI 交付、不输出 Vault Key；Rust 错误秘密/损坏记录/写入失败/禁用/主密码轮换保持正确状态；Kotlin Keystore 强生物识别逐次授权、注册失效、私有封存/删除、锁定与后台迟到清理；前台锁定时无需自定义页直接请求一次系统 Prompt、取消与失败不循环自动弹出且回退可用的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-JNI-018` | 六位 PIN 与 Keystore 封存设备秘密共同派生包装密钥；Rust 错误/第五次失败原子计数、成功主密码重置、写盘失败/禁用/损坏拒绝及锁定会话保持；Compose PIN 与主密码单方式展示、遮蔽输入、第六位提交清空、第五次失败切换主密码、后台清理的 Host/contract/instrumentation 测试 |
| `CT-ANDROID-REVEAL-001` | 已审核的字段 JNI 按次主密码验证和 Passkey/缺值拒绝；Compose 显式查看单值、提交前清空密码、30 秒自动关闭、用户关闭/切换/锁定/后台/迟到响应清除，`FLAG_SECURE` 与长值按需呈现的 contract/instrumentation 测试 |
| `CT-ANDROID-GENERATOR-001` | Android SecureRandom 生成器的密码长度/每类字符覆盖/歧义字符排除、用户名与邮箱别名形状及无效参数拒绝的 JVM 测试；Compose 结果、复制和草稿填入仅在当前会话有效 |
| `CT-NATIVE-*` | 历史 Native Preview 证据只保留在 Rejected Change；当前源码不再执行 |
| `AT-*` | packaged/manual user-visible acceptance；证据写入对应 Change/Release |
| `AT-SERVICE-001`、`AT-SERVICE-AUTO-001` | macOS/Windows packaged Tauri 的网站/服务 CRUD、原 item 导航、锁定清理，以及约 1000 条记录的预览、批量应用、待确认、merge/split/move/ignore、重跑和 rollback |
| `AT-API-PROFILE-001` | macOS/Windows packaged Tauri 在同一 Service 配置 Production/Staging/Local、none/Bearer/Basic/API Key、literal/protected Header、delete/restore/lock cleanup，并由真实 Codex/OpenCode 验证全部 live Environment 只投影 opaque ref/label/kind/http capability/可选 openapiUrl，不能读取 detail；后续执行仍需独立 Agent unlock 与 Action Lease |
| `AT-API-REQUEST-001` | macOS/Windows packaged Tauri 使用无生产凭据 fixture 验证 none/Bearer/Basic/API-key GET/POST JSON/text、canonical preview、原生 mutation/private/HTTP 确认、public HTTP/self-signed/metadata/redirect/oversize/canary 拒绝、cancel/timeout/lock/window close/Vault switch cleanup 与 `execution-unknown`；目标 OS 分别执行，不以交叉编译替代 |
| `AT-TAURI-MACOS-002`、`AT-TAURI-WINDOWS-002` | packaged Tauri 主窗口的系统截图/录屏内容捕获保护；macOS 记录 best-effort 结果，Windows 10 2004+ 必须从公共捕获路径排除 |
| `AT-TAURI-WINDOWS-003` | packaged Windows Tauri 在系统 light/dark 启动、运行中双向主题切换、Explorer/应用重启及主题读取失败回退时的托盘图标可读性和即时更新 |
| `AT-UPDATE-MACOS-001`、`AT-UPDATE-WINDOWS-001` | 目标 OS/architecture 从旧版安装开始验证无更新、取消、离线、篡改拒绝、已解锁确认后的 lock/cleanup、R2 test channel 成功更新，以及 Windows installer exit/macOS restart；macOS 分别覆盖 aarch64/x86_64，两平台均从原生应用菜单验证主动检查的无更新、失败与发现更新路径 |
| `AT-ANDROID-UPDATE-001` | 已安装旧 Review APK 的 arm64 真机在前台收到新版本提示，确认选中 arm64-v8a 与 SHA-256，经系统浏览器下载覆盖安装后保险库数据保留；验证稍后、跳过此版本、关闭自动检查、手动检查无更新/离线失败，以及 24 小时内不重复自动检查 |
| `AT-ANDROID-RELEASE-001` | 从同一 Review run 下载 APK：arm64 真机安装 arm64-v8a 与 universal、32 位或兼容 armeabi-v7a 设备安装 armeabi-v7a、x86_64 模拟器安装 x86_64，完成 create/unlock/lock 冒烟；验证更高 Review 版本覆盖安装保留 Vault、同版本不同 ABI 互相覆盖安装、证书指纹与发布记录一致；不得触碰用户产品 Vault |
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
| `AT-ANDROID-001` | arm64 真机的 fresh create、正确/错误密码 unlock、显式和后台 lock（含快速 Home 往返）、任务划除/进程终止/冷启动保持锁定、`FLAG_SECURE` 截屏与最近任务保护、应用数据 backup exclusion；交叉编译和模拟器不得替代真机验收 |
| `AT-ANDROID-002` | arm64 真机使用合成数据完成 Login 新增、脱敏列表、空密码编辑保留、删除确认、锁定后拒绝和冷启动持久化；不得读取、覆盖或清除产品 application ID 的用户 Vault |
| `AT-ANDROID-003` | arm64 真机使用合成数据验证 Login/回收站搜索、恢复、永久删除和清空确认；后台锁定后查询与回收站摘要必须清除，重新解锁从加密 Vault 刷新 |
| `AT-ANDROID-004` | arm64 真机使用合成数据逐类验证 Card、SSH、Identity、Secret 新增/脱敏列表/编辑/删除；Card、SSH、Identity 的恢复、永久删除和清空确认；后台锁定、冷启动持久化及 release JNI；不得读取、覆盖或清除产品 application ID 的用户 Vault |
| `AT-ANDROID-005` | arm64 真机在独立 Debug Vault 中验证主密码轮换的旧密码拒绝、确认不一致、成功、后台锁定、冷启动新密码解锁，以及失败后原数据可读；不得触碰产品 application ID 的用户 Vault |
| `AT-ANDROID-006` | arm64 真机使用合成凭据验证各类型字段复制、错误主密码、锁定、Passkey 排除、Android 10/13+ 敏感剪贴板提示与 30 秒到期；复制其他内容后不得被 VaultMesh 定时清除 |
| `AT-ANDROID-007` | arm64 真机使用合成数据逐类验证 Login、Card、SSH、Identity 历史脱敏列表、恢复与清空确认、错误版本拒绝、后台锁定清理及冷启动持久化；受管 SSH alias 只读 |
| `AT-ANDROID-008` | arm64 真机使用合成 TOTP seed 验证设置、替换、移除、无效输入、当前代码复制、错误主密码、时间边界、后台锁定与重启持久化；不得显示或记录 seed |
| `AT-ANDROID-009` | arm64 真机使用本机与第三方文档 Provider 验证加密备份回读、选择取消、错误密码、坏文件、超限、format 3 拒绝、恢复覆盖与重启、后台锁定和恢复后同步重新授权；不得触碰产品 application ID 的用户 Vault |
| `AT-ANDROID-010` | arm64 真机使用合成 Login 验证弱密码、重复使用、过期分类与标题关联、后台清理及约 1000 条记录响应；不得展示密码值 |
| `AT-ANDROID-011` | arm64 真机验证密码、用户名、邮箱别名生成参数，复制敏感提示、Login 草稿填入和后台/锁定清理；不得自动保存或保留生成历史 |
| `AT-ANDROID-012` | arm64 真机使用合成恢复码验证粘贴、UTF-8 与 Google 文件导入、清除、错误主密码查看/复制、剪贴板清理、文件选择后台锁定后重新解锁、源文件保留/删除确认及提供者拒绝或文件改变、冷启动持久化；不得触碰产品 application ID 的用户 Vault |
| `AT-ANDROID-013` | arm64 真机使用合成 Login/Card/SSH/Secret 值验证每次查看重新输入主密码、错误密码/Passkey/缺值拒绝、30 秒超时、关闭/切换/后台/锁定后值清除、迟到响应和 `FLAG_SECURE` 截屏/最近任务行为；核对辅助功能实际可见范围 |
| `AT-ANDROID-014` | arm64 真机使用合成卡片验证完整字段创建、打开编辑器脱敏详情、补充字段修改/清除、空卡号和安全码/PIN 保留、明确清除、取消/切换/后台清理、锁定/冷启动持久化及与桌面读取同一 format 4 Vault 的字段一致性 |
| `AT-ANDROID-015` | arm64 真机使用合成普通 Secret 验证环境、Scopes、到期、网站、备注、文件夹与复验设置创建/编辑、空值保留、Passkey 排除、取消/后台清理、冷启动和跨桌面/浏览器的元数据一致性 |
| `AT-ANDROID-016` | arm64 真机使用合成 SSH 凭据验证备注、文件夹、收藏与复验设置创建/编辑，四类认证值留空保留及明确清除，托管 alias 只读、取消/后台清理、冷启动和与桌面共用 format 4 Vault 的字段一致性 |
| `AT-ANDROID-017` | arm64 真机使用合成 Identity 验证完整字段、多邮箱/电话/地址的增删改与首选、稳定 ID、无效输入、取消/后台清理、冷启动及桌面共用 format 4 Vault 的资料一致性 |
| `AT-ANDROID-018` | arm64 真机使用合成 Login 验证附加 URL、自定义字段、备注、文件夹与填充/复验策略创建/编辑，空密码保留、TOTP/恢复码保持、取消/后台清理、冷启动及跨桌面/浏览器字段一致性 |
| `AT-ANDROID-019` | arm64 真机用独立 Debug Vault 验证强生物识别启用、锁定后逐次解锁、取消/失败/无生物识别、注册变化、重启、主密码轮换、关闭和主密码回退；确认产品 application ID 的数据不被触碰 |
| `AT-ANDROID-020` | arm64 真机用独立 Debug Vault 验证六位 PIN 设置/确认、错误次数直到五次锁定、主密码重置、正确 PIN、后台取消、进程重启、Keystore 失效、关闭及备份恢复后回退；不得触碰产品 application ID 的用户 Vault |
| `AT-ANDROID-021` | arm64 Android Debug 与 packaged macOS/Windows 桌面处于同一 LAN，双方分别开启发现、展示本机码并由对端输入完成协议 2.0 配对；验证错误码/尝试上限、双端同时发起、信任重启、重命名/撤销、权限拒绝与撤销、Wi-Fi/蜂窝切换、暂停/锁定/离页/超时清理及不触碰产品 application ID 的数据 |

## Android 同步验收

- `CT-ANDROID-LAN-SYNC-001`：Android 原子 mutation/checkpoint、双向真实共享 TLS 同步、锁定密文缓存/解锁合并、重连、撤销、失败写盘、缓存失败及恢复隔离；固定 JNI、Service 与扫描独立、权限/网络/任务移除清理、Compose 状态和冲突操作验证。
- `AT-ANDROID-022`：arm64 Debug 与桌面独立合成 Vault 完成配对后关闭双方扫描，新增/修改/删除双向同步；离页、后台锁定接收、解锁合并、Wi-Fi 重连、进程重启、撤销及权限拒绝；不读取或清除用户保险库。

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

- `CT-ANDROID-AUTOFILL-001/002` 覆盖 Rust 授权/原子保存、快捷认证只授权当前填充或保存请求、PIN 共享失败计数、包名片段候选排序、私有加密选择顺序、锁定态候选预览的 Keystore 加密、Vault 指纹变化失效、少量相关候选与一次性选中 ID、点选后重新授权及 Rust 校验、用户名优先于网址的列表与系统候选展示、应用图标和紧凑行内布局、最近选择和已关联账号后展示随机账号（适用时）、本机号码与通用入口、其他相关候选随后展示、包名次级标签转应用名称、底部弹窗标题中的应用身份、输入停顿后自动筛选与后端查询限频、相同查询复用及迟到结果丢弃、单一解锁方式切换及最近/其他账号分组、记住关联的原子提交与回滚、用户名成对填充与密码栏独立填充、弹窗外点击与显式取消同路径且弹窗内操作不误取消、取消后以新的一次性请求允许重新触发系统 Autofill、注册新密码表单只为文本用户名提供随机账号直填且不解锁 Vault、QQ 数字手机号字段的精确目标与结构守卫及非 QQ/验证码反例、Kotlin 表单/捕获/生命周期及 JNI/Manifest；`AT-ANDROID-023` 使用隔离合成 Vault，在真机验证系统先显示多个相关账号、点选后主密码/生物识别/PIN、已授权直接填充、QQ 候选与最近选择排序、显式关联、取消、过期和锁定，不能以编译替代。
- `CT-ANDROID-AUTOFILL-003` 覆盖 SIM 权限守卫、号码规范化、国家拨号前缀移除、加密备用写入/读取/删除、候选行仅显示末四位和用户名独立 Dataset；`AT-ANDROID-024` 在真机通过合成号码验证它显示在已关联账号下方且位于 VaultMesh 入口上方、预览脱敏但填入完整本地号码且不带国家拨号前缀，并验证 QQ 注册手机号字段可提供号码而不提供字母随机用户名，以及无权限、无号码和取消路径，不读取或记录真实号码。
- `CT-ANDROID-AUTOFILL-004` 覆盖明确短信验证码字段与密码/TOTP/银行卡/无标签数字反例、聚焦和同 origin 约束、Google Play 权限/目标已有 Retriever 守卫、一次性字段和目标绑定、验证码长度、居中且不透明的等待卡片、卡片外点击和按钮取消、超时/后台/签名变化，以及 OTP 结果不进入登录保存；`AT-ANDROID-025` 在支持 Google Play 服务的真机验证候选、首次系统授权、用户自行发送的测试短信到达后的单字段填充、取消/拒绝/超时和目标应用自行读取路径。测试不得记录短信正文或验证码。

- `cargo test -p vaultmesh-android-runtime` 和适用的 `CT-ANDROID-JNI-001` 至 `CT-ANDROID-JNI-018` contract test 通过。
- `testDebugUnitTest` 中的 `CT-ANDROID-GENERATOR-001` 通过。
- `CT-ANDROID-REVEAL-001` 的 contract 与仪器化测试包通过；真机行为以 `AT-ANDROID-013` 验收。
- `CT-ANDROID-LAN-PAIRING-001` 的桌面↔Android 同协议测试与 Android arm64/x86_64 构建通过；跨设备行为以 `AT-ANDROID-021` 验收。
- Android arm64/x86_64 target 必须编译固定 JNI exports，Release 另须编译 armeabi-v7a；Manifest 只可增加生物识别、`REQ-ANDROID-021` 前台 LAN 和 `REQ-ANDROID-023` 本机号码所需权限，不得声明外部存储、Credential Manager 或 READ_SMS 权限；RECEIVE_SMS 仅允许 REQ-ANDROID-026 的显式互通路径，RECEIVE_BOOT_COMPLETED 仅用于恢复用户已开启且认证记录有效的互通；REQ-ANDROID-023 允许受 BIND_AUTOFILL_SERVICE 保护的导出系统 Autofill 服务及非导出认证页，允许 QUERY_ALL_PACKAGES 仅按请求包名读取签名，并允许 READ_PHONE_NUMBERS 只在用户主动设置时申请；REQ-ANDROID-025 仅通过 Google Play SMS Code Autofill API 取得经系统授权的验证码；REQ-ANDROID-022 允许非导出 connectedDevice 前台服务及对应权限；REQ-ANDROID-027 只允许以已有 INTERNET 前台检查更新清单，不得声明 `REQUEST_INSTALL_PACKAGES`。
- Debug APK 可以在模拟器验证布局与基本 lifecycle，但 `FLAG_SECURE`、后台/系统锁定、任务划除、进程终止、backup exclusion 和 release JNI 必须由 `AT-ANDROID-001` 在 arm64 真机验收。
- 未完成 `AT-ANDROID-001`、签名、依赖审查与独立发布记录前，Android 保持 Partial 且不得描述为已发布。

### GATE-4 Browser

#### 浏览器手动测试台

- `autofill-test.html` 必须为当前 Login、card、identity、SSH、全部 Secret 子类型、OTP（TOTP/邮件/手机短信）、设备号码和 Passkey 提供代表性测试入口；Secret 枚举由 `apps/browser-extension/src/lib/save-capture.ts` 拥有，测试台通过回归测试检查覆盖，不在文档复制枚举。
- `AT-AUTOFILL-001/002` 使用测试台的填充、保存、特殊提交、扩展字段与生命周期页面，逐项验证正确值/来源、保存后的保险库回读、新建/更新/忽略、表单归属、已有值保护及取消/失效。`AT-EMAIL-003` 使用 OTP 页；`AT-PASSKEY-001` 使用本页注册公钥验证 challenge/origin/RP/用户在场/凭据 ID/ES256 签名，并人工核对 VaultMesh 原生确认与实际提供方。二维码页按 `CT-AUTHENTICATOR-001` 的场景进行人工验收。
- 测试台必须将 DOM 检查与人工端到端验收分开：非空和 input/change、可见保存容器、WebAuthn 返回均不得单独标记整页通过。每组清单只有全部人工通过后才可确认；未测试、失败、环境受限必须保持未通过。页内结果不得输出字段值；sessionStorage 只保存整组通过时间，不保存表单数据、二维码或凭据。
- HTTP 只用于允许 HTTP 的路径；支付卡、SSH、Secret 正向用例必须在受信任 HTTPS 环境完成。Firefox 不支持 VaultMesh Passkey proxy。二维码使用本地合成测试图片，重置/离页必须撤销预览 URL；本页不得上传数据。
- `node --test scripts/autofill-test-menu.test.mjs` 验证入口/清单、Secret 类型覆盖、DOM 路径、脱敏、完成门槛与本地 Passkey 验签拒绝路径，作为 `CT-AUTOFILL-001/002` 和 `CT-PASSKEY-001` 的测试台回归补充；不得替代真实扩展/Broker 或平台 AT。
- Android 原生 Autofill、真实服务端登录/导航提交、写盘故障、设备/授权状态及不可访问 frame 需要配合相应隔离环境验收；测试台的原生 `form.submit()` 用例只观察 formdata 并由 CSP 阻止网络，不能注入或证明这些外部状态。不得因测试表单存在而宣称产品功能通过。

#### 浏览器 Gate 检查

- 当前 WXT 原插件的 `CT-BROWSER-001/003` 必须覆盖至少 500 条摘要的 25 条分页、跨页搜索与页码收敛，Broker 权威 Login/Secret/SSH 建议及无字段上下文时 card/identity 不误标，桌面锁定/撤销/停止后的 popup 全量瞬态清理，以及生成结果/历史 60 秒与隐藏清理和桌面受控复制。`CT-ITEM-001/002/003/004/005` 与 `CT-RECOVERY-001` 必须覆盖按实际存在值生成复制菜单、单条删除的可恢复/永久语义、四类安全恢复摘要和类型/目标绑定；编辑草稿必须覆盖隐藏、5 分钟期限、迟到详情及恢复码文件框 45 秒例外。
- `CT-AUTOFILL-001` 必须验证多字段表单按 scope 单次自动目标采集、已尝试 scope 不重新采集、100 毫秒 mutation 调度不饥饿、collector 忙与销毁、并发 focus/capture、重复候选点击以及 profile/DOM 并行后的失效拒绝；`CT-BROWSER-002` 同时验证 Rust 轻量授权检查前后锁定语义不变。
- `CT-BROWSER-001` / `CT-SEC-002` 必须验证无变化轮询只读状态且复用当前摘要，版本/连接/数量变化、旧协议、手动刷新、锁定与销毁后重新读取；验证两项解锁状态并发、在途事件检查合并、写操作互斥、防重放、过期及迟到清理。构建页面必须验证加载反馈即时显示且不存在人为延迟样式；性能对比仅记录耗时、请求数、产物大小，不记录真实条目或秘密。
- `CT-BROWSER-001` 必须以 Broker 实际事件形状验证空闲锁定后 PIN 重新解锁仍可读取历史 `vault-locked` 和新增 `vault-changed`；后者应刷新当前授权摘要，未知事件仍须拒绝，不得把合法事件解析失败显示为桌面断连。
- `CT-SEC-002` / `CT-BROWSER-001` 必须覆盖解锁页无快捷方式、仅 PIN、仅生物识别、两者均可用、未启用/不可用/PIN 锁定、状态读取失败/超时及迟到响应；验证默认优先级、切换清空、6 位 PIN 单次提交、失败次数刷新、生物识别取消、主密码回退与隐藏/销毁清理。系统指纹弹窗仍须真机验收。
- `CT-BROWSER-001` 必须覆盖连接即时反馈、重复点击、权限/状态无回调超时、后台无响应、Native Host 安全错误分类、断连与迟到状态竞争；诊断不得回显原始错误或改变 mutation 重试语义。
- 初始化回归必须覆盖状态成功而列表无响应的超时，以及连续刷新与轮询复用同一轮读取；授权失效后的新轮次不能被旧轮次覆盖。
- `CT-BROWSER-001` 必须以至少 500 条虚构摘要验证分页渲染上限、末页可达、跨页搜索、列表缩短与锁定清理；WXT 构建产物不得一次性创建全量条目的操作控件。
- `CT-ITEM-003/005`、`CT-AUTOFILL-001/002` 必须覆盖 HTTPS 空字段、Secret 子类型/Passkey 排除、二次验证、部分更新秘密保留及单次确认；必须运行实际 core/Broker assignment 测试，不能只用传输 mock 证明授权成立。
- `CT-AUTOFILL-001/002` 与 `CT-ITEM-002/004` 覆盖 card/identity 字段限定格式化、主密码、捕获部分更新、歧义拒绝和取消/重放；`CT-BROWSER-003` 覆盖生成器插入及桌面受控复制的目标/授权/期限和清理。
- `CT-AUTOFILL-001` 必须验证页内图标出现即为当前短期目标预取候选，点击复用同一在途请求并立即显示加载态；失焦、导航、只读变化、目标过期和销毁必须丢弃结果且清除迟到 OTP，不得跨目标复用。
- `CT-AUTHENTICATOR-001` 覆盖 QR 可见性、受支持 profile、候选选择/覆盖确认、迟到清理与不自动保存；`CT-EMAIL-002/003` 覆盖 4–8 位与分格 OTP、非空字段、candidate 过期/导航、无 code audit 和 90 秒有界监听。

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
- 仓库固定的公开 key 是 Chrome Web Store 条目公钥（ID `bdneegbnjbheblmamalplnddbodcghbg`），
  不是商店凭证。本地目标机测试包使用 `pnpm tauri:build` 与 `pnpm extension:zip`，Review Draft 可以
  显式设置 `VAULTMESH_EXTENSION_DISTRIBUTION=sideload-review`；商店或正式公开发布执行
  `pnpm tauri:release:build` 与 `pnpm extension:release:zip:all`。所有命令必须从同一 key 派生同一
  `VAULTMESH_BROWSER_EXTENSION_ID`，同时固定 Firefox Gecko ID；未知分发模式、显式 ID 不匹配或
  Firefox ID 漂移时必须在构建前失败。

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
- Review GitHub Draft Prerelease 可以在 R2 完整发布后创建，但两个 DMG、Windows NSIS/MSI、Chrome ZIP、
  Firefox ZIP 与四个 Android APK（universal、arm64-v8a、armeabi-v7a、x86_64）必须来自同一 source SHA，且 ZIP 与 APK 已通过 R2 公网下载校验；
  Android APK 由 `ADR-0048` 的 CI release keystore 签名，Review 构建不计为 `AT-ANDROID-RELEASE-001` 或 Android 已发布；Draft 必须保持 Draft、不得创建 Git Tag，并且不得在平台
  AT、Work 封存、Release record 门禁完成前公开。
- Release record 与 Git Tag 存在。
- Release 中引用的 Work 均为 schema-v2 Done 或已列入 `changes/archive.json` 的 legacy Work，且 `VAULTMESH_ARCHIVE_BASE_REF` 基线校验通过。

## 完成声明

代码合并不等于完成，也不等于已发布。schema-v2 Work 只有在适用自动化和平台 AT 通过后才能标记 Done；legacy Work 仍以 Verified 并封存完成。只有 Gate 1–6 中适用于该版本的项目通过、Release 记录和 Git Tag 存在才算已发布；Release 只引用 Done schema-v2 Work 或已封存 legacy Work，不回写历史状态或正文。

## 设备填充互通验收

- `CT-DEVICE-ASSIST-001`：真实双实例 TLS、独立授权、秘密 DTO 隔离、120 秒 TTL、单次消费、取消、撤销、重放、证书与恢复隔离。
- `CT-DEVICE-ASSIST-002`：Android SMS 解析/权限/服务、持久互通开关、关闭防复活、密文指纹绑定的锁定冷启动恢复及损坏/替换拒绝、号码来源、JNI、Browser schema/policy/dispatcher/client parity、原文档字段与迟到响应拒绝。
- `CT-DEVICE-ASSIST-002` 的表单回归必须直接读取 `autofill-test.html` 专项及注册/登录真实夹具，验证电话标签、混合账号、短信与手机号优先级、单框/分格及无语义数字框/已有值隔离；入口、扩展筛选与 Rust assignment 的判断必须一致；HTTP/HTTPS 均可逐次点选发起号码与短信请求，非 Web 协议、跨 origin/frame、未点选即消费仍必须拒绝。
- `CT-DEVICE-ASSIST-001`/`CT-DEVICE-ASSIST-002` 必须覆盖慢端点不阻塞已就绪候选、同一手机重复地址不重复连接，以及界面无响应/无效响应、10 秒超时、60 秒期限、关闭与迟到响应取消。
- `CT-DEVICE-ASSIST-001`/`CT-DEVICE-ASSIST-002` 必须验证 v2 认证推送、号码凭据库注册及 Vault/证书隔离、离线本地填充、各电脑独立消费、同机消费去重及原始 TTL、权限/号码变化更新、旧 v1 回退、同一手机多验证码同时展示和连续点击的请求竞态。已消费 opaque ID 与原到期时间可在平台凭据库保留到原两分钟期限以防重启重放，不保存验证码、短信正文或来源历史。
- `AT-DEVICE-ASSIST-001`：无 Google 服务 Android 与 macOS/Windows 的 Chromium/Firefox 安装态号码及 SMS 填充，锁屏/后台、网络切换、任务移除保持互通、开关/通知停止、进程恢复和开机后无需 Vault 解锁、强制停止及撤销，Android 17 限制提示及手动回退。只使用合成测试消息，不记录真实号码或验证码；未执行的平台必须保留待验收。
