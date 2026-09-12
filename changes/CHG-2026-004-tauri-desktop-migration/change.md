# 以 Tauri 2 完整替换 Electron 桌面运行时

- Work ID：`CHG-2026-004-tauri-desktop-migration`
- 类型：Migration
- 状态：Implementing
- 主规格：`../../specs/tauri-desktop-migration.md`
- 决策：`../../adr/0005-tauri-desktop-runtime.md`

## 问题或目标

SwiftUI/AppKit 与未来 WinUI 的双端重写无法有效复用现有 React desktop UI，且必须重复实现
browser broker、平台安全适配和发布链路。VaultMesh 改为以 Tauri 2 作为 macOS/Windows
统一桌面壳，直接复用 React/Vite renderer，并把 Vault、授权、持久化和 OS 能力放在
Rust/Tauri 特权进程中。最终目标是默认开发、构建、测试、打包和 browser registration
均不依赖 Electron。

本 Change 已由用户明确接受架构方向；行为增量已合并到主规格并进入 Implementing。

## 预期行为

- `REQ-TAURI-001`：macOS/Windows 默认桌面实现必须由 Tauri 2 提供，并保持所有当前
  Required Vault、Item、Browser、Email、SSH、Passkey 和安全行为。
- React renderer 必须通过 typed adapter 工作，不获得 Node、filesystem、generic shell 或
  任意 Tauri invoke 能力。
- Tauri Rust runtime 必须直接复用 `vault-core`/共享 Rust operation，不通过 N-API，也不
  启动 Electron 或 Node sidecar 承担长期特权服务。
- 本地 SSH scan 发现仅私钥候选时，导入弹窗必须允许用户可选手动补充公钥；留空仍可导入，
  且仅私钥记录之后可以在 SSH 密钥编辑器中补充公钥。扫描所得私钥继续只保留在 Rust
  有界 session，不得进入 renderer。
- SSH 公钥安装必须由 Rust 特权服务完成：先返回并由用户确认当前主机密钥指纹，提交时
  必须重新连接并比对该指纹；认证可以使用账号中保存的密码、SSH Agent 或另一把 Vault
  私钥。公钥通过 SSH channel stdin 写入固定远端命令，不得把密码、私钥或公钥拼入本地
  shell/进程参数；重复安装必须返回 `alreadyPresent`。只要待安装记录包含私钥，首次安装
  或已存在路径都必须直接重新连接验证该密钥登录；需要主密码复核时 renderer 必须先收集，
  结果必须区分验证成功、私钥不可用与实际验证失败，不得把失败笼统显示为“尚未验证”。
- SSH 外部客户端枚举与启动必须由 Rust 特权服务完成；renderer 只能选择固定的系统终端、
  VS Code 或复制命令操作。Rust 必须校验 account/host/port/username 并生成固定 SSH 参数，
  不得接受 renderer 提供的 shell、可执行文件或参数。复制命令不得包含 Vault 私钥或本地
  临时路径；失焦锁定开启时不得为外部进程释放 Vault 私钥或自动复制密码。允许保持解锁且
  使用既有合并型 SSH 记录的私钥时，私钥只能写入 0600/owner-only 的有界 Rust 临时会话，
  并在 SSH 会话结束、final lock 或进程退出时清理。
- SSH 剪贴板命令导入必须由 Rust 读取系统剪贴板并按无执行语义解析；SSH 密钥生成必须在
  Rust 特权进程内完成，私钥口令不得进入 shell 或进程参数。受管密钥目录和私钥必须为
  owner-only，目标私钥或 `.pub` 已存在时必须拒绝且不得覆盖。
- macOS 桌面 Touch ID 必须与浏览器快速解锁使用独立 device credential，只包装当前 Vault
  Key；新建、改密、恢复或切换 Vault 必须失效旧凭据。Touch ID 已启用时，桌面锁定解锁页
  必须在状态就绪后自动发起一次系统认证，取消或失败后保留手动重试和主密码/PIN fallback，
  且不得因 React 重渲染重复提示。typed renderer adapter 的每个 operation
  必须有 Rust dispatcher owner；已由 Rust browser broker 原生确认取代的 renderer fill channel
  不得继续暴露无接收端的桌面 API。
- Email OTP 后台与手动扫描只能在短临界区内读取 Vault 账户/凭据快照和提交刷新凭据、
  游标、状态及候选；Gmail、Outlook、IMAP 的 DNS、连接、认证和邮件读取必须在释放共享
  Vault runtime 与 Email service 锁后执行。扫描期间 SSH 指纹读取及其他 Vault 操作不得
  因邮箱网络等待而阻塞；账户被编辑、删除或 Vault 被锁定时必须丢弃过期扫描结果。
- Electron 与 SwiftUI/WinUI source 已由 `CHG-2026-008` 移除；旧 Electron 加密 user-data
  只作为迁移和数据回退输入保留。

## 非目标

- 不改变 Vault format 1、Browser RPC 2、KDF 或扩展信任模型。
- 不把 Linux、mobile 或 web client 提升为当前范围。
- 不以 Node sidecar、静态 demo、mock command 或禁用入口宣称 Electron parity。
- 不因 source removal 把尚未完成的平台 Gate 标记为通过。

## 影响范围

| Surface | 影响 |
| --- | --- |
| Core | `vault-core` 继续唯一拥有加密、模型、session 和 rollback |
| Desktop runtime | 新增 Rust-owned runtime，拥有文件提交、授权、临时会话和 browser broker |
| Renderer | 复用现有 React/Vite UI；以 typed Tauri adapter 替换 preload transport |
| Platform | Keychain/Touch ID、DPAPI/Hello、clipboard、dialog、tray、autostart 使用窄 adapter |
| Browser | 保持 RPC v2、104-route policy 和独立 authorization；切换 native-host registration 需 AT |
| Electron | source/build/runtime owner 已移除；旧加密 user-data 继续保留 |
| Native UI | source/build owner 已移除；历史证据保留在 Rejected Change |
| Release | macOS/Windows 分别完成签名、安装、upgrade、rollback 和 native-host 验收 |

## 实现约束

- Tauri capability 只允许主窗口调用显式命令；Rust dispatcher 必须拒绝未知 operation、
  非法 payload、锁定状态和越权敏感值请求。
- Google Desktop OAuth build credential 由本地未跟踪 `.env` 或发布 CI Secret 在构建时注入，
  最终用户不得填写开发者 Client Secret，Finder/Dock 启动不得依赖临时进程环境变量。
  Desktop client 是 public client，Client Secret 不构成鉴权边界；OAuth 仍必须使用 system
  browser、PKCE、state 和随机 loopback callback，构建 credential 不得进入源码、日志、
  renderer 或普通 settings。
- KDF、Vault I/O、邮件、SSH 和 browser transport 不得阻塞 WebView/main thread。
- Email OTP 后台、手动及 browser watch/poll 的 Provider 扫描不得持有共享 Vault runtime
  或 Email service mutex；受保护凭据快照只在 Rust blocking worker 的有界 scan plan/result
  中存在并在 drop 时 zeroize，重叠扫描必须拒绝。
- Tauri SSH client 使用 `ssh2` 0.9.6（MIT OR Apache-2.0）及 vendored OpenSSL；连接、握手、
  channel 与认证必须有界超时。任何网络错误只返回稳定公共消息，不包含 secret 或远端输出。
- 普通 DTO 不得包含 protected value；copy/reveal/fill 必须是独立有界特权操作。
- Mutation 必须继续 commit-before-publish；失败恢复旧文件和旧 session。
- final lock、退出、sleep/session lock、撤销和过期必须清除相应 secret/temp state。
- Tauri 使用独立 app ID、user-data 和 browser-host registration；旧 Electron 数据只读迁移，
  不得作为并行写入目标。

## 任务

| Task | Requirement | 可验证输出 | Test | 状态 |
| --- | --- | --- | --- | --- |
| TDM-000 | REQ-TAURI-001 | Change、Spec、ADR、Scope、Traceability 完成并进入 Implementing | `pnpm docs:check` | Done |
| TDM-010 | REQ-SEC-001、NFR-PRIV-001 | Tauri 2 shell、CSP/capability、typed adapter、无 Node renderer | CT-TAURI-SHELL-001、CT-TAURI-COMMAND-001 | Done |
| TDM-020 | REQ-VAULT-001..003、NFR-REL-001 | Rust lifecycle、持久化、backup/restore/password rotation | CT-TAURI-VAULT-001 | In Progress |
| TDM-030 | REQ-ITEM-001..005、REQ-RECOVERY-001 | React UI 全部 CRUD/copy/reveal/trash/history parity | CT-TAURI-DESKTOP-001 | In Progress |
| TDM-040 | REQ-SEC-002、REQ-ITEM-003、REQ-IMPORT-001、REQ-EMAIL-001..002 | quick unlock、clipboard、import、SSH（含 scan/import、仅私钥候选补充公钥、编辑后补及 Rust-owned 公钥安装）、email 与临时状态清理 | CT-TAURI-DESKTOP-001、CT-ITEM-003、CT-SSH-SCAN-001 | In Progress |
| TDM-050 | REQ-BROWSER-001..002、REQ-AUTOFILL-001..002、REQ-PASSKEY-001 | Rust broker/native host 与 104-route parity | CT-TAURI-BROWSER-001、AT-BROWSER-001 | In Progress（111/111 route、macOS Unix transport、Windows current-user named pipe、Rust packaged host、固定 extension identity、Chrome/Edge NSIS+MSI registration/uninstall、listener 健康检测、安全中心非秘密诊断/重试及 package/extension 同源 ID 构建门禁自动化完成；真实 Windows Chrome/Edge package AT Pending） |
| TDM-060 | REQ-TAURI-002、NFR-COMPAT-001 | 默认脚本/构建/browser registration 切到 Tauri；Electron/Native source 退出产品依赖 | CT-TAURI-SHELL-001、CT-TAURI-SOURCE-001 | Done（source removal 证据见 `CHG-2026-008`） |
| TDM-070 | 全部关联 Requirement | macOS/Windows package、签名、upgrade/rollback 和 release evidence | AT-TAURI-MACOS-001、AT-TAURI-WINDOWS-001 | 用户确认已完成；可定位平台证据待回填 |

## 验收与证据

实现证据必须记录具体命令、版本、OS/architecture、测试数量和失败路径。只有 TDM-010 至
TDM-070 全部完成后才可以标记 Verified；只有 Release record 与 Git Tag 存在后才可以标记
Released。

> UAT 状态标注（2026-07-24）：用户确认 Tauri 桌面的 `AT-TAURI-MACOS-001` 与
> `AT-TAURI-WINDOWS-001` 完整平台 UAT 已完成。当前记录尚缺执行所用 OS/architecture、
> package/build 标识、逐项结果及失败路径等可定位证据，因此先记录为“用户确认已完成，证据待回填”；
> 在证据补齐前不把 Traceability 的 Platform AT 提升为 `Pass`，也不据此把本 Change 标记为
> `Verified`。

| Evidence ID | 日期 | 范围 | 证据 | 结果 |
| --- | --- | --- | --- | --- |
| EVID-TDM-001 | 2026-07-22 | TDM-000/010 与 TDM-020/030 首个真实切片；macOS 14.8.7 x86_64 | `pnpm docs:check` = 37 Markdown/8 YAML；Tauri typed adapter 2 tests；Rust core 24 tests、FFI/runtime 19 tests、Tauri command 2 tests；`cargo clippy --all-targets --no-deps -D warnings`；Electron 34 files/171 tests；Browser parity 2 files/6 tests；native-host 12 tests；Tauri production WebView build；macOS `.app`/`.dmg` build；ad-hoc strict `codesign`；LaunchServices 启动与视觉检查。Tauri `.app` 17 MiB、`.dmg` 7.3 MiB，对照当前 Electron unpacked 300 MiB | `CT-TAURI-SHELL-001`、`CT-TAURI-COMMAND-001` Pass；`CT-TAURI-VAULT-001` lifecycle/atomic mutation/backup-restore slice Pass；完整 desktop/browser/platform parity 仍 Not Run |
| EVID-TDM-002 | 2026-07-22 | TDM-040 import slice；macOS 14.8.7 x86_64 | `BUG-2026-004-tauri-import-dialog` EVID-TID-001：Rust import session/parser/batch 7 tests、Tauri adapter 2 tests、Clippy、typecheck、production `.app`/`.dmg` build 和 docs check 通过 | `CT-TAURI-DESKTOP-001` import slice Pass；真实 dialog 与其余 TDM-040 能力仍 Not Run |
| EVID-TDM-003 | 2026-07-22 | TDM-040 desktop PIN quick-unlock slice；macOS 14.8.7 x86_64 | Tauri Rust runtime 实现 PIN + OS credential-store device secret 的 scrypt/AES-256-GCM Vault Key wrapper，credential replacement、原子 0600 record、失败计数/锁定、主密码重置、不同 Vault/restore/password-change 失效和 zeroizing buffer；Rust runtime quick-key round trip 记录 `desktop-pin`；Tauri transport 将 Rust string rejection 转换为 renderer `Error`。Tauri Rust 10 tests、FFI/runtime 22 tests、typed adapter 3 tests、Rust Clippy `-D warnings`、Tauri typecheck/WebView production build、macOS `.app`/`.dmg` package build 通过 | `CT-TAURI-DESKTOP-001` PIN crypto/state/transport slice Pass；packaged Keychain UI round trip 与 `AT-TAURI-MACOS-001`、Windows Credential Manager/`AT-TAURI-WINDOWS-001` Not Run；TDM-040 保持 In Progress |
| EVID-TDM-004 | 2026-07-22 | TDM-060 Electron→Tauri data migration slice；macOS 14.8.7 x86_64 | Rust 首启迁移仅在非 Preview identifier 且 Tauri Vault 不存在时检测 Electron 默认 Vault；真实 format 1 round trip、no-overwrite、source retention、错误密码 Pending、正确主密码完成凭据、settings 边界、quick-unlock/browser pairing reset、超限与 symlink 拒绝测试通过。`cargo test -p vaultmesh-tauri-desktop` = 15 tests；Tauri adapter = 3 tests；Electron reference = 35 files/174 tests；extension = 22 files/141 tests；native-host = 12 tests；browser parity = 2 files/6 tests。全端 typecheck、Clippy `-D warnings`、`cargo fmt --check`、`pnpm docs:check`（39 Markdown/10 YAML）和 production WebView/package build 通过，生成 7.5 MiB x86_64 DMG。产物仍为 `com.vaultmesh.tauri.preview` 且未签名 | `CT-TAURI-SHELL-001` migration slice Pass；正式 identifier/default scripts/browser host 切换、签名/notarization 和 `AT-TAURI-MACOS-001` upgrade/rollback 仍未完成 |
| EVID-TDM-005 | 2026-07-22 | TDM-050 Tauri Rust browser lifecycle/transport/pairing/read slice；macOS 14.8.7 x86_64 | Rust broker 实现 native-host payload envelope 的 HMAC-SHA256 constant-time verification、384 KiB line/240 KiB RPC limit、UUID correlation、RPC v2、30 秒 clock skew、70 秒 lifetime、replay cache、gesture/unlock policy 和 unknown-operation rejection。除 lifecycle/pairing 五个 route 外，新增 `vault.workspace`、五类 renderer-safe list/detail、`password.health`、autofill candidate/fill history 与四类 trash/history read，达到 27/104；锁定读取 fail closed，Login detail 要求 fresh gesture 且回归测试确认不含 password。browser runtime 使用独立 `DesktopRuntime` authorization，master-password unlock 记录 extension source；固定 HMAC 向量与 Node `createHmac(...).digest('base64url')` 一致。macOS newline-delimited Unix listener 使用 0600 socket、0700 parent、拒绝非 socket stale target，并显式检查 103-byte endpoint 上限；真实 local socket envelope round trip 通过。Preview 专属 pairing 将 canonical Base64URL secret 存入 Keychain，磁盘只有 0600 enabled record；缺失 credential/损坏 record 不静默轮换。Tauri lifecycle 保持 listener 并在 Exit/TERM 清理 endpoint；development host plan 使用独立 `com.vaultmesh.tauri.preview.browser` manifest 和 Keychain locator，不写 secret。Tauri Rust 22 tests、FFI 20 tests、Tauri adapter 3 tests、native-host 13 tests、双 crate Clippy `-D warnings`、typecheck、docs check 和 production `.app`/`.dmg` build 通过；packaged `.app` 启动实测创建 Keychain item 与 0600 short socket，TERM 后 socket 清除 | `CT-TAURI-BROWSER-001` lifecycle/Unix transport/pairing/read core slice Pass；Windows pipe、其余 77 routes、正式 binary native-host install、真实 Chromium AT 尚未完成，不构成 parity |
| EVID-TDM-006 | 2026-07-22 | TDM-020/050 multi-session persistence coordinator slice；macOS 14.8.7 x86_64 | `vault-ffi` 为 opaque Vault handle 记录已发布加密文件 SHA-256 fingerprint，以进程内 path-keyed mutex 串行 commit；事务写前执行 compare-and-swap，stale low-level handle 返回 append-only `VAULTMESH_STATUS_CONFLICT=11` 并保留较新文件。Tauri desktop/browser `DesktopRuntime` 在操作前用当前 Vault Key 自动刷新；缺失文件或不同 Vault Key 使旧 session 失效。双 runtime 交替 add 后双方读取 2 items、低层 stale overwrite 拒绝且磁盘仅保留首个 commit、backing file 消失及不同 Vault Key replacement 后锁定的回归测试通过。C header/ABI contract 同步；`cargo test -p vaultmesh-ffi` = 26 tests，`cargo test -p vaultmesh-tauri-desktop --lib` = 22 tests，双 crate Clippy `-D warnings` 通过 | `CT-TAURI-VAULT-001` multi-session refresh/CAS slice Pass；browser mutation routes 仍未开放，跨进程 Electron/Tauri 同文件写入仍禁止 |
| EVID-TDM-007 | 2026-07-22 | TDM-050 剩余 77 个 Browser RPC route；macOS 14.8.7 x86_64 | Tauri broker allowlist 与共享 schema 达到严格 104/104；ownership test 要求每个 route 恰好由 broker、共享 Rust core 或窄 platform adapter 之一拥有。新增 single-use operation/gesture-bound confirmation、locked `vault.create` confirmation 修复、vault mutation event、pairing revoke tombstone/secret zeroize、独立 browser PIN、Touch ID LocalAuthentication + Keychain credential、clipboard expiry、backup/restore、settings、import、密码生成、SSH bounded scan/commit/cancel、P-256 WebAuthn create/get、Autofill candidate/execute/legacy approval。Autofill 校验 HTTP(S) top/target origin、page URL、tab/document/frame、field handle 唯一性、expiry/one-use，Card 无条件复核 current master password，assignment 不提交表单；Passkey round trip 验证私钥不进入 metadata/RPC 且 assertion counter 持久递增。`cargo test -p vaultmesh-tauri-desktop --lib` 28/28；`cargo test -p vaultmesh-ffi` 26/26；Electron 35 files/174 tests；Extension 22 files/141 tests；Browser parity 2 files/6 tests；native-host 13/13；Tauri adapter 3/3；全 workspace Clippy `-D warnings`、Electron/Extension/Tauri typecheck、`cargo fmt --check`、production WebView 与 Tauri release bundle 通过。bundle 为 18 MiB `.app`/7.8 MiB x64 `.dmg`，实际链接 LocalAuthentication/Security；包仍未签名 | `CT-TAURI-BROWSER-001` 104-route implementation/policy/secret-lifecycle slice Pass；正式 native-host registration、真实 Chromium `AT-BROWSER-001`、Windows pipe/AT 和签名仍 Not Run，TDM-050 保持 In Progress |

| EVID-TDM-008 | 2026-07-22 | TDM-050/060 本机 Tauri replacement；macOS 14.8.7 x86_64 | Tauri identifier 切为 `com.vaultmesh.desktop`，默认 `desktop:*`/`local:*` 切到 Tauri；新增随 App 打包的 x86_64 Rust Native Messaging Host，直接读取 owner-only 配置与 Keychain pairing、校验固定开发扩展 origin、执行 bounded frame/HMAC/Unix socket forwarding，不依赖 Electron/Node sidecar。`pnpm tauri:typecheck`、Tauri adapter 3/3、Tauri Rust 28/28、extension 141/141、browser parity 6/6、native-host 13/13、Host Clippy `-D warnings`、production build 通过。本机脚本 ad-hoc 签名并用 `ditto` 覆盖 `/Applications/VaultMesh.app`，严格 `codesign` Pass；ad-hoc 重签时仅轮换 device-bound browser pairing；重新生成包含 Rust Host 的 7.8 MiB `VaultMesh-Tauri-local.dmg`，`hdiutil verify`、挂载后 identifier/Host/strict code seal 检查均 Pass。Chrome/Edge manifest 均指向 App 内 Rust Host，真实 `vault.status` host→Tauri broker 往返 Pass。Electron 源/目标 Vault 均 692618 bytes 且 SHA-256 `b966c4cf43bc8bdb1e68c8cb6cb68d9a7a606bea817a4babe03dbc9a84b6fb42`；旧 Electron App bundle 与临时备份已删除，旧加密数据目录保留。用户随后以主密码成功解锁 Tauri Vault，`electron-migration-v1.json` 已提交为 `verifiedByMasterPassword: true`，pending receipt 已移除 | `CT-TAURI-SHELL-001`、`CT-TAURI-BROWSER-001` 本机 replacement slice Pass；真实 Chromium `AT-BROWSER-001`、Windows transport/AT 仍 Not Run，Change 保持 Implementing |

| EVID-TDM-009 | 2026-07-22 | TDM-030/060 macOS status bar parity；macOS 14.8.7 x86_64 | Tauri 启用 `tray-icon`/`image-png`，复用 Electron 18×18 template asset；App setup 创建 `vaultmesh-status-bar`，左键显示/恢复/聚焦主窗口，右键菜单保持“显示 VaultMesh/退出 VaultMesh”，关闭主窗口时 prevent-close、隐藏窗口与 Dock，macOS Reopen 恢复窗口。未知 menu ID 拒绝；新增 `CT-TAURI-DESKTOP-001` menu action regression。`cargo test -p vaultmesh-tauri-desktop --lib` 29/29、Clippy `-D warnings`、Tauri typecheck 与 adapter 3/3 Pass；`pnpm tauri:local:package` 重建、ad-hoc strict code seal、Vault SHA-256、Rust Host 往返和 DMG verify Pass。安装态 System Events 只读检查返回 2 个 menu bars，第二栏包含 `status menu`；`VaultMesh-Tauri-local.dmg` SHA-256 `8134f037cd91399d23bc83b260de61adac04ddd8cde8d97d424ed18b662732ed` | macOS status bar creation 与 Electron interaction contract Pass；Windows tray 与完整 desktop AT 仍随对应平台验收 |

| EVID-TDM-010 | 2026-07-23 | TDM-040 Email OTP 与本地 SSH scan Tauri migration；macOS 14.8.7 x86_64 | Desktop dispatcher 接通 `ssh.scan/commit/cancel`，复用 bounded `~/.ssh` 普通文件扫描、opaque session、duplicate detection、single-use commit 和 lock cleanup。新增 Rust-owned Email OTP service：Provider credential 进入 format 1 encrypted optional account record，普通 list 只返回 `hasCredential`；公网 IMAP 强制 TLS/read-only `EXAMINE`，Gmail API 与 Microsoft Graph 使用 system-browser loopback、state、PKCE S256、refresh token，OAuth 期间仅抑制 blur-lock 且不占用 Vault runtime lock；后台 bounded poll、runtime cursor/dedup、OTP expiry、short-lived renderer event、protected clipboard 和 final-lock cleanup 完成。`.env.example` 与 build-time Client ID/tenant 注入就绪。Rust core 26、FFI 29、Tauri 40 tests（共 95）通过；三 crate Clippy `-D warnings`、Tauri typecheck、14 files/55 renderer+adapter tests、`pnpm docs:check` 通过。`pnpm tauri:build` 生成 29 MiB `.app` 与 12 MiB x64 DMG，DMG SHA-256 `f97d9004a3d35593bdcbb599550bc532fbfaec04fa5a16ba1e70a52b05319150` | `CT-SSH-SCAN-001`、`CT-EMAIL-001`、`CT-EMAIL-002` automated Pass；真实 Gmail/Outlook/IMAP Provider、OAuth permission review、domain-match 与 packaged `AT-EMAIL-001/002` Not Run，因此 TDM-040 与 Change 保持 In Progress |
| EVID-TDM-011 | 2026-07-23 | TDM-040 packaged Gmail OAuth configuration；macOS 14.8.7 x86_64 | Tauri build script 将 Google Desktop OAuth Client Secret 加入受控 `.env`/CI build-time allowlist，并声明 `rerun-if-env-changed`；Rust packaged runtime 以 compile-time fallback 用于授权码交换和 refresh，runtime environment 只保留开发覆盖。用户连接表单、Vault account record、renderer summary 和普通 settings 均不接收开发者 credential。`cargo fmt --all -- --check`、Tauri Rust 41/41、renderer/adapter 16 files/57 tests、`pnpm tauri:typecheck`、`pnpm docs:check`（58 Markdown/28 YAML）通过 | `CT-EMAIL-001` packaged configuration slice Pass；真实 populated credential package 与 Provider AT 仍需本机重建执行，TDM-040 保持 In Progress |
| EVID-TDM-012 | 2026-07-24 | TDM-070 Tauri macOS/Windows 完整平台 UAT | 用户在当前项目任务中确认 `AT-TAURI-MACOS-001` 与 `AT-TAURI-WINDOWS-001` 已完成；尚未提供执行 OS/architecture、package/build 标识、逐项结果和失败路径 | 用户确认已完成；正式 `Pass` 证据待回填，Change 不因此进入 Verified |
| EVID-TDM-013 | 2026-07-24 | TDM-040 SSH 仅私钥候选补充公钥；macOS 14.8.7 x86_64 | SSH scan 弹窗仅对仅私钥候选提供可选公钥输入；typed adapter 以向后兼容 `publicKeyOverrides` 提交，Rust 在消费 bounded session 前校验候选归属、1 MiB 上限与单行 OpenSSH 公钥格式，无效输入不消费 session；留空仍导入仅私钥记录。Core 回归证明编辑后补公钥保留原私钥。`cargo test -p vaultmesh-core -p vaultmesh-tauri-desktop` = 81 tests；Tauri renderer/shared `pnpm --dir apps/tauri-desktop test` = 16 files/65 tests；Tauri typecheck、双 crate Clippy `-D warnings`、`cargo fmt --check`、`pnpm docs:check`（64 Markdown/34 YAML）通过 | `CT-SSH-SCAN-001` 与 `CT-TAURI-DESKTOP-001` 该切片 Pass；扫描所得私钥未进入 preview/renderer，真实 packaged UI AT 未执行，TDM-040 保持 In Progress |
| EVID-TDM-014 | 2026-07-24 | TDM-040 SSH 导入密钥可用性与编辑回归；macOS 14.8.7 x86_64 | 用户复测发现安装弹窗仍提示没有可用密钥且编辑页不显示公钥字段。根因为 TypeScript 契约要求 `recordKind`，但 Rust SSH summary/detail 未返回该字段，导致 renderer 收到 `undefined` 后同时被可用密钥筛选和密钥编辑分支排除。Core renderer-safe DTO 现从已有 `host + username` 派生 `account/key`，不写入 Vault、不迁移格式；scan commit runtime 回归断言导入 item 返回 `recordKind: key`，core 回归覆盖 account/key 派生及旧 Vault round trip；renderer 回归区分“可编辑的仅私钥记录”和“可安装的含公钥记录”，仅私钥时提示先编辑补充公钥。`cargo test -p vaultmesh-core -p vaultmesh-tauri-desktop` = 81 tests；renderer/shared = 16 files/66 tests；Tauri typecheck、双 crate Clippy `-D warnings`、`cargo fmt --check` 与 `pnpm docs:check` 通过；`pnpm tauri:build` 生成 production `.app` 与 12.2 MiB x64 DMG（SHA-256 `9bfbb267d19cd513b5b1aa502e281e070c977a4b8995a2403d90842cd67f52b0`） | `CT-SSH-SCAN-001`、`CT-TAURI-DESKTOP-001` 自动化与 production build Pass；该缺陷已修复，真实 packaged UI 交互 AT 未执行，TDM-040 保持 In Progress |
| EVID-TDM-015 | 2026-07-24 | TDM-040 / REQ-ITEM-003 SSH 公钥安装特权操作；macOS 14.8.7 x86_64 | 用户复测发现 `ssh.inspect-host-key` 与 `ssh.install-public-key` 仍落入“特权操作尚未迁移”占位拒绝。Tauri dispatcher 现接通 Rust-owned `ssh2` 0.9.6（MIT OR Apache-2.0、vendored OpenSSL）服务：预览仅握手读取 SHA-256 主机指纹，安装前重新连接并精确比对；认证支持账户保存密码、SSH Agent 或另一条 Vault 私钥；目标公钥只经 SSH channel stdin 送入固定远端命令，不进入本地 shell 参数；重复安装返回 `alreadyPresent`；可用时用上传密钥重新连接验证登录。受保护字段只在 Rust runtime 有界取用并 zeroize，网络 I/O 在 blocking worker，renderer 只接收稳定状态与错误。隔离本机 OpenSSH ignored CT 使用临时 host key、authorized_keys 和 ForceCommand，验证指纹变化 fail closed、首次安装、重复安装及新密钥登录，显式执行 Pass。`cargo test -p vaultmesh-core -p vaultmesh-tauri-desktop` = core 26 + Tauri 59 Pass、1 ignored（该项另行显式 Pass）；renderer/shared = 16 files/68 tests；Tauri typecheck、双 crate Clippy `-D warnings`、`cargo fmt --check`、`pnpm docs:check` 通过。`pnpm tauri:build` 生成 33 MiB production `.app` 与 14 MiB x64 DMG，DMG SHA-256 `ce0f415f53e808b07984703f6bac4ac7cb474745b3580e13e5a7803f2575cbab` | `CT-ITEM-003` 与 `CT-TAURI-DESKTOP-001` 该切片 Pass；真实远端服务器和 packaged UI 的 `AT-ITEM-003` 未执行，TDM-040 与 Change 保持 In Progress |
| EVID-TDM-016 | 2026-07-24 | TDM-040 / REQ-ITEM-003 公钥已存在后的直接密钥登录验证；macOS 14.8.7 x86_64 | 用户复测得到“公钥已存在，但尚未验证密钥登录”。根因为安装服务把“没有验证私钥”“上传私钥需要主密码但 renderer 未收集”和“已尝试但认证失败”统一压成 boolean `false`。现在首次安装和 `alreadyPresent` 都在待上传记录包含私钥时直接重新连接并验证；上传私钥自身启用 `masterPasswordReprompt` 时，界面无论首次连接采用密码、Agent 或另一私钥都会先收集 Vault 主密码。结果契约保留兼容 boolean 并新增 `verified`、`unavailable`、`failed`，UI 分别显示直接验证成功、缺少私钥或实际验证失败，不再把失败描述为未验证。隔离本机 OpenSSH 往返显式执行 Pass，覆盖首次安装和重复安装直接验证。Rust core 26 + Tauri 59 Pass、1 ignored（OpenSSH 项另行显式 Pass）；renderer/shared 16 files/69 tests、Tauri typecheck、双 crate Clippy `-D warnings`、`cargo fmt --check` 通过。`pnpm tauri:build` 与 `hdiutil verify` Pass，生成 14 MiB x64 DMG，SHA-256 `242a302162f8712b6e831212c91ec44410204d8444056b838eb5b4dc32202ebc` | `CT-ITEM-003` 与 `CT-TAURI-DESKTOP-001` 该回归 Pass；`root@10.0.0.2:22` 的真实远端结果仍需用户用新包复测，Change 保持 In Progress |
| EVID-TDM-017 | 2026-07-24 | TDM-040 / REQ-EMAIL-001..002 Email Provider 扫描锁竞争；macOS 14.8.7 x86_64 | 用户确认启用邮箱验证码后台检查时 SSH 主机指纹明显变慢，关闭后恢复；对 `10.0.0.2:22` 的只读基线探测为 TCP `0.00s`、OpenSSH host-key `0.07s`。根因为桌面后台在持有共享 `DesktopRuntime` 与 `EmailOtpService` mutex 时执行 Gmail/Graph/IMAP DNS、连接、认证和邮件读取，使 SSH 读取 Vault 目标记录排队。扫描现拆为：锁内生成包含 encrypted-account secret 快照的 bounded plan、锁外 blocking worker Provider I/O、锁内比较账户快照并提交 OAuth refresh credential/status/candidates。账户已编辑/删除、Vault 已锁定或 final lock 时丢弃并 zeroize 旧结果；单一 `scan_in_progress` 拒绝重叠。浏览器 watch/poll 使用其独立解锁 runtime 生成计划、后台联网并在后续 poll 提交，未退化为依赖桌面解锁。新增并发 CT 在网络执行闭包中同时 `try_lock` runtime/service 成功，stale-result CT 证明账户变更后旧邮件不进入候选。Rust core 26 + Tauri 61 Pass、1 ignored；renderer/shared 16 files/69 tests、Tauri typecheck、双 crate Clippy `-D warnings`、`cargo fmt --check` 通过。`pnpm tauri:build` 与 `hdiutil verify` Pass，生成 14 MiB x64 DMG，SHA-256 `39c1dace9c889a4e4aae5448f1bf43dc581968c991f838daa508fb463c750fbf` | `CT-EMAIL-001`、`CT-EMAIL-002` 与 `CT-TAURI-DESKTOP-001` concurrency/state-lifecycle 回归 Pass；真实 Gmail/Outlook/IMAP 与 packaged SSH 并行 AT 待用户用新包复测，TDM-040 保持 In Progress |
| EVID-TDM-018 | 2026-07-25 | TDM-040 / REQ-ITEM-003 SSH 外部客户端启动；macOS 14.8.7 x86_64 | 用户复测“打开终端”得到“该 Tauri 特权操作尚未迁移或不被允许”。根因为 typed adapter 已发送 `ssh.external-clients` / `ssh.launch`，Rust dispatcher 只接通 scan、host-key 与 public-key install，两个外部客户端操作落入总兜底拒绝。Tauri Rust runtime 现枚举固定系统终端/VS Code/复制命令，严格解析 input 与 account target，生成不含 secret/local path 的固定显示命令，并由 Rust 启动平台客户端或写入有时限剪贴板；renderer 仍无 shell/filesystem/generic invoke。失焦锁定开启时不释放 Vault 私钥或自动复制密码；允许保持解锁的既有合并型 key account 只使用 0700 session/0600 identity，终端脚本结束、final lock 及 Tauri 退出时清理。Rust Tauri 65 Pass、1 ignored；renderer/shared 16 files/70 Pass；Tauri typecheck、Clippy `-D warnings`、`cargo fmt --check` Pass。`pnpm tauri:build` 生成 31 MiB app binary 与 14 MiB x64 DMG，`hdiutil verify` Pass，DMG SHA-256 `e5653f93454585569c24e85785920ade9a983ac3d7d9a54da54bffb664ab3c95` | `CT-ITEM-003`、`CT-TAURI-COMMAND-001` 与 `CT-TAURI-DESKTOP-001` 自动化和 production build Pass；真实 packaged UI 打开系统终端/VS Code 的 `AT-ITEM-003` 待用户复测，TDM-040 与 Change 保持 In Progress |
| EVID-TDM-019 | 2026-07-25 | TDM-030/040/050 / REQ-SEC-001..002、REQ-ITEM-003、REQ-TAURI-002 未迁移操作审计与修复；macOS 14.8.7 x86_64 | 全量比较 typed Tauri adapter 与 Rust dispatcher 后补齐 `ssh.import-clipboard`、`ssh.generate-key-pair` 和桌面 `biometric.*`。剪贴板由 Rust 读取并复刻既有无 shell-eval SSH parser，覆盖引号、option/config、URL、IPv6、端口、长度与恶意字面量；密钥使用进程内 `ssh-key` 0.6.7（Apache-2.0 OR MIT）生成 ED25519/ECDSA/RSA 和 bcrypt-pbkdf 加密，口令不进入子进程，受管目录/私钥为 0700/0600、`create_new` 且私钥或 `.pub` 冲突均 fail closed；内置引擎不支持的 ML-DSA 不再显示，旧调用得到稳定拒绝。桌面 Touch ID 使用独立 Keychain service 包装 Vault Key，改密/恢复/切换 Vault 失效；不新增 serialized unlock enum，避免改变 Vault format 1。移除已被 Rust broker 原生确认取代且从未 emit 的 renderer Browser Fill dialog/3 个无接收端 operation；新增 source parity CT，112/112 typed operation 全有 Rust owner，未知操作统一拒绝而不再返回“尚未迁移”。macOS/Windows 共用 Tauri tray 菜单和关闭驻留路径，Windows 分支仍需目标机 AT。自动化：core 26 Pass；FFI 28 Pass；Tauri Rust 70 Pass/1 ignored（隔离 OpenSSH daemon）；renderer 17 files/73 Pass；extension 34 files/218 Pass；Tauri/extension typecheck、三 crate Clippy `-D warnings`、`cargo fmt --check`、`pnpm docs:check` Pass。`pnpm tauri:build` 生成 34 MiB app 与 14 MiB x64 DMG，`hdiutil verify` Pass，DMG SHA-256 `ddda40855d0d6e7e39f164f42ae8d6951d39125865e8e517926611af005aafd8`；app 未签名 | `CT-ITEM-003`、`CT-SEC-002`、`CT-TAURI-COMMAND-001`、`CT-TAURI-DESKTOP-001` 自动化切片 Pass；packaged Touch ID/SSH UI、签名、Windows tray/native-host pipe 与平台 AT 未执行，Change 保持 Implementing |
| EVID-TDM-020 | 2026-08-04 | TDM-050/070 / REQ-BROWSER-001..002、REQ-TAURI-002 Windows Browser package slice；macOS 14.8.7 x86_64 + isolated `x86_64-pc-windows-msvc` Rust check | Windows desktop 新增固定 `VaultMesh.BrowserBroker.v2` named pipe：SDDL 仅允许当前用户、拒绝远程客户端、首实例防抢占、16 连接上限、384 KiB request/1 MiB response 与 5 秒 partial-frame deadline；退出显式 wake/stop。Windows `vaultmesh-native-host.exe` 不再是空程序，严格校验 compile-time extension origin、AppData config、固定 pipe/keyring locator，从 Credential Manager 读取 canonical 32-byte pairing secret，执行 bounded native frame、HMAC envelope、70 秒 response deadline 和 correlation。桌面首次启动原子写 config/manifest 并注册 Chrome/Edge HKCU；NSIS hooks 与 WiX component 安装/卸载同一 manifest registry，保留 Vault/配对数据；Tauri `externalBin` 同时打包 Agent 与 Browser Host。标准 extension build 默认固定 public key，实测 manifest ID 为 `dmmjcaemejijgkpginfccokjmbknbgif`，自定义 key/ID mismatch fail closed；Windows `browser:dev` 使用 `.exe` Host、AppData profile 和 runtime registration；`tauri:windows:browser-at` / `browser-uninstall-at` 分别执行目标机 registry/manifest/Host/真实 `vault.status` 与卸载清理验收。验证：`pnpm scripts:test` 27/27；Tauri Rust lib 217 Pass/1 ignored；extension 39 files/229 Pass；Tauri/extension typecheck；macOS Rust Clippy `-D warnings`、`cargo fmt --check`；最小依赖隔离工程对新增 Windows Host、registration、pipe listener 与 Windows-only test 执行 `cargo check` 和 Clippy `-D warnings` Pass。完整仓库从 macOS 交叉检查在 vendored OpenSSL/ring 进入项目代码前因缺少 Windows SDK/Windows Perl 阻断。`pnpm tauri:build` Pass，最终 `.app` 同时包含 684 KiB Rust Host 与 651 KiB Agent shim，x64 DMG SHA-256 `a8d79d1e3ec14443a96b6ab710ce3876dbf8f22446cecbd261dee1ca1058456f` | `CT-TAURI-BROWSER-001` Windows transport/identity/package source 与条件编译切片 Pass；真实 Windows NSIS/MSI 安装、Chrome/Edge `vault.status`、revoke、upgrade/uninstall 和签名 `AT-BROWSER-001` / `AT-TAURI-WINDOWS-001` 仍需目标 Windows 执行，Change 保持 Implementing |
| EVID-TDM-021 | 2026-08-04 | TDM-050/070 / REQ-BROWSER-001..002、REQ-TAURI-002 Windows Browser code-completion slice；macOS 14.8.7 x86_64 + isolated `x86_64-pc-windows-msvc` Rust check | Windows Browser listener 新增显式健康状态，首实例后 worker 异常退出不再静默；桌面以可重试 integration owner 保存 pairing/broker/listener/Host registration 状态，启动失败返回稳定非秘密分类，安全中心显示 pipe、Host registration 与 compile-time extension ID 并允许重新检查和修复。新增 `desktop.browser-integration.get/retry`，typed adapter/Rust owner 达到 167/167；状态 schema 拒绝路径和任意系统错误。统一 `build-tauri.mjs` 把同一 key 派生 ID 传给 packaged Host 与 Tauri 主程序，修复仅设置自定义 key 时 Host/desktop 退回开发 ID 的隐性不一致；`tauri:release:build` / `extension:release:zip` 要求显式非开发 key，ID mismatch 或 release 使用开发 key 在构建前失败。验证：scripts 30/30；renderer/shared 29 files/127 tests；Tauri Rust lib 217 Pass/1 ignored；browser parity 6/6；Tauri typecheck、macOS Clippy `-D warnings`、`cargo fmt --check`、extension production build、CT-TAURI-SOURCE Pass。完整 Windows 交叉检查仍在 OpenSSL/ring 进入项目代码前被 Windows SDK/Windows Perl 阻断；最小 Windows 工程对 Host registration、named pipe、integration health owner 与 Host binary 执行 target `cargo check` 和 all-target Clippy `-D warnings` Pass。新统一 `pnpm tauri:build` production package Pass，`.app` 包含 684 KiB Host、651 KiB Agent，16 MiB x64 DMG SHA-256 `078a45fac752ebfb3729c7dbf47b8e0bb7dc958036e8085e3ae7ae568272de57` | `CT-TAURI-BROWSER-001` 代码闭环与可诊断/可恢复路径 Pass；真实 Windows Chrome/Edge `connectNative`、NSIS/MSI 安装、revoke、upgrade/uninstall 与签名仍由 `AT-BROWSER-001` / `AT-TAURI-WINDOWS-001` 在目标机执行，Change 保持 Implementing |
| EVID-TDM-022 | 2026-09-10 | TDM-040 / REQ-SEC-002 桌面 Touch ID 自动解锁提示；macOS | 已复现安装态主解锁页仅显示手动“使用 Touch ID”。根因为 `UnlockPage` 只有按钮 handler，没有状态就绪后的自动调用。新增页面生命周期 guard：Touch ID enabled、Vault locked 且状态就绪时自动尝试一次，调用前置位以兼容 React StrictMode；取消或失败后保留按钮及主密码/PIN fallback。RED 回归先得到 0 次调用，修复后 focused Pass；renderer 全量 31 files/143 tests、TypeScript typecheck、Vite production WebView build Pass | `CT-TAURI-DESKTOP-001` 自动化 Pass；当前 `/Applications/VaultMesh.app` 仍为旧安装包，重建安装后的真实系统 Touch ID 自动弹窗需 `AT-TAURI-MACOS-001` 复测，Change 保持 Implementing |

## 安全与数据生命周期

WebView 只持有 renderer-safe DTO 和有界 reveal 状态。主密码、Vault Key、provider token、
邮件正文、OTP、SSH 私钥、fill assignment 和 clipboard value 只进入对应 Rust/platform
owner，终止路径清零或销毁。Tauri log、panic、crash report、WebView storage 和 settings
不得包含上述值。

## 兼容与迁移

Vault format 与 Browser RPC 不变。Tauri 使用 `com.vaultmesh.desktop` app ID 与独立 user-data，
默认命令和本机 browser registration 已切换；quick-unlock 与 pairing credential 重新建立，
不复制设备绑定材料。Electron/Native source 已移除；旧 Electron 加密数据必须至少保留到用户
用主密码完成迁移 receipt，并继续受 Release rollback window 约束。
