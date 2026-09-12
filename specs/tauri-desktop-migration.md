# Tauri 2 desktop migration spec

执行计划与证据：
`../changes/CHG-2026-004-tauri-desktop-migration/change.md`（Implementing）。

## 目标拓扑

```text
React/Vite renderer
  ↓ typed adapter（known operations only）
Tauri capability + explicit commands
  ↓
Rust desktop runtime
  ├─ vault-core（crypto/model/session/rollback）
  ├─ atomic persistence and authorization
  ├─ browser RPC v2 broker/native-host transport
  └─ platform adapters（clipboard/dialog/quick unlock/SSH/email）
```

Tauri 是 macOS/Windows 的唯一产品 shell。Electron 与 Native Preview 源码已由
`CHG-2026-008` 移除；React renderer、typed contracts、Browser RPC policy 和产品资源由 Tauri
路径直接拥有。源码移除不代表 Windows、真实 Chromium、签名、upgrade/rollback AT 已完成。

Tauri browser broker 的共享 schema/policy 与 Rust dispatcher 必须保持 111/111 route parity，并对
未知 route、非法 payload、锁定、过期、重放和越权操作 fail closed。macOS listener 必须使用
owner-only 短 Unix socket path，拒绝非 socket stale target；Windows 必须使用独立 named pipe
adapter。pairing secret 必须保存在 OS credential service，磁盘只保存 owner-only enabled/tombstone
state；credential 缺失或 record 损坏必须 fail closed，不得静默轮换。App Exit 必须停止 listener
并清除 socket pathname。

## Renderer 与 command 边界

- Tauri 直接拥有 React/Vite renderer 和 `VaultMeshApi` 类型；transport 由唯一 typed adapter
  注入，页面和 store 不得直接 import Tauri API。
- WebView 不启用 Node，不获得 filesystem、shell、clipboard、dialog、process 或 generic invoke。
- capability 只绑定明确 window label、local bundled origin 和所需 command；禁止 wildcard remote
  origin、任意 URL navigation 和未经 allowlist 的新窗口。
- adapter 只能映射编译期已知 operation；Rust dispatcher 再次执行 exhaustive allowlist、payload
  schema/size、session authorization 和 response minimization。
- blocking KDF/I/O/SSH/email/browser work 必须离开 WebView/main thread；重复提交、取消和退出必须
  有确定结果。

## Runtime 所有权

- `vault-core` 继续唯一拥有 crypto、format、model、session 和 mutation rollback。
- Rust desktop runtime 拥有 Vault path、原子文件 commit、desktop/browser 独立授权、临时
  recovery-code file/import/SSH/email/fill/Passkey state 和 final-lock cleanup。
- 同一 Tauri 进程内的 desktop/browser Vault handle 必须按规范化 path 串行 mutation，并在每次
  commit 前比较上次已发布加密文件的 SHA-256 fingerprint；检测到新版本时先用当前 Vault Key
  自动刷新，无法刷新时清除旧 session，低层 stale handle 必须返回 append-only ABI conflict 状态，
  不得覆盖较新的原子提交。
- 普通 list/detail 只返回 renderer-safe DTO；protected value 只通过 field-scoped command 返回到
  clipboard owner 或有界 reveal response。
- Tauri command 不暴露 Rust layout、Vault Key、envelope、filesystem path、provider token、邮件
  正文或 browser pairing secret。
- Tauri shell 必须让每个自有产品窗口从创建起请求平台内容捕获保护，且不向 renderer 授予关闭
  保护的 window capability；Windows 公共捕获排除必须通过 packaged AT，macOS 只承诺启用平台
  best-effort hint。
- 平台 adapter 可以使用窄 Swift/Objective-C/Win32 调用，但不得复制 core 业务或持久化 secret 到
  非 OS-protected storage。
- macOS 桌面 Touch ID 已启用时，锁定解锁页必须在状态就绪后自动发起一次系统认证；取消或失败后
  保留手动 Touch ID 和主密码/PIN fallback，并以页面生命周期 guard 防止重渲染重复提示。
- Rust desktop runtime 独占 macOS/Windows 登录项注册与查询；登录项只能传入固定
  `--autostart` 参数。首次默认注册使用 app-data 内的非秘密初始化标记区分用户后续显式关闭，
  renderer 不获得 autostart 插件 capability，也不能提供可执行文件路径或启动参数。
- 主产品窗口从配置起保持隐藏；runtime 仅在确认不是 `--autostart` 启动后显示并聚焦窗口。
  登录项启动必须保留锁定状态和托盘入口，注册查询或写入失败不得阻止应用启动。

## Tauri-only source Gate

`CHG-2026-008` 已按用户明确决策提前执行 source removal。仓库必须持续满足：

1. Tauri renderer/contracts/tests/assets 不引用已删除的 Electron/Native 路径。
2. workspace、lockfile、默认脚本和 CI 不包含 Electron、Forge、N-API bridge 或 Native Preview build owner。
3. Browser RPC v2 schema/policy/dispatcher 保持 111/111 parity。
4. 旧 Electron Vault/user-data、迁移 receipt 与 credential 不因源码清理被删除。
5. macOS/Windows、真实 Chromium、签名安装、upgrade/uninstall/rollback AT 未通过时，Change 和
   Release 仍不得标记 Verified/Released。

## 兼容与共存

Vault 只写入和读取 format 3。Tauri 主密码、quick unlock、Browser、Agent 与 restore 复用同一个严格 reader；
其他所有版本在 KDF 前拒绝，不提供旧格式迁移、降级或专用备份入口。
Browser RPC 2 和 extension wire contract 保持不变。Tauri 使用正式 app identifier、独立 user-data、browser-host
identifier、socket/pipe 和 updater channel。Test 与 Review updater channel 均由 Rust runtime 独占，固定 HTTPS
endpoint 与 public key 编入对应 release build，renderer 不获得 updater plugin capability；两个 channel 的 manifest
必须隔离，版本化 artifact 先发布，静态 channel manifest 最后原子切换，且各自不允许 downgrade。完整发布流水线
使用标准 GitHub-hosted Runner 分别在原生 macOS ARM64、macOS Intel 和 Windows x64 环境构建，不依赖自定义
Runner 标签。`0.0.1-review`
是独立 Review fresh-install 基线；小规模验收可以在 immutable artifact 就绪后先发布只含已验证目标平台的
阶段性 Review manifest，使基线检查返回无更新，并在相同 current version 下只追加 artifact 后续就绪且尚不存在的
目标平台；追加必须保持 version、notes、pub_date 与全部既有 platform entry 不变。该清单不构成完整三平台 Review 发布。
现有 `0.1.x` test 安装只能手动重装，不能自动降级。旧 Electron 应用不再可从当前源码构建；只有 format-3 加密 user-data
可以作为迁移与数据回退输入，其他版本由当前构建拒绝。

正式 identifier 切换后的首次启动必须执行以下 Electron 数据迁移规则：

- Preview identifier 不得读取或复制 Electron user-data；正式 identifier 仅在 Tauri 目标 Vault
  不存在时检测 Electron 的默认 Vault。
- 迁移只接受不超过格式读取上限的非空普通文件，拒绝符号链接、超限输入和已有目标；复制使用
  owner-only 临时文件与 no-clobber 原子发布，绝不移动或覆盖 Electron 源 Vault。
- 兼容且通过边界校验的非秘密安全设置可以规范化复制；PIN、Touch ID/Windows credential、邮箱
  credential、browser pairing、host registration 和 WebView state 不得按文件复制。
- Vault 副本在主密码成功解锁前保持 Pending；只有 Rust runtime 成功解密后才可以写入完成凭据。
  错误密码、损坏凭据或提交失败必须保持旧 Electron 数据和可回滚状态。
- 应用包可以在完成凭据、项目核对和加密备份成功后移除 Electron；旧 user-data 只能在平台
  upgrade/rollback AT 完成并越过 Release 定义的回滚窗口后删除。
