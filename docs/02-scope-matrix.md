# 当前范围矩阵

状态含义：`Required` 当前必须保持；`Partial` 已有实现但缺少平台/发布门禁；`Future` 只允许按已接受 CHG 开始；`Out` 当前禁止实现。

## 客户端与平台

| Surface | macOS | Windows | 当前状态 |
| --- | --- | --- | --- |
| Electron desktop | Out | Out | 源码已由 `CHG-2026-008` 移除；旧加密 user-data 暂时保留 |
| Tauri 2 desktop | Required | Required | 唯一产品 shell；平台发布验收仍由 `CHG-2026-004` 跟踪 |
| R2 test-channel 自动更新 | Required（aarch64/x86_64） | Required（x86_64） | `CHG-2026-029` 实现；完整发布固定使用标准 GitHub-hosted 原生架构 Runner，不依赖 self-hosted 标签；Tauri 更新签名强制，Apple/Windows 代码签名不属于测试通道完成条件，目标平台 AT 未完成前为 Partial |
| R2 Review 发布基线 | Required（aarch64/x86_64） | Required（x86_64） | `CHG-2026-030` 以 `0.0.1-review` 为 fresh-install 基线，当前统一版本为 `0.0.8-review`，并使用独立 `channels/review/latest.json`；完整发布固定使用标准 GitHub-hosted 原生架构 Runner，并在 R2 成功后创建不含 Git Tag 的 GitHub Draft Prerelease；允许先发布只含已验证目标平台的阶段性 manifest 进行小规模验收，并在同版本 immutable artifact 就绪后追加缺失平台，但阶段性 manifest 与 Draft 均不计为完整正式发布或平台 AT；既有 `0.1.x` test 安装不得自动降级，目标平台 AT 未完成前为 Partial |
| Tauri 登录时静默启动 | Required | Required | `CHG-2026-019` 实现；默认启用、保持锁定并可由用户关闭，目标平台 AT 未完成前保持发布 Gate |
| Tauri 窗口内容捕获保护 | Required（启用平台提示；现代 macOS 不承诺通用截屏阻断） | Required（Windows 10 2004+ 公共系统捕获排除） | `CHG-2026-018` 实现；目标平台 AT 未完成前保持发布 Gate |
| Chromium MV3 + Firefox MV2 extension + native host | Required | Required | 共享 WXT remote UI 与 Browser RPC；浏览器特定固定身份/Native Messaging manifest；Firefox 不包含 Chromium-only Passkey proxy；发布安装/签名验证待完成 |
| 本地标准 stdio MCP client + owner-only Agent IPC | Required | Required | `CHG-2026-020` 实施中；Codex/OpenCode 是兼容性验收客户端，不构成产品白名单；只允许动作级 capability，目标平台打包与独立安全评审完成前保持发布 Gate |
| 显式 LAN VaultMesh peer discovery/pairing | Required | Required | `CHG-2026-040`：默认关闭、十分钟 mDNS/TLS + 一次性配对码认证；不传输 Vault 或提供远程操作 |
| 远程 MCP、云端 Agent、常驻网络监听 broker | Out | Out | 不引入 VaultMesh 服务端、远程 bearer 管理面或端口映射 |
| SwiftUI/AppKit client | Out | N/A | 产品源码已移除；历史 contract 证据保留在 Rejected Change |
| WinUI 3 client | N/A | Out | reserved source root 已移除 |
| Android Compose client | N/A | N/A | Partial；`CHG-2026-047` 实施 create/unlock/status/lock、app-private storage 与 lifecycle lock；Autofill、Credential Manager、Passkey、LAN 后台同步、导入导出和 quick unlock 暂不属于首切片 |
| Linux/iOS/web client | Out | Out | 不在当前范围 |

## Vault 能力

| 能力 | 状态 |
| --- | --- |
| Create/unlock/lock、主密码轮换 | Required |
| Login、card、SSH、identity、developer secret CRUD | Required |
| 网站/服务聚合、离线自动整理、待确认纠错、merge/split/move 与原 item 导航 | Required |
| 网站/服务下手动配置结构化 API 环境、typed credential binding、固定 Header 与安全 Agent discovery | Required |
| 桌面 API request workbench：从 live API 环境执行受约束请求、Rust 内部凭据注入、有界 response 与取消/锁定清理 | Required |
| Login 关联的 2FA 恢复码粘贴/文件导入、可确认删除源文件、保存、强制主密码查看与复制 | Required |
| Trash/history、密码健康、生成器 | Required |
| 加密 backup/restore | Required |
| Vault 账号与 API 环境安全搜索/筛选、直接动作授权、一次/连接期/持久 capability lease、动作级 SSH/direct-Secret HTTP/managed-web/protected-auth broker | Required；ApiEnvironment HTTP 执行由 `CHG-2026-028` 后续接入 |
| PIN quick unlock | Required |
| macOS Touch ID quick unlock | Required |
| Windows Hello/DPAPI quick unlock | Partial，受 `OPEN-001` 阻塞 |
| 局域网已授权设备事件同步、锁定密文收发与解锁合并 | Required；CHG-2026-044 实施与平台验收中 |
| 账号、服务器/跨网络同步、分享、恢复后门 | Out |

## Browser 能力

| 能力 | 状态 |
| --- | --- |
| 固定 ID 配对、独立 unlock/lock、撤销 | Required |
| Popup 管理 Vault workflow | Required；实验性 Bitwarden 副本按下列桌面集中范围裁剪 |
| 实验性 Bitwarden 副本的 Vault 备份/恢复、批量文件导入、SSH 扫描导入入口 | Out；由桌面端完成，不计入插件迁移缺口；不移除既有桌面/原插件兼容 RPC |
| Popup Login 编辑的受控恢复码文件导入 | Required |
| Login/card/identity/secret/SSH 显式填充 | Required |
| 策略控制的 login/OTP page-load fill | Required |
| Popup/OTP 字段页内图标显示并显式选择全局未过期邮箱 OTP | Required |
| 插件 popup 内用户主动触发的 TOTP QR 识别与附加到 Login | Required |
| Save/Ignore capture | Required |
| Chromium 127+ ES256 Passkey proxy | Required |
| 自动表单提交、SMS OTP、conditional mediation、largeBlob/PRF | Out |
| Firefox MV2 extension（Passkey proxy 除外） | Required；由 `CHG-2026-036` 推进双浏览器 ZIP 与 Native Host 发布验收 |
| Safari extension | Out |
| 复用 Browser 配对/session 作为 Agent 授权 | Out |

## Email OTP

| 能力 | 状态 |
| --- | --- |
| Gmail API OAuth、Microsoft Graph OAuth | Required |
| QQ/163/126/Yeah/iCloud/Yahoo/Zoho/Fastmail IMAP presets | Required |
| Custom read-only IMAP | Required |
| 增量 cursor、点击后短时高频 boost、过期候选、通知复制 | Required |
| 插件 popup/OTP 字段页内图标的全局未过期候选与一次性 OTP 字段填充 | Required |
| 写邮件、标记已读、持久化正文/OTP | Out |

## React 用户反馈

| 能力 | 状态 |
| --- | --- |
| Tauri renderer 与 Chromium/Firefox extension popup 的瞬态反馈使用顶部居中 Sonner toast | Required |
| 需要用户确认的 AlertDialog 与字段级内联校验 | Required，不属于 toast 替换范围 |

## 发布状态

源码仓库保持 Public，并自重新许可提交起以 source-available 的 `PolyForm-Noncommercial-1.0.0` 提供，仅允许许可证定义的非商业用途；商业使用必须取得 `atlantis-mk <atlanxg@gmail.com>` 另行签署的书面授权。该许可不符合 OSI 开源定义，不得把当前版本描述为开源软件。重新许可前已按 `AGPL-3.0-or-later` 取得的历史版本继续适用原授权。`private: true` 只用于阻止 workspace 包被意外发布到包注册表，不改变源码许可。仓库内明确标注的第三方材料、依赖及项目无权商业再许可的贡献继续适用各自条款。

源码可见不等于产品已正式发布，也不表示安装包已通过安全或平台验收。正式产品公开发布仍受 `docs/07-test-release-plan.md` 中密码学审计、Windows 平台验证、签名/安装、依赖和升级完整性 Gate 约束，`OPEN-003` 不因源码可见而关闭。

Public 默认分支以当前 PolyForm 工作树作为新的根历史，普通远端分支不得保留此前的 AGPL 提交链。该 Git 引用策略不删除 GitHub PR 隐藏引用、缓存、外部 clone 或存档，也不撤销任何已经合法取得的权利。

Public GitHub 仓库使用重建后的独立 repository identity，只承载当前 PolyForm `main` 及其后续历史；旧仓库的 PR、Actions 和 Draft Release 不迁移。仓库级 secret scanning、push protection 与 private vulnerability reporting 必须保持启用。
