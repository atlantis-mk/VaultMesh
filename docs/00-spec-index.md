# VaultMesh 规格索引

## 当前基线

- 规格修订：`0.1.53-active`
- 产品版本：`0.0.10-review`
- Vault 格式：`4`（唯一写入格式；format 3 仅允许 desktop 主密码验证、备份后升级；不提供降级）
- Browser RPC：`2`
- Native ABI：`1`
- 状态：Tauri 2 desktop、Android Compose、Chromium MV3 与 Firefox MV2 扩展为当前实现；Android 首个 create/unlock/status/lock 切片实施中，Firefox 不包含 Chromium-only Passkey proxy；Electron/Native Preview 源码已移除；`0.0.1-review` 为独立 Review 安装基线，当前 Review 更新版本为 `0.0.10-review`，正式发布门禁未完成
- 最后更新：`2026-09-13`

## 路由顺序

1. 先读取 `../AGENTS.md`。
2. 已知 Work ID 时直接读取其 `change.yaml` 和 `change.md`，再按 `requirements`、`adrs`、`context_refs`、`related_changes` 精确定位；不需要先读取本索引。
3. 未知 Work ID 时使用本索引定位权威文档，并只搜索 `../changes/*/change.yaml` 元数据选择候选。
4. 主规格、专项 Spec、ADR 和 Traceability 按匹配标题、稳定 ID 或表格行读取；高风险与冲突场景按 `../AGENTS.md` 扩大范围。

## 文档地图

| 文件 | 唯一职责 | 状态 |
| --- | --- | --- |
| `01-product-definition.md` | 产品承诺、用户结果、非目标 | Active |
| `02-scope-matrix.md` | 当前 Required/Partial/Future/Out 边界 | Active |
| `03-functional-requirements.md` | 稳定 ID 的可验收行为 | Active |
| `04-architecture.md` | 所有权、依赖方向和运行时数据流 | Active |
| `05-data-model.md` | Vault envelope、payload 与兼容规则 | Active |
| `06-security-privacy.md` | 威胁范围、秘密生命周期和安全决策 | Active |
| `07-test-release-plan.md` | 测试层次、命令和发布 Gate | Active |
| `08-traceability.md` | 由 Requirements 和 Work routing 生成的索引 | Generated |
| `09-document-governance.md` | AI Direct/Work、ADR、版本维护规则 | Active |

## 专项规格

- `../specs/browser-integration.md`：RPC、配对、自动填充、捕获和 Passkey
- `../specs/agent-capability-broker.md`：本地 Agent MCP/IPC、Vault 账号引用、授权、动作 adapter 与秘密不披露边界
- `../specs/email-otp.md`：邮件 Provider、OAuth/IMAP 和候选生命周期
- `../specs/native-desktop-migration.md`：已停止的 SwiftUI/WinUI 迁移历史证据
- `../specs/tauri-desktop-migration.md`：Tauri 2 统一桌面运行时与发布 Gate
- `../specs/android-client.md`：Android Compose、Kotlin/JNI 边界、私有存储与锁定生命周期
- `../specs/lan-peer-pairing.md`：显式局域网客户端发现、双向短码验证与设备信任

- `../specs/lan-vault-sync.md`：已授权桌面设备的局域网自动双向同步

## 已接受 ADR

- `../adr/0001-rust-vault-core.md`
- `../adr/0002-electron-privilege-boundary.md`
- `../adr/0003-browser-extension-remote-ui.md`
- `../adr/0004-incremental-native-migration.md`
- `../adr/0005-tauri-desktop-runtime.md`
- `../adr/0006-remove-electron-native-sources.md`
- `../adr/0007-agent-capability-broker.md`
- `../adr/0008-direct-agent-action-authorization.md`
- `../adr/0009-unified-risk-aware-agent-permission.md`
- `../adr/0010-agent-client-shared-unlock.md`
- `../adr/0011-direct-secret-http-action.md`
- `../adr/0012-remove-agent-profile.md`
- `../adr/0013-agent-managed-openssh-host-alias.md`
- `../adr/0014-service-hub-format-3-navigation-metadata.md`
- `../adr/0015-api-environment-target-ownership.md`
- `../adr/0016-desktop-api-request-network-boundary.md`
- `../adr/0017-cross-browser-extension-native-messaging.md`
- `../adr/0018-lan-peer-discovery-trust-model.md`
- `../adr/0019-lan-vault-sync.md`

## Change 与 Release 入口

- `../changes/README.md`
- `../changes/_template/`
- `../changes/archive.json`
- `../releases/README.md`
- `../releases/_template.md`

新 schema-v2 Work 的状态和路由只由 `change.yaml` 手写拥有；`docs/08-traceability.md` 由 `pnpm docs:trace` 生成。legacy Work 保持其历史 YAML 与正文。定位任务时只搜索 YAML 元数据，确认候选后才读取正文。

## 权威代码定位

| 合约 | 实现定位 |
| --- | --- |
| Vault envelope/KDF | `../crates/vault-core/src/format.rs` |
| Encrypted payload | `../crates/vault-core/src/model.rs` |
| Mutation/session | `../crates/vault-core/src/session.rs` |
| Desktop typed API/schemas | `../apps/tauri-desktop/src/shared/api.ts`、`contracts.ts` |
| Browser operations/policy | `../apps/tauri-desktop/src/shared/browser-rpc.ts`、`browser-rpc-policy.ts` |
| Extension workflow parity | `../apps/tauri-desktop/src/shared/browser-extension-capabilities.ts` |
| Browser wire schema | `../apps/browser-extension/src/lib/protocol.ts` |
| Agent MCP/IPC 工具 registry | `../apps/tauri-desktop/src/shared/agent-capabilities.json` |
| Agent internal connector definition model | `../crates/vault-core/src/agent_connector.rs` |
| Agent privileged broker | `../apps/tauri-desktop/src-tauri/src/agent_broker.rs` |
| Agent secretless MCP shim | `../crates/agent-mcp/src/main.rs` |
| Tauri packaging/capabilities | `../apps/tauri-desktop/src-tauri/tauri.conf.json`、`capabilities/` |
| Tauri shared Rust runtime | `../crates/vault-ffi/src/runtime.rs`、`runtime_part*.inc.rs` |
| Tauri shell/runtime | `../apps/tauri-desktop/` |
| Android JNI runtime | `../crates/vault-android-runtime/` |
| Android Compose/platform shell | `../apps/android/` |

## 未决事项

| ID | 问题 | 阻塞范围 |
| --- | --- | --- |
| `OPEN-001` | Windows quick unlock 采用 DPAPI only 还是 DPAPI + Windows Hello | Windows 安全体验/发布 |
| `OPEN-003` | 独立密码学、内存生命周期和格式审计的执行方案 | 正式公开发布 |

AI 可以完成与未决事项无关的工作，但不得自行关闭这些范围或安全决策。

## 已关闭事项

| ID | 决策 | 日期 | 证据 |
| --- | --- | --- | --- |
| `OPEN-002` | 立即以 macOS 为第一平台，第一切片为 create/unlock/status/lock；Windows second | 2026-07-22 | `../changes/CHG-2026-002-native-desktop-migration/` |
