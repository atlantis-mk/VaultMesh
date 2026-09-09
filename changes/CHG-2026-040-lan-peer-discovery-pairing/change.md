# 局域网 VaultMesh 客户端发现与可信配对

## 问题或目标

让 macOS 与 Windows VaultMesh 桌面客户端能够在同一局域网内由用户显式发现、核对安全短码并建立可撤销的设备信任关系。

## 预期行为

实现 `REQ-LAN-PEER-001`：发现默认关闭、一次最长十分钟，采用类似蓝牙数字比较的任一端发起、对端自动响应流程，双方比较六码后才保存信任；配对不解锁或读取 Vault。

## 非目标

不提供同步、分享、远程操作、账户、云端/中继、端口映射、第三方协议或 Browser/Agent 授权复用。

## 影响范围

Tauri Rust runtime、typed desktop contract、React 设置入口、平台凭据库与 LAN protocol 1；Vault format、core、Browser RPC、Agent IPC、native host 均无影响。

## 实现约束

LAN service 是 Rust runtime 的独立 owner。mDNS 只广告随机实例标识、版本、端口和 nonce；首次会话使用 TLS 1.3 并由双方比较 TLS exporter 派生的六码，已配对连接固定对方设备证书。双方同时发起时必须按临时实例 ID 保留唯一规范会话并静默淘汰竞争会话，不得显示两个短码或要求用户约定发起端。失败、超时、取消、撤销和系统锁定必须清除瞬态会话并 fail closed。

## 任务

| Task | Requirement | 可验证输出 | Test | 状态 |
| --- | --- | --- | --- | --- |
| LAN-01 | REQ-LAN-PEER-001 | 主规格、ADR、scope、traceability | CT-LAN-PAIRING-001 | Complete |
| LAN-02 | REQ-LAN-PEER-001 | Rust LAN service 与 typed operations | CT-LAN-PAIRING-001 | Complete |
| LAN-03 | REQ-LAN-PEER-001 | Nearby devices UI 与目标平台验收 | AT-LAN-PAIRING-001 | Implementation Complete; AT Pending |

## 验收与证据

自动化必须覆盖广告解析、版本拒绝、短码、持久化回滚、撤销和时限。macOS↔macOS、Windows↔Windows、macOS↔Windows 的 packaged 验收在实现后写入本 Work。

- `cargo test -p vaultmesh-tauri-desktop lan_pairing --lib`：21 passed；覆盖 exact/bounded v1 TXT、同链路双栈 listener、TLS 1.3/SAS、单端发起、双端同时发起的唯一会话/单短码仲裁、本机确认后的等待状态、双端确认后的持久化与 connected、nonce mismatch、超限证书、重复/超时/取消、pin drift、停止清理、首次信任前不自动探测、失败握手清理与可重试、凭据/索引及远端持久化失败回滚，并包含 session-lock locked/unlocked/unknown 回归。
- `pnpm tauri:test`：desktop Rust 246 passed / 1 environment-only ignored，native host 1 passed，Agent MCP 4 passed，stdio E2E 6 passed，renderer 142 passed。
- `pnpm tauri:typecheck`、`pnpm --filter @vaultmesh/tauri-desktop build:web` 与 `cargo clippy -p vaultmesh-tauri-desktop --lib -- -D warnings`：通过。
- macOS debug application bundle 已生成于 `target/debug/bundle/macos/VaultMesh.app`；最终包的 `Info.plist` 已确认包含 `_vaultmesh-pair._tcp` 与 `NSLocalNetworkUsageDescription`。该本地 debug bundle 未签名，不替代签名 packaged AT。
- Windows 专用 WTS session-lock 代码此前已使用 `x86_64-pc-windows-msvc` metadata 单独 typecheck 通过；当前 owner-only DACL 修复的仓库级 Windows cross-check 在 macOS 上被 OpenSSL/AWS-LC/zlib 的 Windows SDK 与原生编译器缺失阻断，仍必须在 Windows 目标机完成原生 build/CT/AT。
- 2026-09-09 Windows 原生验证：安装 Rust 1.95.0 MSVC toolchain、Visual Studio 2022 C++ Build Tools 与 Strawberry Perl 后，`pnpm install --frozen-lockfile`、`node --test scripts/build-tauri.test.mjs`（4/4）和 Windows x64 debug Tauri build 通过。构建保留应用的 `0.0.9-review` SemVer，并按 `CHG-2026-030` 仅映射 MSI ProductVersion 为 `0.0.9`；生成 `target/debug/vaultmesh-tauri-desktop.exe`、`target/debug/bundle/msi/VaultMesh_0.0.9-review_x64_en-US.msi` 与 `target/debug/bundle/nsis/VaultMesh_0.0.9-review_x64-setup.exe`。EXE 启动存活检查 8 秒通过后停止。`cargo test -p vaultmesh-tauri-desktop lan_pairing --lib` 在执行 LAN 测试前被 Windows test harness 中 Agent Unix-only transport 条件编译与缺失 `Duration`/`thread` 导入阻断；该失败不覆盖已完成的 packaged build，也不替代 `AT-LAN-PAIRING-001`。
- macOS 实机预验收发现未锁定会话可能不返回 `CGSSessionScreenIsLocked`；旧判断将缺省值误判为锁定，导致发现开启后在 250ms monitor tick 被立即停止。现已改为 locked/unlocked/unknown 三态决策，仅明确 locked 执行清理；修复后的 macOS debug bundle 已重建。
- macOS 实机预验收发现手动 `begin` 后的内部 `in_flight` 未投影到 UI，按钮会在短码产生前重新可用并允许重复 begin；同时首次信任建立前的无意义自动身份探测可能与手动会话竞争。现已增加 renderer-safe `connecting`/`failed` 状态、首次信任前禁止自动探测、10 秒 pre-prompt 握手上限和失败后的明确重试路径。
- macOS 实机预验收进一步确认双端均可发现且能显示短码，但原流程要求用户隐式约定只有一端点击“配对”；双端同时点击会让两条合法 TLS 会话竞争并以通用失败结束。现已改为类似蓝牙数字比较的流程：任一端可发起，对端自动进入同一短码确认；双端同时发起时按临时实例 ID 选择唯一 TLS client，竞争会话静默退出。确认后 UI 保持“等待另一台设备”状态，完整双端确认、原子持久化和 connected 路径已有回归测试。
- macOS↔Windows 实机预验收在两端短码一致并确认后仍回滚；macOS 本机未留下 peer proof 或 `lan-peer-trust.json`，将失败定位到双方持久化确认阶段。Windows 原实现用普通数据写句柄调用文件安全 API，该句柄未显式取得 `WRITE_DAC`，可能导致 owner-only DACL 应用失败。现已在同一 atomic temp file 上以最小 `WRITE_DAC` 权限重新打开安全句柄，并按 Windows 文件对象 API 应用保护 DACL后再提交；Windows 专属回归要求 owner-only 索引实际创建并可读取。renderer-safe 状态同时区分本机与对端安全存储失败，不再折叠成网络错误。该修复仍待新版 Windows 包实机确认。
- `pnpm docs:check`：通过。
- `AT-LAN-PAIRING-001` 尚待两台目标设备执行 macOS↔macOS、Windows↔Windows、macOS↔Windows 与 firewall/system-lock/sleep 路径；Work 因此保持 `Implementing`，不得进入 Verified 或封存。

## 安全与数据生命周期

设备私钥、已配对验证材料进入 OS credential store；本地索引仅含非秘密 peer 标识、固定指纹和用户本地标签。监听、广告、TLS 会话、nonce 与安全短码只存在于发现窗口；不写日志、Vault、clipboard、renderer persistence 或 crash data。

## 兼容与迁移

无 Vault/RPC/IPC/ABI 迁移。协议主版本不兼容时拒绝；删除或损坏 OS pairing material 时本机视为未配对。
