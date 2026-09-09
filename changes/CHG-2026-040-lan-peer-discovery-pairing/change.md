# 局域网 VaultMesh 客户端发现与可信配对

## 问题或目标

让 macOS 与 Windows VaultMesh 桌面客户端能够在同一局域网内由用户显式发现，通过一端展示、另一端输入的一次性配对码建立可撤销的设备信任关系。

## 预期行为

实现 `REQ-LAN-PEER-001`：发现默认关闭、一次最长十分钟；开启时生成本机六码，另一端选择设备并输入该码，TLS 内认证成功后双方自动保存信任，不再要求双端二次确认；配对不解锁或读取 Vault。

## 非目标

不提供同步、分享、远程操作、账户、云端/中继、端口映射、第三方协议或 Browser/Agent 授权复用。

## 影响范围

Tauri Rust runtime、typed desktop contract、React 设置入口、平台凭据库与 LAN protocol 1；Vault format、core、Browser RPC、Agent IPC、native host 均无影响。

## 实现约束

LAN service 是 Rust runtime 的独立 owner。mDNS 只广告随机实例标识、精确流程版本、端口和 nonce；本机六码不得进入 mDNS、日志或持久化，首次会话使用 TLS 1.3 内 SPAKE2 与双向 key confirmation 验证输入码，已配对连接固定对方设备证书。双方同时发起时必须按临时实例 ID 保留唯一规范会话并静默淘汰竞争会话。错误码、失败、超时、取消、撤销和系统锁定必须清除瞬态会话并 fail closed。

## 任务

| Task | Requirement | 可验证输出 | Test | 状态 |
| --- | --- | --- | --- | --- |
| LAN-01 | REQ-LAN-PEER-001 | 主规格、ADR、scope、traceability | CT-LAN-PAIRING-001 | Complete |
| LAN-02 | REQ-LAN-PEER-001 | Rust LAN service 与 typed operations | CT-LAN-PAIRING-001 | Complete |
| LAN-03 | REQ-LAN-PEER-001 | Nearby devices UI 与目标平台验收 | AT-LAN-PAIRING-001 | Implementation Complete（packaged AT Pending） |

## 验收与证据

自动化必须覆盖广告解析、版本拒绝、短码、持久化回滚、撤销和时限。macOS↔macOS、Windows↔Windows、macOS↔Windows 的 packaged 验收在实现后写入本 Work。

- `cargo test -p vaultmesh-tauri-desktop lan_pairing --lib`：22 passed；覆盖 exact/bounded v1.1 TXT、旧 v1 流程隔离与配对码不进入 mDNS、同链路双栈 listener、随机六码及原子五次尝试上限、TLS 1.3 内 SPAKE2/key confirmation、单端输入正确码后双方自动持久化与 connected、错误码不建立信任、双端同时输入时唯一会话仲裁、nonce mismatch、超限证书、pin drift、停止清理、首次信任前不自动探测、失败握手清理与可重试、凭据/索引及远端持久化失败回滚，并包含 session-lock locked/unlocked/unknown 回归。
- `pnpm tauri:test`：desktop Rust 247 passed / 1 environment-only ignored，native host 1 passed，Agent MCP 4 passed，stdio E2E 6 passed，renderer 142 passed。
- `pnpm tauri:typecheck`、`cargo fmt --all -- --check` 与 `cargo clippy -p vaultmesh-tauri-desktop --lib -- -D warnings`：通过。
- macOS debug application bundle 已生成于 `target/debug/bundle/macos/VaultMesh.app`；最终包的 `Info.plist` 已确认包含 `_vaultmesh-pair._tcp` 与 `NSLocalNetworkUsageDescription`。该本地 debug bundle 未签名，不替代签名 packaged AT。
- Windows 专用 WTS session-lock 代码此前已使用 `x86_64-pc-windows-msvc` metadata 单独 typecheck 通过；当前 owner-only DACL 修复的仓库级 Windows cross-check 在 macOS 上被 OpenSSL/AWS-LC/zlib 的 Windows SDK 与原生编译器缺失阻断，仍必须在 Windows 目标机完成原生 build/CT/AT。
- 2026-09-09 Windows 原生验证：安装 Rust 1.95.0 MSVC toolchain、Visual Studio 2022 C++ Build Tools 与 Strawberry Perl 后，`pnpm install --frozen-lockfile`、`node --test scripts/build-tauri.test.mjs`（4/4）和 Windows x64 debug Tauri build 通过。构建保留应用的 `0.0.9-review` SemVer，并按 `CHG-2026-030` 仅映射 MSI ProductVersion 为 `0.0.9`；生成 `target/debug/vaultmesh-tauri-desktop.exe`、`target/debug/bundle/msi/VaultMesh_0.0.9-review_x64_en-US.msi` 与 `target/debug/bundle/nsis/VaultMesh_0.0.9-review_x64-setup.exe`。EXE 启动存活检查 8 秒通过后停止。`cargo test -p vaultmesh-tauri-desktop lan_pairing --lib` 在执行 LAN 测试前被 Windows test harness 中 Agent Unix-only transport 条件编译与缺失 `Duration`/`thread` 导入阻断；该失败不覆盖已完成的 packaged build，也不替代 `AT-LAN-PAIRING-001`。
- macOS 实机预验收发现未锁定会话可能不返回 `CGSSessionScreenIsLocked`；旧判断将缺省值误判为锁定，导致发现开启后在 250ms monitor tick 被立即停止。现已改为 locked/unlocked/unknown 三态决策，仅明确 locked 执行清理；修复后的 macOS debug bundle 已重建。
- macOS 实机预验收发现手动 `begin` 后的内部 `in_flight` 未投影到 UI，按钮会在短码产生前重新可用并允许重复 begin；同时首次信任建立前的无意义自动身份探测可能与手动会话竞争。现已增加 renderer-safe `connecting`/`failed` 状态、首次信任前禁止自动探测、10 秒 pre-prompt 握手上限和失败后的明确重试路径。
- macOS 实机预验收进一步确认双端均可发现且能显示短码，但原流程要求用户隐式约定只有一端点击“配对”；双端同时点击会让两条合法 TLS 会话竞争并以通用失败结束。现已改为类似蓝牙数字比较的流程：任一端可发起，对端自动进入同一短码确认；双端同时发起时按临时实例 ID 选择唯一 TLS client，竞争会话静默退出。确认后 UI 保持“等待另一台设备”状态，完整双端确认、原子持久化和 connected 路径已有回归测试。
- macOS↔Windows 实机预验收在两端短码一致并确认后仍回滚；macOS 本机未留下 peer proof 或 `lan-peer-trust.json`，将失败定位到双方持久化确认阶段。Windows 原实现用普通数据写句柄调用文件安全 API，该句柄未显式取得 `WRITE_DAC`，可能导致 owner-only DACL 应用失败。现已在同一 atomic temp file 上以最小 `WRITE_DAC` 权限重新打开安全句柄，并按 Windows 文件对象 API 应用保护 DACL后再提交；Windows 专属回归要求 owner-only 索引实际创建并可读取。renderer-safe 状态同时区分本机与对端安全存储失败，不再折叠成网络错误。该修复仍待新版 Windows 包实机确认。
- 用户持续实机验证表明，双端比较并分别确认安全短码的交互复杂且容易进入“配对未完成”。当前实现已替换该流程：开启发现即生成本机一次性六码；另一端选择设备并输入该码；协议通过 SPAKE2 和绑定 TLS exporter/双方身份/证书/实例/nonce 的双向 key confirmation 验证，正确后两端自动原子保存信任，不再创建 renderer pending confirmation。旧的 `lan.pairing.confirm`/`lan.pairing.cancel` operation 已移除，错误码、尝试耗尽和安全存储失败均保留可区分的 fail-closed 状态。
- 输码版首次实机复测仍显示通用安全连接失败；检查发现 mDNS 仍把已废弃的双端数字比较构建和输码构建共同声明为 `v=1`，两端会互相发现但在 TLS 内解析不同帧。当前输码流程改为精确发现修订 `v=1.1`，旧 `v=1` 在扫描阶段直接忽略。再次复测确认两端均为 `v=1.1` 后仍在配对码认证前失败，因此 runtime 现在显式完成 TLS handshake，并把证书交换、TLS、Hello/TrustState、发现漂移、本机/对端证书固定冲突、尝试耗尽和持久化结果同步拆为 renderer-safe 失败阶段；不记录或投影 endpoint、证书、nonce、密钥或协议帧。
- `pnpm docs:check`：通过。
- 后续实机出现 TLS/证书交换两种失败，已由 `BUG-2026-021-lan-accepted-socket-mode` 在 macOS 生产 accept_loop 上复现并修复连接继承非阻塞模式的问题；先前版本不一致、时间或安全软件判断不构成该次故障的根因证据。该 Bug 记录修复前/后测试和双机复测状态。
- `AT-LAN-PAIRING-001` 尚待两台目标设备执行 macOS↔macOS、Windows↔Windows、macOS↔Windows 与 firewall/system-lock/sleep 路径；Work 因此保持 `Implementing`，不得进入 Verified 或封存。
- 2026-09-09 Windows 存储失败诊断（基线 `8025eca`）：从当前 `lan_pairing.rs` 提取 `write_private` / `set_windows_owner_only`，使用已构建的同仓库依赖，在应用实际 app-data 目录写入独立临时空索引，并以独立临时凭据执行 keyring 写/读/删。连续两次复现 `SetSecurityInfo` 返回 `5`（Access denied），凭据库三步均成功。仅将安全句柄访问掩码从 `WRITE_DAC` 改成 `WRITE_DAC | READ_CONTROL` 的对照诊断，两次索引写入/读取及凭据库三步均成功；未改变目标 owner-only DACL。由此定位当前 Windows 索引权限设置仍缺少安全描述符读取权限，先前仅补 `WRITE_DAC` 的修复不完整。本次仅获取诊断详情，产品代码/运行程序未替换；后续修复仍需 Windows 回归、DACL 内容验证和真实双机配对验收。本地可定位诊断程序与输出为 `target/lan-storage-diagnostic/probe.rs`、`probe-read-control.rs`、`baseline.log`、`read-control.log`（临时构建产物，不含真实凭据、配对码或 peer 数据）；测试索引/凭据已清理。

## 安全与数据生命周期

Windows `SetSecurityInfo` error 5 的后续修复、权限回归与重建证据由 `BUG-2026-022-lan-windows-trust-acl` 维护。

设备私钥、已配对验证材料进入 OS credential store；本地索引仅含非秘密 peer 标识、固定指纹和用户本地标签。监听、广告、TLS 会话、nonce 与本机配对码只存在于发现窗口；不写日志、Vault、clipboard、renderer persistence 或 crash data。

## 兼容与迁移

无 Vault/RPC/IPC/ABI 迁移。协议主版本不兼容时拒绝；删除或损坏 OS pairing material 时本机视为未配对。
