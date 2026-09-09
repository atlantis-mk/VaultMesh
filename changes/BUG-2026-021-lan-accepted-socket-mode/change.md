# LAN 入站连接继承非阻塞模式导致握手失败

## 问题或目标

Windows 连接 macOS 的新版输码配对在证书交换后显示 TLS 握手失败。调查生产非阻塞 listener 与原有 blocking listener 测试的差异；最小复现使用真实 accept_loop，并在证书交换后延迟发送 TLS 数据。

## 预期行为

符合 REQ-LAN-PEER-001：短暂网络间隔不得使正常握手失败，正确配对码后双方建立信任。

## 非目标

不改变发现协议、TLS 认证、PAKE、证书固定或存储格式。

## 影响范围

Tauri Rust LAN 入站网络 I/O 与回归测试。Vault/core、renderer、Agent/Browser 边界无变化。

## 实现约束

listener 保持非阻塞以响应停止；连接 worker 使用带超时的阻塞读写，停止仍通过 shutdown 中断。

## 任务

| Task | Requirement | 可验证输出 | Test | 状态 |
| --- | --- | --- | --- | --- |
| SOCKET-01 | REQ-LAN-PEER-001 | 生产 accept_loop 延迟 TLS 复现、修复和完整配对回归 | CT-LAN-PAIRING-001 | Complete |
| SOCKET-02 | REQ-LAN-PEER-001 | 重建本机 app 与 Windows↔macOS 复测 | AT-LAN-PAIRING-001 | Pending |

## 验收与证据

- macOS 修复前执行 `cargo test -p vaultmesh-tauri-desktop ct_lan_pairing_production_listener_tolerates_delayed_tls --lib`：0 passed / 1 failed；真实双栈非阻塞 listener 经 accept_loop 接受连接，交换证书后延迟 100ms 发送 ClientHello，0.18s 内失败。
- 仅增加 `socket.set_nonblocking(false)` 后，同一测试 1 passed；新测试另覆盖延迟证书，以及实际 accept_loop + outbound 的 PAKE、双端存储确认和 connected 完整流程。TLS 单独成功的测试同时要求无信任事件。
- `cargo test -p vaultmesh-tauri-desktop lan_pairing --lib`：25 passed；`cargo clippy -p vaultmesh-tauri-desktop --lib -- -D warnings`、`cargo fmt --all`、`pnpm docs:check` 和 `git diff --check` 通过。
- `pnpm --filter @vaultmesh/tauri-desktop tauri build --debug` 成功生成 macOS app 与 DMG；本机运行的 debug app 已退出并从新构建的 `target/debug/bundle/macos/VaultMesh.app` 重新启动。
- Windows↔macOS 实机复测结果待用户确认；协议没有变化，现有 Windows v1.1 可以先连接更新后的 Mac。Work 保持 Implementing，不以 loopback CT 代替 AT。
- 收尾时工作区出现并行的未跟踪 `CHG-2026-042-aivo-document-governance`，再次执行全库 `pnpm docs:check` 因其引用的 `work:new` / `docs:trace` 命令尚不存在而失败；未修改或提交该并行工作。本 Work 加入后、该并行文件出现前的文档检查已通过。

## 安全与数据生命周期

无新增日志或敏感数据投影。沿用原有读写超时与 session shutdown。

## 兼容与迁移

无格式或协议迁移；修复版本以本 Work 关联的 Git 提交为准。

## Bug 根因（仅 type=bug）

macOS 接受连接继承 listener 的 O_NONBLOCK，而 pair 使用同步 read_exact/rustls complete_io，并依赖 socket 超时等待网络数据。非阻塞读取在无数据时立即返回 WouldBlock：发生在 preface 时表现为证书交换失败，发生在 ClientHello/后续 TLS flight 时表现为 TLS 失败。原有握手测试使用阻塞 listener 并直接调用 pair，双栈测试只证明 accept 成功，因此全部漏掉生产入口的 socket 模式。受影响构建包括 0db33a2 及以前的 LAN 实现。修复在 pair 入口显式切回阻塞模式，再保留原有 10 秒读写超时与 session shutdown；不改变证书、TLS、PAKE 或协议修订。
