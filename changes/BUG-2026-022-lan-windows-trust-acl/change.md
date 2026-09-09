# Windows LAN 信任索引安全句柄缺少读取权限

## 问题或目标

Windows `8025eca` 配对通过认证后显示本机无法安全保存设备信任。相同 Windows 用户与 app-data 目录中，提取生产存储函数的独立诊断两次复现 SetSecurityInfo 返回 5（拒绝访问）；临时 keyring 写、读、删全部成功。预期索引原子写入并限定当前用户，实际索引权限设置失败。

## 预期行为

恢复 REQ-LAN-PEER-001 的 Windows 本地信任保存；索引创建和替换后仍保留 owner-only 保护 DACL。

## 非目标

无协议、配对交互、凭据格式、Vault、Browser 或 Agent 行为变化。

## 影响范围

Tauri Rust LAN 索引安全句柄与 Windows 回归。无生产依赖、公开 API、格式或架构边界变化。

## 实现约束

仅补充同一临时文件安全句柄的 READ_CONTROL 权限。保持保护 DACL、原子写入、失败回滚与独立授权；不得改成宽松文件权限或要求管理员运行。

## 任务

| Task | Requirement | 可验证输出 | Test | 状态 |
| --- | --- | --- | --- | --- |
| ACL-01 | REQ-LAN-PEER-001 | 修复前失败、修复后成功，创建/替换后 DACL 与回滚验证 | CT-LAN-PAIRING-001 | Complete |
| ACL-02 | REQ-LAN-PEER-001 | Windows 本机重建与双机配对复测 | AT-LAN-PAIRING-001 | Build Complete / 双机复测 Pending |

## 验收与证据

- 前置诊断见 CHG-2026-040；本地 `target/lan-storage-diagnostic/baseline.log` 与 `read-control.log` 保存同目录临时索引的失败/对照结果。仅补 READ_CONTROL 后两次存储成功；未读取真实凭据或 Vault。
- Windows MSVC Rust 1.95.0：直接以 `rustc --edition=2024 --test apps/tauri-desktop/src-tauri/src/lan_pairing.rs` 编译生产模块及其原有测试，链接本仓库缓存的依赖与 native libraries（本地完整调用脚本 `target/lan-storage-diagnostic/compile-lan-tests.ps1`），隔离此前无关 Agent test harness 的编译阻塞；不替换 LAN 源码或测试。修复前 `lan-tests.exe ct_lan_pairing_index_is_owner_only --nocapture`：0 passed / 1 failed，在首个索引 save 返回 Err；仅补 READ_CONTROL 后同一测试 1 passed。新断言通过 Windows 安全 API 验证创建/原子替换后的 DACL 被保护、只有一条非继承 allow ACE、SID 等于文件 owner、权限为 FILE_ALL_ACCESS，并验证替换后内容实际更新。
- `target/lan-storage-diagnostic/lan-tests.exe --nocapture`：24 passed / 0 failed，涵盖生产入口配对、正确/错误码、双方存储确认、索引与凭据回滚、远端存储失败回滚、停止和权限检查。本地日志 `regression-before.log`、`regression-after.log`、`lan-regression.log` 位于同目录。
- `pnpm docs:check` 被已有包管理器启动器缺失阻断；直接执行 `node scripts/docs-check.mjs` 被 Windows 路径分隔符导致的模板查找错误阻断。诊断调用仅在内存规范化 Node path.join/relative 后，路由/ID/YAML/引用检查均无错误，但归档字节校验仍报告该 CRLF checkout 的既有封存内容与摘要不一致；未改写任何封存文件或摘要。
- 使用 `git -c core.autocrlf=false archive` 导出 HEAD 的规范 LF 临时副本，仅覆盖本次未封存 Work/Traceability 变更，仍使用原 `docs-check.mjs` / `work-archive-lib.mjs`，在内存规范化 Node path.join/relative 后检查通过：108 Markdown、63 YAML、50 requirements、127 test IDs、18 ADRs、51 routed Changes、31 archived Changes。临时副本位于 `target/docs-check-lf`；没有跳过归档校验或修改工作区封存内容。
- Windows x64 原生 `cargo build -p vaultmesh-tauri-desktop --bin vaultmesh-tauri-desktop --features tauri/custom-protocol --locked` 通过（12m20s，原有 Windows warning 保留）；本次使用 VS 2022 Build Tools 的 VCINSTALLDIR 与 VSCMD_ARG_TGT_ARCH=x64，生成包含本地 frontend 的 debug EXE，构建时间为 2026-09-09 21:08:18 +08:00。旧本机进程已停止，新 `target/debug/vaultmesh-tauri-desktop.exe` 已启动，8 秒后仍存活且 Responding=true（PID 5172）。这不是签名安装包验收，也不替代双机配对结果。
- `rustfmt --edition 2024 --check apps/tauri-desktop/src-tauri/src/lan_pairing.rs` 与 `git diff --check` 通过。真实 Windows↔macOS 配对需要两端重新开启发现后复测，因此 Work 保持 Implementing，不进入 Verified 或封存。

## 安全与数据生命周期

不增加日志、秘密投影或持久状态。回归仅使用临时非秘密 fixture，验证文件权限实际内容。

## 兼容与迁移

无迁移。应用原有设置与信任索引兼容，失败时继续沿用旧状态与回滚。

## Bug 根因（仅 type=bug）

ReOpenFile 仅请求 WRITE_DAC，在当前 Windows 的 SetSecurityInfo 保护 DACL 路径中不足以读取安全描述符，返回错误 5。增加 READ_CONTROL 后原调用成功。此前 owner-only 测试仅验证写入/读取，且 Windows test harness 被无关 Unix-only Agent 测试编译错误阻断，未运行到平台代码。修复版本为本 Work 对应变更；不以独立存储诊断替代真实配对 AT。
