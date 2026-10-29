# ADR-0052：Agent 短时本地 SSH-Agent 协议桥接与旧代理工具废弃

- 状态：Accepted
- 日期：2026-10-27
- 关联 Work：`CHG-2026-078-agent-ssh-agent-bridge`
- 关闭 OPEN：无

## 背景

在当前 Agent Capability Broker 中，SSH 交互依赖逐命令代理工具（如 `vaultmesh_ssh_exec`、`vaultmesh_ssh_upload`、`vaultmesh_ssh_pty_*` 等）。虽然该机制能够对结构化命令实施 R1~R4 风险分级与逐次确认，但存在以下显著限制：

1. **复合运维工具链阻断**：像 `rsync`、`scp`、`sftp`、`git clone/push`、`ansible` 以及依赖 SSH 隧道的远程 Docker 调试等标准开发工具，无法通过单一的结构化 JSON 命令接口透明执行。
2. **确认疲劳（Confirmation Fatigue）**：复合脚本或持续部署需要连续执行多次 SSH 握手，逐命令弹窗确认严重破坏开发流。
3. **外部引入风险评估**：考虑过通过本地启动 HashiCorp Vault 签发临时证书，但 HashiCorp Vault 作为独立 Go 进程依赖过重（150MB+）、本地解封复杂，且目标机器必须预先在 `sshd_config` 配置 `TrustedUserCAKeys`；若直接将私钥文件落盘暴露给 Agent，则直接违反 [ADR-0007](file:///Users/jsonlee/Projects/VaultMesh/adr/0007-agent-capability-broker.md)“Agent 只获得能力，不获得凭据”的底线。

因此，需要在坚守“私钥不暴露”的前提下，打通原生 OpenSSH 客户端工具链的免打扰会话能力。

## 决策

1. **新增短时本地 SSH-Agent 会话工具**：
   * 新增 R1 公共动作 `vaultmesh_ssh_agent_open`（`confirmation: none`）：Agent 提交目标 SSH `accountRef` 与可选的 `durationMinutes`（默认 15 分钟，上限 60 分钟）。
   * 新增 R0 公共动作 `vaultmesh_ssh_agent_close`：Agent 任务完成后提前主动释放指定 `sessionRef`。
2. **复用现有原生配对与解锁管线（免二次动作授权打扰）**：
   * 沿用现有的 `AgentBrokerCore` 状态机：未配对时触发 `AgentNativeUiSurface::Pairing`；Vault 锁定时自动触发 `AgentNativeUiSurface::Unlock` 独立置顶解锁窗口；
   * `vaultmesh_ssh_agent_open` 依赖保险库解锁即可生成会话，免除独立的二次动作授权审批弹窗打扰（无需触发 `AgentNativeUiSurface::Authorization`）。
3. **本地专属 Socket 与严格权限控制**：
   * 解锁通过后，Rust desktop runtime 在本地创建单会话独占的 Unix Domain Socket（macOS/Linux：`~/.vaultmesh/agent-sessions/<session-uuid>.sock`，目录权限 `0700`，文件权限 `0600`）或 Windows Named Pipe（Owner-only SID 访问控制列表）。
   * 响应返回 `socketPath`、`exportCommand`（`export SSH_AUTH_SOCK=...`）、`expiresAt`、`accountLabel` 与公钥指纹。
4. **只读签名代理与硬性 TTL**：
   * 本地 Socket 仅实现 OpenSSH Agent 协议子集：只响应 `SSH2_AGENTC_REQUEST_IDENTITIES`（列出该账号对应的公钥）与 `SSH2_AGENTC_SIGN_REQUEST`（内存计算数字签名）。
   * 私钥始终由 `vault-core` 的 `Zeroizing` 内存持有，签名在 Rust 内部完成，**私钥原文绝不以文件或 IPC 形式暴露给 Agent**。
   * 严守 TTL：超时后立即注销监听并物理删除 Socket 文件；Vault 重新锁定或客户端退出时强制清理所有存活 Socket。
5. **密码账号全自动动态签发与直连（密码/私钥统一）**：
   * 账号存有私钥时，直接解密载入短时 Agent 内存；
   * 账号仅存有密码时，VaultMesh 在内存中动态生成临时 ED25519 密钥对，并使用保存的密码后台登录服务器将公钥安全追加至 `~/.ssh/authorized_keys`，随后将私钥载入短时 Agent 内存，实现密码账号全自动免密直连。
   * 响应中附带 `targetHost`、`targetPort`、`targetUser` 与标准 `sshCommand`，引导 Agent 直连真实 IP/域名，绝不依赖亦不生成 Host Alias。
6. **旧版代理工具与主机配置工具废弃**：
   * `vaultmesh_ssh_host_setup` 标记为 `[已废弃]`，避免向宿主机 `~/.ssh/config` 写入持久别名或落盘私钥。Agent 严禁扫描宿主机配置，所有服务器数据均以 VaultMesh 自身为单一来源；
   * 旧版本代理 SSH 工具（`vaultmesh_ssh_exec`、`vaultmesh_ssh_upload`、`vaultmesh_ssh_download`、`vaultmesh_ssh_pty_open`、`vaultmesh_ssh_pty_read`、`vaultmesh_ssh_pty_write`、`vaultmesh_ssh_pty_resize`、`vaultmesh_ssh_pty_close`、`vaultmesh_ssh_tunnel_open`）在 MCP 描述中统一标注为 `[已废弃 / Deprecated: 推荐使用 vaultmesh_ssh_agent_open 获取本地 SSH-Agent 会话]`。
   * 运行时保持向后兼容，不破坏既有自动化脚本。
7. **配套提供 MCP 说明书 Skill**：
   * 编写工程级 Skill `skills/vaultmesh-mcp/SKILL.md`，提供完整的 MCP 客户端接入配置、首次配对解锁指引、全工具详细用法说明及常见错误排查手册。

## 原因

- **行业最佳实践对齐**：与 1Password 8、KeePassXC、Secretive 等现代密码管理器的 SSH-Agent 架构一致，天然支持操作系统所有基于 SSH 的工具链。
- **兼顾极简体验与强安全性**：一次确认享受 15 分钟免打扰原生体验；私钥不落地、不外泄，即便 Agent 环境存在 Prompt 泄漏风险，也无法窃取长期私钥原文。
- **纯 Rust 轻量实现**：利用现有的 `ssh-key` crate 和标准网络库即可完成，无需引入数百兆外部依赖或复杂的本地服务器解封状态机。

## 被拒方案

- **本地运行 HashiCorp Vault 守护进程**：Go 二进制跨平台打包体积过大、本地状态机与解封流程复杂、目标服务器必须提前修改 `sshd_config` 信任 CA，且受 BSL 商业许可证限制。
- **向 Agent 发放临时物理私钥文件**：直接违反 ADR-0007 秘密不泄露的底线，无法防止私钥随 Agent 上下文/日志上传至第三方模型，且恶意/失控 Agent 可在有效时间内向服务器写入永久后门。

## 验证

- `CT-AGENT-SSH-001` 与新增的 SSH-Agent 单元测试必须覆盖 Socket 创建、权限设置、身份查询、签名验证、TTL 到期拒绝与 Vault 锁定清理。
- `CT-AGENT-PROTOCOL-001` 必须验证公共工具注册表包含新工具且旧工具带有已废弃标注。
- Vitest 测试与 `pnpm docs:check` 必须全数通过。
