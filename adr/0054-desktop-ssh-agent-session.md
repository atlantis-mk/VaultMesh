# ADR-0054：桌面外部客户端统一短时 SSH-Agent 会话桥接与配置

- 状态：Proposed
- 日期：2026-10-28
- 关联 Work：`CHG-2026-080-desktop-ssh-agent-session`
- 关闭 OPEN：无

## 背景

在桌面端 SSH 凭据卡片中，用户可通过“系统终端”或“VS Code”等外部客户端直接连接目标服务器。然而原有实现存在明显的设计缺陷与安全隐患：
1. **私钥落盘隐患**：`launch_system_terminal` 会将解密后的私钥明文写入应用临时目录（`ssh-launch/<uuid>/identity`），虽然依赖脚本退出时执行清理，但若终端被强行终止或系统崩溃，私钥将持久残留在磁盘上。
2. **密码账号体验割裂**：纯密码账号仅能依赖剪贴板自动复制，要求用户手动在终端中粘贴，易受窗口失焦锁定策略与主密码复核策略干扰。
3. **VS Code 无法使用保险库私钥**：原有逻辑直接对 VS Code 禁用保险库私钥提取，导致仅存储在 VaultMesh 中的私钥无法在 VS Code Remote-SSH 中成功鉴权。

此前在 [ADR-0052](0052-agent-ephemeral-ssh-agent-bridge.md) 中，VaultMesh 已为 Agent MCP 实现了基于纯内存 OpenSSH Agent 协议的短时会话桥接（`SshAgentRegistry`）与密码账号自动 ED25519 密钥部署。桌面端外部客户端应当统一复用该底层服务，消除割裂与安全隐患。

## 决策

1. **统一复用底层短时 SSH-Agent 会话服务**：
   - 桌面外部客户端（系统终端、VS Code）启动时，统一调用底层的短时 SSH-Agent 会话签发能力。
   - 私钥常驻 `Zeroizing` 内存，仅通过本地 Unix Domain Socket（macOS: 0600 权限）或 Windows 管道响应标准签名挑战，**彻底废除物理私钥落盘（`write_identity`）机制**。
2. **纯密码账号全自动动态密钥签发与直连**：
   - 纯密码账号复用自动 Bootstrap 机制，后台使用密码通过 SSH 登录并将临时生成的 ED25519 公钥追加至远端 `authorized_keys`，实现全自动免密直连。
3. **客户端适配机制**：
   - **系统终端**：启动脚本通过注入 `export SSH_AUTH_SOCK="<socketPath>"` 驱动系统自带 OpenSSH 原生直连，关闭或退出时无需清理物理私钥文件。
   - **VS Code**：通过 OpenSSH 标准的 `IdentityAgent <socketPath>` 配置桥接，使后台常驻的 VS Code Remote-SSH 能够透明定位到该短时会话 Socket。
4. **会话时长安全可配置**：
   - 将短时 SSH 会话时长配置纳入桌面安全设置（`SecuritySettings`）中的 `sshSessionDurationMinutes`，默认 15 分钟，支持用户在 1 至 60 分钟范围内自定义。
   - 会话超时、用户主动关闭或保险库锁定时，强制立即销毁所有活跃会话及其通信 Socket。

## 原因

- **杜绝私钥落盘风险**：对齐现代安全标准，私钥生命周期仅限内存，物理介质无残留。
- **一致的用户体验**：密码与密钥账号在系统终端与 VS Code 均可享受全自动免密连接。
- **架构收拢**：消除 MCP 与桌面 UI 两套平行的 SSH 物料收集与执行逻辑，降低维护成本。

## 后果

- 彻底移除 `ssh_external` 中的私钥写入代码及残留目录清理风险。
- 安全设置增加 `sshSessionDurationMinutes` 字段，需同步桌面与浏览器扩展设置模型。
- 需要更新相关单元测试以验证短时会话签发、时长边界约束及 Vault 锁定销毁。

## 被拒方案

- **向 VS Code 传递明文密钥文件**：严重破坏内存安全边界与防泄露底线。
- **仅保留剪贴板密码复制**：体验差，且无法解决 VS Code 缺少有效私钥鉴权通道的问题。

## 验证

- `CT-ITEM-003`：验证外部客户端启动时成功创建短时 SSH-Agent 会话，且未向磁盘写入私钥文件。
- `CT-SEC-002`：验证安全设置中 `sshSessionDurationMinutes` 的默认值、范围约束与修改生效。
