---
name: vaultmesh-mcp
description: VaultMesh 本地 Agent MCP 能力桥接与使用指南。涵盖 MCP 客户端配置、解锁工作流、推荐的本地短时 SSH-Agent 桥接（支持密码账号全自动临时密钥签发与直连）、已废弃工具迁移指引及安全规范。
---

# VaultMesh MCP 能力使用指南

VaultMesh 通过由本地 privileged runtime 驱动的 **Agent Capability Broker**，以标准 Model Context Protocol (MCP) 接口为 AI Agent（如 Claude Desktop、Claude Code、Cursor、Cline 等）提供安全、隔离的密码管理器能力集成。

---

## 一、 核心安全与架构原则

1. **本地优先与单一事实来源（Local-First & Single Source of Truth）**：
   * 所有数据、加解密与通信均在本地发生（Unix Domain Socket 或 Windows Named Pipe），不依赖任何中央服务器或云端后端。
   * **严禁扫描宿主机配置**：Agent 查询服务器、账号、私钥或密码，**唯一入口就是 `vaultmesh_accounts_list`**。系统绝不读取、不扫描宿主机 `~/.ssh/config`、`~/.ssh/known_hosts` 或 `~/.ssh/id_*`。
2. **只获得能力，不获得凭据（Capabilities, not Credentials）**：
   * MCP 接口永远不会向 Agent 暴露明文主密码、私钥、Token、OTP 或恢复代码。
   * Agent 获得的是**结构化动作能力**（例如短时内存 SSH-Agent 签名代理），而不是明文私钥。
3. **零本地配置侵入，直连真实 IP/域名（No Host Alias & Direct Endpoint）**：
   * **严禁使用或生成 Host Alias**：连接目标时，直接使用 `vaultmesh_accounts_list` 或 `vaultmesh_ssh_agent_open` 返回的真实 `host`（IP 或域名）、`port` 与 `username`，避免别名解析歧义，且**绝不向本地宿主机 `~/.ssh/config` 写入任何持久别名配置**。
4. **分层防护与独立 UI**：
   * **配对（Pairing）**：初次连接需通过独立置顶窗口确认客户端身份；
   * **解锁（Unlock）**：保险库锁定时，自动唤起独立解锁窗口，主密码绝不经由 MCP 传输；
   * **免二次授权弹窗**：`vaultmesh_ssh_agent_open` 仅受保险库解锁保护，解锁后静默返回，不弹出二次权限确认弹窗。

---

## 二、 MCP 客户端接入配置

VaultMesh 分发轻量级标准 I/O 适配器二进制 `vaultmesh-agent-mcp`。所有客户端均通过 stdio 进程模式启动该二进制，并必须指定稳定自定义的 `--client <client-key>`。

### 1. Claude Desktop 配置
在 Claude Desktop 配置文件中添加：
* **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "vaultmesh": {
      "command": "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-agent-mcp",
      "args": ["--client", "claude-desktop"]
    }
  }
}
```
> **提示**：若本地为开发构建，command 可指向项目编译产物：`<repo_path>/target/debug/vaultmesh-agent-mcp`。

### 2. Claude Code CLI 配置
在终端中执行：
```bash
claude mcp add vaultmesh /Applications/VaultMesh.app/Contents/MacOS/vaultmesh-agent-mcp --client claude-code
```

### 3. Cursor 配置
在项目的 `.cursor/mcp.json` 中配置：
```json
{
  "mcpServers": {
    "vaultmesh": {
      "command": "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-agent-mcp",
      "args": ["--client", "cursor-ide"]
    }
  }
}
```

### 4. VS Code (Cline / Roo Code) 配置
在插件设置中的 `cline_mcp_settings.json` 加入：
```json
{
  "mcpServers": {
    "vaultmesh": {
      "command": "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-agent-mcp",
      "args": ["--client", "cline-agent"]
    }
  }
}
```

---

## 三、 首次连接与鉴权生命周期

### 1. 首次配对（Pairing Required）
* **表现**：工具返回 `pairing-required`。
* **流程**：屏幕弹出 VaultMesh 原生置顶配对窗口，用户点击【允许配对】后，Agent 无需重连，直接重试当前工具调用即可。

### 2. 保险库锁定（Vault Locked）
* **表现**：工具返回 `vault-locked` 或 `unlock-agent`。
* **流程**：屏幕自动弹出独立解锁窗口，用户通过 Touch ID / 主密码解锁后，Agent 重试该动作即可继续。

---

## 四、 全量工具说明与使用指南

### 1. 账号检索与元数据工具

#### `vaultmesh_accounts_list`
* **说明**：检索 VaultMesh 中允许 Agent 访问的非秘密账号元数据。支持按类型、关键词或能力过滤。
* **参数**：
  * `query` (可选 string)：按标签或主机名模糊搜索。
  * `kinds` (可选 string-array)：条目类型，如 `["ssh", "secret"]`。
  * `capabilities` (可选 string-array)：能力过滤，如 `["ssh-agent"]`。
* **返回**：包含 `entries[].accountRef`、`label`、`kind`、`actions`。

#### `vaultmesh_items_list_metadata` / `vaultmesh_item_get_metadata`
* **说明**：只读获取保险库条目的非受保护基础属性（如名称、文件夹、修改时间），绝不返回密码或私钥。

---

### 2. SSH 远程运维（唯一推荐：短时 SSH-Agent 桥接）

#### ⭐ `vaultmesh_ssh_agent_open`（推荐首选）
* **能力**：在本地为目标 SSH 账号开启短时专属的 OpenSSH Agent 协议桥接会话（基于 Unix Socket 或 Windows Named Pipe）。
* **全自动凭据适配（密码 / 私钥通用）**：
  * **情况 A（账号存有私钥）**：直接将 VaultMesh 中加密存储的私钥解密并载入短时 Agent 内存。
  * **情况 B（账号仅存有密码）**：VaultMesh 会**全自动**在内存中动态生成临时 ED25519 密钥对，并使用保存的密码后台登录服务器将公钥安全追加到 `~/.ssh/authorized_keys`，随后将私钥载入短时 Agent 内存。**完全不需要 Agent 手动处理密钥生成或密码输入！**
* **最大优势**：
  * **100% 支持所有原生工具链（`rsync`、`scp`、`sftp`、`ssh`、`git`、`ansible` 等）**；
  * **私钥零落盘**：私钥仅存在于短时 Agent 进程内存中，有效时间到期（默认 15 分钟）或会话关闭时自动销毁，本地磁盘零残留；
  * **零配置侵入**：完全不修改用户的 `~/.ssh/config`，不生成任何 Host Alias。
* **参数**：
  * `accountRef` (必填 string)：通过 `vaultmesh_accounts_list` 获取的 SSH 账号 ID。
  * `durationMinutes` (可选 integer)：申请有效时长，默认 15，上限 60。
* **返回示例**：
  ```json
  {
    "sessionRef": "sess_01JAZ8F2...",
    "socketPath": "/Users/name/Library/Application Support/com.vaultmesh.desktop/agent/ssh-agent-xxxx.sock",
    "exportCommand": "export SSH_AUTH_SOCK=\"/Users/name/Library/Application Support/com.vaultmesh.desktop/agent/ssh-agent-xxxx.sock\"",
    "targetHost": "47.109.23.109",
    "targetPort": 30885,
    "targetUser": "wtai",
    "sshCommand": "ssh -p 30885 wtai@47.109.23.109",
    "rsyncCommand": "rsync -avz -e \"ssh -p 30885\" <src> wtai@47.109.23.109:<dest>",
    "scpCommand": "scp -P 30885 <src> wtai@47.109.23.109:<dest>",
    "expiresAt": "2026-10-28T17:15:00Z",
    "accountLabel": "innerfire2",
    "fingerprint": "SHA256:4t7XmK..."
  }
  ```
* **Agent 规范使用方式（严禁使用别名）**：
  ```bash
  # 1. 注入短时 Agent 环境变量
  export SSH_AUTH_SOCK="/Users/name/Library/Application Support/com.vaultmesh.desktop/agent/ssh-agent-xxxx.sock"

  # 2. 直接使用真实 IP/域名与端口执行命令（不要使用 alias）：
  ssh -p 30885 wtai@47.109.23.109 "uname -a"
  rsync -avz -e "ssh -p 30885" ./dist/ wtai@47.109.23.109:/var/www/
  scp -P 30885 ./config.json wtai@47.109.23.109:~/
  ```

#### `vaultmesh_ssh_agent_close`
* **能力**：当 Agent 提前完成任务时，主动注销指定的 SSH-Agent 会话并销毁 Socket。
* **参数**：
  * `sessionRef` (必填 string)：要关闭的会话 ID。

---

### 3. 已废弃 SSH 工具（Legacy）

> [!WARNING]
> 以下工具为早期逐命令代理或侵入式本地配置版本，现已**全部明确标记为已废弃**。请勿在新的自动化流程中使用它们，推荐统一迁移到 `vaultmesh_ssh_agent_open`。

| 已废弃工具名 | 状态 | 废弃原因与推荐替代方案 |
| :--- | :--- | :--- |
| `vaultmesh_ssh_host_setup` | **[已废弃]** | **避免向宿主机写入配置**。严禁 Agent 调用此工具修改 `~/.ssh/config` 或创建主机别名。直接使用 `vaultmesh_ssh_agent_open`，并直连真实 IP/域名。 |
| `vaultmesh_ssh_exec` | **[已废弃]** | 早期逐命令代理。现使用 `vaultmesh_ssh_agent_open`，通过原生 `ssh` 执行。 |
| `vaultmesh_ssh_upload` | **[已废弃]** | 早期文件代理。现使用 `vaultmesh_ssh_agent_open`，通过原生 `scp` 或 `rsync` 上传。 |
| `vaultmesh_ssh_download` | **[已废弃]** | 早期文件代理。现使用 `vaultmesh_ssh_agent_open`，通过原生 `scp` 或 `rsync` 下载。 |
| `vaultmesh_ssh_public_key_install` | **[已废弃]** | 现已在 `vaultmesh_ssh_agent_open` 中针对密码账号全自动处理，无需独立安装。 |
| `vaultmesh_ssh_pty_open` / `read` / `write` / `resize` / `close` | **[已废弃]** | 早期 PTY 代理。现使用 `vaultmesh_ssh_agent_open` 获得原生终端交互。 |
| `vaultmesh_ssh_tunnel_open` | **[已废弃]** | 早期隧道代理。现使用 `vaultmesh_ssh_agent_open`，通过原生 `ssh -L` / `ssh -R` 转发端口。 |

---

### 4. HTTP 与 Web 工具

#### `vaultmesh_http_request`
* **说明**：对绑定了 API Token 或鉴权凭据的后端服务发起有界 HTTP 请求。由 Rust 宿主在内部注入授权标头，Token 原文绝不回显给 Agent。
* **参数**：`accountRef`、`method`（GET/POST/PUT 等）、`path`、可选的 `query` 与 `body`。

#### `vaultmesh_web_*` 系列
* **说明**：在隔离的托管无头浏览器中访问受认证的 Web 应用。支持导航（`navigate`）、受保护数据提取（`extract`）及提交（`act`）。

---

### 5. 受保护认证填充

#### `vaultmesh_otp_fill`
* **说明**：获取绑定的 TOTP、短信或邮件短时验证码并填入，支持单次有界消费。

#### `vaultmesh_recovery_code_consume`
* **说明**：在灾难恢复流程中消费单次备用恢复代码（R3 级强授权）。

#### `vaultmesh_passkey_*`
* **说明**：通过系统认证器完成 Passkey / WebAuthn 身份断言请求。

---

## 五、 最佳实践工作流范例

### 场景一：密码账号或密钥账号无缝运维工作流（统一标准范式）

无论目标机器在 VaultMesh 中保存的是**私钥**还是**密码**，Agent 的操作范式完全一致：

```markdown
1. 检索账号：
   调用 `vaultmesh_accounts_list({ query: "innerfire" })`
   -> 获取目标 accountRef: "bbf91855-...", label: "innerfire2 (47.109.23.109:30885)"

2. 开启短时 SSH-Agent 桥接：
   调用 `vaultmesh_ssh_agent_open({ accountRef: "bbf91855-...", durationMinutes: 15 })`
   -> 若是密码账号，VaultMesh 自动完成临时密钥注入；
   -> 成功返回：
      socketPath: "/Users/.../agent/ssh-agent-xxxx.sock"
      targetHost: "47.109.23.109"
      targetPort: 30885
      targetUser: "wtai"

3. 在 Agent 本地环境注入并执行命令（直连真实 IP/端口，不使用别名）：
   $ export SSH_AUTH_SOCK="/Users/.../agent/ssh-agent-xxxx.sock"
   $ ssh -p 30885 wtai@47.109.23.109 "docker ps"
   $ rsync -avz -e "ssh -p 30885" ./build/ wtai@47.109.23.109:/opt/app/
   $ scp -P 30885 ./app.env wtai@47.109.23.109:/opt/app/.env

4. 清理会话（可选，超时亦会自动安全销毁）：
   调用 `vaultmesh_ssh_agent_close({ sessionRef: "sess_xxx" })`
```

---

## 六、 常见问题与排查

1. **`rsync` 或 `ssh` 提示 `Permission denied (publickey)`**：
   * 确认当前进程环境中已导出 `SSH_AUTH_SOCK`；
   * 确认执行命令时使用的是 `vaultmesh_ssh_agent_open` 返回的对应端口与用户。
2. **为什么严禁使用 Host Alias？**
   * 避免不同项目或环境间的 Alias 重名冲突；
   * 避免对宿主机 `~/.ssh/config` 产生持久文件写入；
   * 使用 IP/域名直连是最可靠、无歧义的连接方式。
3. **调用报错 `broker-unavailable`**：
   * 确认 VaultMesh 桌面客户端已经启动运行。
