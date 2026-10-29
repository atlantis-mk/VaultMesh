# ADR-0053：桌面单一钥匙串根密钥与统一凭据库

- 状态：Accepted
- 日期：2026-10-28
- 关联 Work：`CHG-2026-079-unified-desktop-keychain-root`
- 关闭 OPEN：无

## 背景

在当前桌面端（Tauri desktop）实现中，不同子系统分别向操作系统钥匙串（macOS Keychain / Windows Credential Manager）注册了各自独立的服务标识（如 `com.vaultmesh.desktop.desktop-biometric`、`com.vaultmesh.desktop.agent-pairing`、`com.vaultmesh.desktop.agent-authorization`、`com.vaultmesh.desktop.browser-pairing`、`com.vaultmesh.desktop.lan-pairing` 以及各类 PIN 凭据，多达 10 个独立 Service 条目）。

在 macOS 上，钥匙串安全模型以 `(Service, Account)` 条目为单位绑定进程访问控制（ACL）。在开发重编、版本更新或未共享 Team ID Keychain Access Group 时，每个独立条目均会触发一次系统级的密码/授权弹窗（SecurityAgent Prompt），造成严重的授权弹窗疲劳。此外，同一应用在同一操作系统用户空间下的数据过度物理切割并不能增加实质隔离性，反而在系统钥匙串中留下了大量碎片残留。

## 决策

1. **唯一钥匙串根条目（Single App Keyring Root Entry）**：
   * 桌面端在操作系统凭据存储中仅保留唯一的服务名称与根账户：
     * 服务名：`com.vaultmesh.desktop`
     * 账户名：`root-secret-v1`
   * 该条目仅存储一个 256-bit（32 字节）的安全随机根密钥（Master Device Secret），并在内存中以 `Zeroizing` 包裹持有。
   * 操作系统仅需在此条目建立或首次读取时向用户索权一次。

2. **本地统一加密凭据库（Device Credentials Store）**：
   * 所有子模块的附属凭据（包括桌面/Agent 生物识别凭据、Agent 配对记录、Agent 持久授权对称密钥、浏览器 Native Host 配对凭据、局域网设备配对证书与密钥、PIN 凭据）统一持久化于应用支持目录的专有文件中：`device-credentials.enc`。
   * 文件必须使用由 `root-secret-v1` 通过 HKDF-SHA256 派生出的主加密密钥，采用 AES-256-GCM 进行认证加密；AAD 绑定应用标识、当前 OS 用户与协议版本。
   * 文件权限必须为 `0600`，父目录必须为 `0700`，写入操作必须采用原子替换（写临时文件后原子重命名）。

3. **双向无损兼容与静默回退迁移（Lazy One-Time Migration）**：
   * 当子模块请求特定凭据时，统一存储先从 `device-credentials.enc` 检索。
   * 若命中则直接返回；若未命中，则回退尝试读取对应的历史遗留独立钥匙串条目（如 `com.vaultmesh.desktop.agent-pairing`）。
   * 一旦从遗留条目读出数据，系统必须立即将其迁入 `device-credentials.enc` 原子落盘，并自动调用 `delete_credential` 删除该遗留钥匙串条目。
   * 既有已配对客户端、已配对局域网设备与 Touch ID 配置在升级后 100% 保持可用，无需用户重新配对或重新录入。

## 原因

- **根除弹窗地狱**：将启动与运行期间的多轮系统密码弹窗收拢为唯一的 1 次授权，大幅提升日常开发与实际运行体验。
- **对齐工业界标准实践**：与 1Password、Chrome、Signal 等现代成熟安全应用采用的“系统钥匙串单根密钥 + 本地加密凭据库”架构完全一致。
- **整洁的凭据生命周期**：避免在用户操作系统钥匙串中散落多个孤儿条目，卸载或重置时更易于统一清理。
- **安全边界不妥协**：核心保险库数据仍由主密码强派生密钥保护；本地凭据库受操作系统钥匙串与 AES-256-GCM 双重锁闭，内存中不同子模块仍通过 HKDF 派生不同子密钥，权限与隔离性不降反升。

## 后果

- 新增 `DeviceCredentialStore` 统一凭据抽象层，各子模块（Agent broker、Browser pairing、Biometric service、PIN service、LAN sync）的持久化钥匙串调用需重构接入该统一接口。
- 需要覆盖迁移回归测试，验证当存在旧版本分散条目时的无损平滑迁移和老条目自动清理。

## 被拒方案

- **保留 10 个独立条目仅做界面静默提示**：无法绕过 macOS 操作系统 SecurityAgent 的原生物理弹窗机制。
- **直接清空旧条目要求用户全部重新配对**：会破坏老用户的既有设备配对、Touch ID 与 Agent 集成体验，不可接受。
- **将所有子凭据明文写入本地 json 文件**：严重降低安全性，绕过了 OS Keychain 提供的硬件级/系统级访问保护。

## 验证

- 覆盖 `DeviceCredentialStore` 的初始化、单钥匙串读写、AES-256-GCM 加解密、并发原子写入测试。
- 覆盖从全部旧 Service 服务的懒迁移与清理测试。
- 通过 `CT-SEC-002`、`CT-AGENT-AUTH-001`、`cargo test` 与 `pnpm tauri:test` 全量回归。
