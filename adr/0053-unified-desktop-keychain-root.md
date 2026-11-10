# ADR-0053：桌面单一钥匙串根密钥与统一凭据库

- 状态：Accepted
- 日期：2026-10-28
- 修订：2026-11-03（包内双二进制共享根条目，取消命中后的旧钥匙串回退）
- 修订：2026-11-06（精确化 ad-hoc ACL 身份、全量校验与一次性修复，杜绝重复授权弹窗；根钥匙串不可用时降级启动，未签名或签名不完整的发布包拒绝访问根条目）
- 修订：2026-11-10（v0.1.4 起的安装已完成旧凭据迁移，移除旧凭据钥匙串迁移，升级只剩根条目一次授权）
- 关联 Work：`CHG-2026-079-unified-desktop-keychain-root`、`CHG-2026-082-drop-legacy-credential-migration`
- 关闭 OPEN：无

## 背景

在当前桌面端（Tauri desktop）实现中，不同子系统分别向操作系统钥匙串（macOS Keychain / Windows Credential Manager）注册了各自独立的服务标识（如 `com.vaultmesh.desktop.desktop-biometric`、`com.vaultmesh.desktop.agent-pairing`、`com.vaultmesh.desktop.agent-authorization`、`com.vaultmesh.desktop.browser-pairing`、`com.vaultmesh.desktop.lan-pairing` 以及各类 PIN 凭据，多达 10 个独立 Service 条目）。

在 macOS 上，文件钥匙串以代码签名和可执行文件路径为每个客户端单独建立 ACL。主程序上的“始终允许”不会覆盖另一个二进制。`vaultmesh-native-host` 与主程序都会读取同一根条目；Host 再回退到旧的 `browser-pairing` 条目时，会在每次启动和浏览器自动填充时再次弹出密码框。开发专用 Host、未签名二进制和其他第三方程序不得加入该条目的信任列表。

## 决策

1. **唯一钥匙串根条目（Single App Keyring Root Entry）**：
   * 桌面端在操作系统凭据存储中仅保留唯一的服务名称与根账户：
     * 服务名：`com.vaultmesh.desktop`
     * 账户名：`root-secret-v1`
   * 该条目仅存储一个 256-bit（32 字节）的安全随机根密钥（Master Device Secret），并在内存中以 `Zeroizing` 包裹持有。
   * 带同一 Team ID 的签名包只在该条目建立时向用户索权一次。之后主程序冷启动和包内 Native Host 自动填充都不得再次索权。

2. **谁可以共享根条目**：
   * macOS 优先使用数据保护钥匙串和 Keychain Access Group `$(TeamIdentifierPrefix)com.vaultmesh.desktop`。主程序与包内 `Contents/MacOS/vaultmesh-native-host` 必须带同一 Team ID 的该 entitlement。读取签名信息必须使用 `kSecCSSigningInformation`；访问组来自 `kSecCodeInfoEntitlementsDict`，该字典不存在时再解析 `kSecCodeInfoEntitlements` 的 `CFData`。不得把这份 Data 当作字典。
   * 给已签名二进制补上访问组时，必须先导出现有 entitlements，合并访问组后再重签。不得用只含访问组的 plist 覆盖 Hardened Runtime、WebKit/JIT 或其他既有 entitlement。
   * 没有 Team ID 的 ad-hoc 签名包不能使用 Access Group。此时根条目仍可留在文件钥匙串，但创建和每一次更新都必须把信任应用写成且仅写成上述两个包内可执行文件，并把分区列表写成二者的 cdhash；两者 Team ID 相同时再追加同一个 `teamid:`。
   * macOS 文件钥匙串必须按 `SecTrustedApplicationCopyData` 的不透明身份比较信任应用，不能把返回值重新解释为可执行文件路径；主程序可被系统归一化为 `.app` 身份。校验必须汇总整个 Access 的全部 ACL，要求非空信任应用并集恰好是双二进制，且至少一个 PartitionID ACL 存在并且所有 PartitionID ACL 都精确匹配当前分区列表。`SecACLCopyAuthorizations` 按 macOS 头文件直接返回 `CFArrayRef`，不得声明错误的 out 参数 ABI。
   * 读取根条目前先执行上述校验。主程序与 Host 必须用 VaultMesh 应用支持目录内 owner-only 非秘密文件锁串行检查和读取；同一进程只缓存一次 ACL 尝试结果。只有用户主动启动的桌面主程序可以修复 ACL；Native Host 遇到非精确 ACL 或缺失根条目时必须 fail closed，不得请求系统修改或创建授权，避免浏览器 Native Messaging 自动重连放大成弹窗循环。每个 main/Host cdhash 组合最多迁移一次：迁移成功后在应用支持目录写入非秘密标记 `.keychain-acl-plan`（两个 cdhash 的摘要），标记匹配时主程序与 Host 都只读取，不得再检查或修改 ACL。系统在创建条目时总会额外加入一个默认 PartitionID ACL，因此“所有 ACL 结构恰好等于计划”不可达，不得作为是否修复的判据。`SecKeychainItemSetAccess` 会追加而非替换 ACL（每次新增 Encrypt、Decrypt、PartitionID 各一条）且总要求登录密码，禁止在生产路径使用。迁移只由主程序执行：读取旧秘密、删除该根条目、用仅信任双二进制与当前分区列表的 Access 重建；重建失败必须以默认访问恢复原秘密，不得丢失。修复不得遍历、修改或清理其他软件的条目。取消时取消或复验失败必须 fail closed，同一进程不得通过旧钥匙串读取继续或重复提示。
   * 根钥匙串读取、创建或修复失败（含用户取消）不得中止桌面启动：Tauri 在 AppKit 启动回调中把 `setup` 错误变成 panic 并 abort。桌面主程序必须改用拒绝一切读写的不可用设备凭据存储，并向用户显示不含秘密的原因；主密码解锁继续可用，PIN、生物识别与设备配对在下次成功打开根条目前保持停用。
   * 发布构建运行在 `.app` 内但无法生成完整共享计划（未签名或主程序与 Host 签名不一致）时，必须在访问钥匙串前失败，不得回退到普通 `keyring::Entry`，以免系统授权框的“始终允许”把该构建身份写入 ACL。
   * 未签名二进制、`vaultmesh-bitwarden-dev-host`、`vaultmesh-agent-mcp` 以及其他包外或第三方程序不得进入 Access Group 或 Trusted Applications。Native Messaging 注册路径必须指向 `.app` 内的 Host。

3. **本地统一加密凭据库（Device Credentials Store）**：
   * 所有子模块的附属凭据（包括桌面/Agent 生物识别凭据、Agent 配对记录、Agent 持久授权对称密钥、浏览器 Native Host 配对凭据、局域网设备配对证书与密钥、PIN 凭据）统一持久化于应用支持目录的专有文件中：`device-credentials.enc`。
   * 主程序与 Native Host 必须使用同一目录：macOS 为 `~/Library/Application Support/com.vaultmesh.desktop`，Windows 为 `%APPDATA%\com.vaultmesh.desktop`。
   * 文件必须使用由 `root-secret-v1` 通过 HKDF-SHA256 派生出的主加密密钥，采用 AES-256-GCM 进行认证加密。当前文件版本的 AAD 必须绑定应用标识 `com.vaultmesh.desktop`、当前 OS 用户（Unix 为 uid）和协议版本。空 AAD 的旧文件在成功解密后必须重封为带 AAD 的版本。
   * 文件权限必须为 `0600`，父目录必须为 `0700`，写入操作必须采用原子替换（写临时文件后原子重命名）。
   * 生产环境的 PIN 与生物识别必须经过 `DeviceCredentialStore`。Release 构建不得再直接调用 `keyring::Entry` 保存或读取这些凭据。

4. **不再访问旧凭据钥匙串**：
   * v0.1.4–v0.1.7 曾在主程序首次打开统一存储时把旧 Service 迁入 `device-credentials.enc` 并删除旧条目。每条旧条目由旧构建创建，新构建读取时 macOS 会逐条要求登录密码，任一条取消还会导致每次启动重弹，因此 2026-11-10 起移除该迁移。
   * 统一存储只读写加密文件，不得读取、枚举或删除旧 Service；即使目标凭据缺失，也不得调用旧 `keyring::Entry`。生产 Native Host 读取配对秘密时同样不得回退。文件中遗留的迁移标记条目保持无害。
   * 开发专用 Host 不得打开生产根条目。
   * 直接从 v0.1.1–v0.1.3 升级的安装必须重新设置 PIN/Touch ID 并重新配对浏览器、局域网设备与 Agent；其旧钥匙串条目留作孤儿，不再自动清理。

## 原因

- **根除弹窗地狱**：同一 Team ID 的签名包把主程序和包内 Native Host 收进同一个 Access Group，启动与自动填充不再因为第二个二进制重复索权。
- **对齐工业界标准实践**：与 1Password、Chrome、Signal 等现代成熟安全应用采用的“系统钥匙串单根密钥 + 本地加密凭据库”架构完全一致。
- **整洁的凭据生命周期**：避免在用户操作系统钥匙串中散落多个孤儿条目，卸载或重置时更易于统一清理。
- **安全边界不妥协**：核心保险库数据仍由主密码强派生密钥保护；本地凭据库受操作系统钥匙串与 AES-256-GCM 双重锁闭，内存中不同子模块仍通过 HKDF 派生不同子密钥，权限与隔离性不降反升。

## 后果

- 新增 `DeviceCredentialStore` 统一凭据抽象层，各子模块（Agent broker、Browser pairing、Biometric service、PIN service、LAN sync）的持久化钥匙串调用需重构接入该统一接口。
- 需要覆盖统一存储不读取、枚举或删除旧 Service，以及 Native Messaging 路径保持在 `.app` 内。Ad-hoc 包没有 Team ID，Access Group 不会生效；文件钥匙串路径必须在创建和更新时写入两个包内可执行文件。签名身份从 ad-hoc 改为 Developer ID 后，发布流程必须只给主程序和包内 Host 重签 Keychain entitlement，不得签给 Agent sidecar。

## 被拒方案

- **保留 10 个独立条目仅做界面静默提示**：无法绕过 macOS 操作系统 SecurityAgent 的原生物理弹窗机制。
- **长期保留逐条读取的旧凭据迁移**：每条旧条目各弹一次登录密码框，取消后每次启动重弹；v0.1.4–v0.1.7 已覆盖迁移窗口，2026-11-10 起改为移除迁移，仅 v0.1.1–v0.1.3 直接升级需要重新设置。
- **把开发 Host 或任意当前进程加入 Trusted Applications**：会让未签名或开发二进制读取设备根密钥。
- **统一存储未命中时继续读取旧钥匙串**：Host 每次自动填充都会再次触发独立 ACL 弹窗。
- **将所有子凭据明文写入本地 json 文件**：严重降低安全性，绕过了 OS Keychain 提供的硬件级/系统级访问保护。

## 验证

- 覆盖 `DeviceCredentialStore` 的初始化、单钥匙串读写、AES-256-GCM 加解密、并发原子写入测试。
- 证明统一存储的打开、读取缺失账户、写入和删除都不访问旧 Service。
- 覆盖包内路径约束：Native Messaging 只注册 `.app/Contents/MacOS/vaultmesh-native-host`。
- `AT-SEC-001` / `AT-BROWSER-001` 在带同一 Team ID 的签名 macOS 包上验证：一次授权后，冷启动和浏览器自动填充不再弹出钥匙串密码。
- `AT-SEC-002` 在隔离的 ad-hoc macOS 包上验证：污染 ACL 首次修复最多授权一次，之后主程序冷启动与重复浏览器自动填充不再出现根钥匙串读取或访问许可弹窗。
- 通过 `CT-SEC-002`、`CT-AGENT-AUTH-001`、`cargo test` 与 `pnpm tauri:test` 全量回归。
