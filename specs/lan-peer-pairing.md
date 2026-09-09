# 局域网客户端发现与可信配对

## LAN-PAIR-001 范围与生命周期

仅 macOS/Windows VaultMesh Tauri 客户端支持 LAN protocol 2。附近设备 UI 的解锁展示条件与锁定跳转由 `REQ-LAN-PEER-001` 定义；用户必须在该页面显式开启发现。服务最多运行十分钟，desktop Vault 锁定导致页面卸载、离开页面、系统会话锁定、睡眠、退出、停止或超时必须关闭 mDNS、listener 和所有 pending/connected session。重新解锁并进入页面不得自动开启发现或恢复旧配对会话。设备信任与 Vault、Agent、Browser 授权相互独立，配对 transport 不传输 Vault 数据；新配对明确授权双方当前 Vault 的同步，由独立同步服务执行（见 `lan-vault-sync.md`），旧配对须双方补充确认。

## LAN-PAIR-002 发现与认证

使用 `_vaultmesh-pair._tcp.local.`。TXT 只允许 `v=2.0`、随机 `i` 和一次性 `n`；`1` 与 `1.1` 是已废弃、未包含同步授权的配对修订，当前客户端必须在发现阶段忽略它，避免不同帧流程互相发现后才于 TLS 内失败。未知、不完整、过长或非 `2.0` 记录同样忽略，SRV hostname 必须为本次发现随机生成而非系统 hostname。TCP listener 使用一个临时双栈端口，连接端点和入站来源必须匹配本机活动网卡的同链路网段。TLS 加密 Hello 才交换持久随机设备 ID 与是否由用户发起配对；该 ID 不进入 mDNS。

开启发现时必须使用 CSPRNG 生成本次窗口专用的六位十进制配对码；配对码只显示在生成它的本机 UI，不得进入 mDNS、日志或持久化。另一台设备选择该客户端、输入其当前配对码并提交后，双方必须在首次 TLS 连接内以 client/server 固定角色执行短时密码认证密钥交换（PAKE），并把双方设备 ID、证书、实例、nonce 与 TLS exporter 绑定到双向 key confirmation。只有输入码正确且两端 key confirmation 均通过时才自动进入持久化，不得再要求生成码的一端二次确认，也不得在网络帧中直接发送配对码。

错误配对码、PAKE 消息/确认错误、重放或达到本次发现窗口的失败尝试上限必须 fail closed；重新停止并开启发现必须生成新码并清零失败计数。若双方在请求建立前同时选择对方，协议必须按双方临时实例 ID 确定唯一的 TLS client，保留该规范会话并安全关闭另一条竞争会话；不得建立两条信任会话或把被淘汰会话报告成配对失败。PAKE 成功、双方交换持久化成功状态且本地凭据库/索引均写入成功前不得建立 peer。

已配对 peer 必须 mutual TLS 并按持久设备 ID 固定其证书指纹；任何证书变化、版本错误、帧过长、超时、重复提交、取消或撤销均拒绝对应会话。竞争会话只允许在双方均携带显式用户配对意图且规范会话仍继续时被淘汰，不得放宽证书、PAKE 或双向 key confirmation 要求。

## LAN-PAIR-003 持久化与 UI

设备私钥、持久设备 ID 和 peer proof 使用平台凭据库；owner-only 索引只保存 opaque peer ID、固定证书指纹、协议版本和用户本地标签。typed desktop API 只投影 opaque ref、连接/错误/已连接状态、可编辑标签、本机当前配对码，并只接受目标 opaque ref 与用户输入的六码；绝不投影 IP、port、证书、公钥、固定指纹、nonce、PAKE 消息或 LAN frame。UI 必须明确：一端展示当前配对码，另一端选择该设备并输入配对码；验证成功后两端自动完成。
