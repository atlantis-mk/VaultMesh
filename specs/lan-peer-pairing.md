# 局域网客户端发现与可信配对

## LAN-PAIR-001 范围与生命周期

仅 macOS/Windows VaultMesh Tauri 客户端支持 LAN protocol 1。用户必须从不依赖 Vault 解锁的附近设备 UI 显式开启发现；窗口失焦仍可以按既有策略锁定 Vault，但附近设备页保持可用。服务最多运行十分钟，离开页面、系统会话锁定、睡眠、退出、停止或超时必须关闭 mDNS、listener 和所有 pending/connected session。配对与 Vault、Agent、Browser 授权相互独立，不传输或操作 Vault 数据。

## LAN-PAIR-002 发现与认证

使用 `_vaultmesh-pair._tcp.local.`。TXT 只允许 `v=1`、随机 `i` 和一次性 `n`；未知、不完整、过长或非 v1 记录忽略，SRV hostname 必须为本次发现随机生成而非系统 hostname。TCP listener 使用一个临时双栈端口，连接端点和入站来源必须匹配本机活动网卡的同链路网段。TLS 加密 Hello 才交换持久随机设备 ID 与是否由用户发起配对；该 ID 不进入 mDNS。

首次配对采用类似蓝牙 Secure Simple Pairing 的数字比较流程：任一端选择附近设备后，对端必须自动进入同一个待确认请求；两端显示由 TLS 1.3 exporter、双方设备证书和本次 nonce 派生的同一六位十进制安全短码，并分别确认。若双方在请求建立前同时选择对方，协议必须按双方临时实例 ID 确定唯一的 TLS client，保留该规范会话并安全关闭另一条竞争会话；不得显示两个短码、要求用户约定哪一端发起或把被淘汰会话报告成配对失败。两端均确认、双方交换持久化成功状态且本地凭据库/索引均写入成功前不得建立 peer。

已配对 peer 必须 mutual TLS 并按持久设备 ID 固定其证书指纹；任何证书变化、版本错误、帧过长、超时、重复确认、取消或撤销均拒绝对应会话。竞争会话只允许在双方均携带显式用户配对意图且规范会话仍继续时被淘汰，不得放宽证书、短码或双向确认要求。

## LAN-PAIR-003 持久化与 UI

设备私钥、持久设备 ID 和 peer proof 使用平台凭据库；owner-only 索引只保存 opaque peer ID、固定证书指纹、协议版本和用户本地标签。typed desktop API 只投影 opaque ref、请求/数字比较/持久化/已连接状态、可编辑标签和配对短码，绝不投影 IP、port、证书、公钥、固定指纹、nonce 或 LAN frame。UI 必须明确任一端均可发起；对端无需再次点击“配对”，但必须独立确认短码。
