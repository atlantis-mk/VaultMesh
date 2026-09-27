# 功能与非功能需求

Requirement ID 永久稳定。详细机制由 `specs/` 和 ADR 所有；本文件只定义用户可观察结果与硬约束。

## 产品与 Vault 生命周期

### REQ-PRODUCT-001 本地优先运行

- 必须：用户不创建账号、不连接 VaultMesh 服务即可创建和使用 Vault。
- 必须：当前版本仅提供 REQ-LAN-SYNC-001 定义的局域网设备同步，不提供服务器同步、分享或恢复后门。
- 验收：`AT-PRODUCT-001`。

### REQ-LAN-PEER-001 局域网客户端发现与可信配对

- 必须：macOS/Windows VaultMesh desktop 与 Android Compose 客户端可以在用户显式开启、最长十分钟的局域网发现窗口内，生成本次窗口专用的随机六码配对码并互相发现同一协议主版本与配对流程修订的 VaultMesh 客户端；不同流程修订必须在发现阶段相互隔离，不得等到 TLS 握手后才以通用错误失败。另一台设备选择该客户端并输入其当前配对码后，双方必须通过与当前 TLS 会话绑定的密码认证密钥交换自动建立可撤销设备信任，不得再要求被发现端二次确认。
- 必须：附近设备页面只能在本机 Vault 解锁后展示；锁定状态不得加载或展示设备列表与配对码。页面显示期间，手动锁定、按策略锁定或状态刷新发现已锁定时必须立即停止发现并返回锁定页；desktop 窗口失焦和 Android Activity 暂停分别按平台策略锁定 Vault。LAN 设备信任不得授予或继承 desktop/browser/Agent/Android unlock；配对仅为 REQ-LAN-SYNC-001 建立当前 Vault 的同步授权，不授予远程操作、Browser RPC 或 Agent IPC 权限。
- 必须：mDNS TXT 只能包含协议版本、随机实例 ID 与一次性 nonce，SRV/A/AAAA 只能使用随机会话 hostname 与临时 endpoint；不得披露系统 hostname、用户信息、Vault metadata、证书、公钥、配对码或受保护值。renderer-safe DTO 除本机当前的短时配对码外，不得包含 hostname、IP、port、证书、公钥、固定指纹、nonce 或协议帧；错误配对码、证书变化、协议不兼容、超时、取消、重复、撤销和损坏持久化必须 fail closed。
- 验收：`CT-LAN-PAIRING-001`、`AT-LAN-PAIRING-001`。

### REQ-LAN-SYNC-001 局域网自动双向同步

- 必须：配对授权后，同一 LAN 时变化主动推送、重连主动补齐；完全锁定时只收发加密更新，desktop 或独立 Browser/Agent 解锁后验证合并适用凭据与组织信息，离开附近设备页面仍继续；各端主密码与 Vault Key 独立。新配对明确包含同步授权，旧配对双方补充确认，授权绑定双方 Vault 与设备身份。
- 必须：不同 ID 保留独立；同记录采用确定性最后修改版本，败者保留加密历史；重复幂等，删除和历史清理不被旧设备复活；变化、版本和墓碑同事务原子落盘后才确认。
- 必须：邮件连接凭据、本地权限/设置/审计与 SSH 部署绑定不得传输；旧单设备 Passkey 保持本机，新可备份 Passkey 支持同步。锁定必须清除对应解密授权，但允许已授权通道仅搬运密文；睡眠、撤销、切换 Vault 或退出必须停止相应传输。首次通道建立须双方解锁；不得借同步授予 Browser/Agent 权限。
- 必须：format-3 升级由主密码验证并先保存加密备份，format 4 不得被旧 writer 修改；恢复必须轮换副本 epoch 并重新授权。机制由 `specs/lan-vault-sync.md` 所有。
- 必须：三个及以上设备按原始版本去重与收敛；逐设备区分密文已送达和已合并。撤销一条配对边不承诺阻止其他授权边转发。锁定收发不承诺即时可用，在线已解锁以秒级生效为性能验收目标。
- 验收：`CT-LAN-SYNC-001`、`AT-LAN-SYNC-001`。

### REQ-DEVICE-ASSIST-001 已配对设备填充协助

- 必须：同一局域网内已配对 Android 可以向 macOS/Windows Chromium/Firefox 提供手机号码与短信候选；两项能力分别一次授权，默认关闭，不能由同步或配对推导。目标网页支持 HTTP 和 HTTPS；只允许电脑用户主动点选，手机不逐次确认；手机锁屏仍可提供但不得解锁 Vault。
- 必须：授权由平台凭据库保护并绑定 Vault 与设备身份；恢复、替换、撤销、证书变化后失效。请求最长 120 秒且绑定原 Browser 授权、origin、tab、document、frame 和字段，最终空字段验证与一次性 assignment 不得跳过；导航、隐藏、过期、取消、锁定、重复与迟到响应必须拒绝。不自动提交。
- 必须：号码候选仅显示末四位；短信最多 20 个内存候选且只保存两分钟，正文不传输或持久化，普通 DTO 不含验证码。来源不证明网站归属；v1 主动取码仍全局一次消费，v2 推送允许各授权电脑分别本地消费一次；原始 TTL 不随重连延长。
- 必须：旧端不支持时降级为无互通入口，不改变 Vault 格式或已有同步；机制由 `specs/device-fill-assist.md` 所有。
- 必须：已授权号码在电脑凭据库持久注册，按设备/证书及本机 Vault 隔离，离线可本地填入；短信以认证被动推送为主，电脑短时内存保留原始期限，保留主动回退。撤销、更新与离线清理语义由互通专项规格所有。
- 验收：`CT-DEVICE-ASSIST-001`、`CT-DEVICE-ASSIST-002`、`AT-DEVICE-ASSIST-001`。

### REQ-VAULT-001 创建、解锁和锁定

- 必须：用户可以创建加密 Vault，以正确主密码解锁，错误密码失败，并显式或按策略锁定。
- 失败：锁定后所有数据操作失败；重复锁定保持幂等。
- 验收：`CT-VAULT-001`、`CT-NATIVE-VAULT-001`、`CT-NATIVE-RESPONSIVENESS-001`、
  `AT-VAULT-001`、`AT-NATIVE-MACOS-001`。

### REQ-VAULT-002 主密码轮换

- 必须：验证旧主密码后更换包装材料，不改变用户 payload。
- 失败：验证、加密或原子提交失败时旧密码和旧文件仍有效。
- 验收：`CT-VAULT-002`。

### REQ-VAULT-003 加密备份与恢复

- 必须：备份保持为加密 Vault envelope；恢复前验证格式和密码并原子替换。
- 必须：备份不提供绕过主密码的恢复路径。
- 验收：`CT-VAULT-003`、`CT-NATIVE-DESKTOP-001`、`AT-VAULT-002`、`AT-NATIVE-MACOS-004`。

## Item 与恢复

### REQ-ITEM-001 Login

- 必须：支持 login CRUD、URI/custom fields、TOTP、re-prompt、受控 copy/reveal 和自动填充策略。
- 必须：支持把 2FA 恢复码作为 Login 的受保护字段保存；summary/detail 只能返回存在性，
  桌面端与浏览器扩展每次查看或复制都必须由 core 重新验证主密码，不受 Login 普通 re-prompt 设置影响；插件查看值只能在当前 popup 内存中短暂存在，插件复制必须由桌面特权 runtime 写入带过期清理的系统剪贴板。
- 必须：桌面 Login 新建/编辑与插件 Login 编辑可通过特权 runtime 选择 UTF-8 文本文件；普通文本按换行解析并保留每个非空码，完整识别为 Google 编号双栏下载格式时必须忽略说明文字、拆分两列并按编号排序。插件发起时必须先恢复、显示并聚焦 VaultMesh 主窗口，文件选择和删除确认框必须以主窗口为 parent。解析后必须由原生确认框询问是否删除源文件，只有用户明确同意且文件未变时才可删除。完整路径不得进入 renderer 或插件，插件解析结果只能保留在当前 popup 编辑草稿。
- 必须：浏览器扩展不得因页面出现 TOTP QR 而向网页插入识别按钮、菜单或其他 QR UI；只有用户在
  插件 popup 内主动发起当前页面识别或在 Login 编辑器点击扫描后，才可以识别当前页面可见的
  TOTP QR，并把密钥加入当前 popup 草稿。已有 TOTP 必须确认覆盖，取消、失败或重复操作不得改变 Login。
- 验收：`CT-ITEM-001`、`CT-AUTHENTICATOR-001`、`CT-RECOVERY-CODES-001`、
  `AT-ITEM-001`、`AT-RECOVERY-CODES-001`。

### REQ-ITEM-002 Payment card

- 必须：支持 card CRUD；列表/详情省略完整卡号、安全码和 PIN，浏览器填充始终重新验证主密码。
- 验收：`CT-ITEM-002`、`AT-ITEM-002`。

### REQ-ITEM-003 SSH credential

- 必须：支持密码/密钥凭证、生成、受限本地扫描、外部客户端和公钥安装；秘密不进入 summary/detail。
- 验收：`CT-ITEM-003`、`AT-ITEM-003`。

### REQ-ITEM-004 Identity

- 必须：支持部分身份资料 CRUD、表单映射、trash/history；自动流程不得泄露未选择字段。
- 验收：`CT-ITEM-004`、`AT-ITEM-004`。

### REQ-ITEM-005 Developer/service secret

- 必须：以平台无关 kind 保存 API key、token、authenticator key、client/webhook secret 等；受保护值只允许替换或特权复制。
- 验收：`CT-ITEM-005`、`AT-ITEM-005`。

### REQ-RECOVERY-001 Trash 与 history

- 必须：适用 Item 的删除和编辑前版本保留在加密 payload 中，并支持 restore、purge/clear。
- 必须：当前 WXT 原插件只读取 Login、card、identity 与 SSH 的回收站/历史安全摘要；恢复、永久删除与清空使用既有类型化 Browser RPC，破坏性操作必须显式确认并消费桌面一次性确认。切换类型/项目、隐藏、锁定、撤销或断连必须丢弃列表与迟到响应；Secret 不展示不存在的恢复入口。
- 失败：任一恢复或清理提交失败不改变当前状态。
- 验收：`CT-RECOVERY-001`、`AT-RECOVERY-001`。

### REQ-SERVICE-001 网站/服务聚合

- 必须：用户可以创建、编辑、搜索、删除、恢复和清理网站/服务记录；Service 保存名称、非秘密说明、标签、
  一个或多个规范化 HTTP(S) 地址，以及关联 Login、developer/service Secret、SSH credential、Identity 或 Passkey 所属 Login
  的 typed opaque reference。关系允许多对多，不复制受保护值，也不改变源 item 的 CRUD、history、re-prompt、
  target、autofill、Passkey 或 Agent policy。
- 必须：用户可以在本地对现有 safe metadata 生成绑定 Vault namespace、item catalog revision、规则版本与输入 digest
  的确定性批量预览；高置信度结果经一次确认原子应用，中低置信度保留为待确认/未分组。规则 v1 只把非 IP、
  非 localhost 的 exact canonical host 作为 high-confidence key，不同非默认 port、跨 host、共享托管域、仅标题相似
  或冲突 URI 不得自动应用。输入变化使旧 plan 过期，取消不写入，重复 apply/re-run 必须幂等。
- 必须：新建、导入或更新 item 可以按同一 v1 规则自动关联唯一 high-confidence Service；无唯一结果时只生成建议，
  用户可以关闭持续自动聚合。automatic source、ignored suggestion 与显式 merge/split/move 决定保存在加密 payload；
  用户决定优先，规则升级不得静默改写。
- 必须：Service 详情按概览、登录账号、API/密钥、SSH、其他展示 renderer-safe count/reference，并允许进入原 item；
  summary/detail 不得包含 username、password、Token、TOTP、恢复码、SSH host、私钥或 protected custom field。
- 必须：Service 删除不级联删除源 item；item delete/restore/purge、Service restore/purge、merge/split/move/link/unlink
  必须验证 kind/ID 并原子提交。未知 kind、重复引用、dangling reference 和类型混淆不得产生错误导航。
- 必须：Service 地址和关系只用于组织、展示与建议。Browser autofill、Passkey、Agent discovery、HTTP 与 SSH
  每次都必须重新读取原 item 的 authoritative target，不得从 Service 推导 permission 或扩大 origin/target。
- 验收：`CT-SERVICE-001`、`CT-SERVICE-AUTO-001`、`AT-SERVICE-001`、`AT-SERVICE-AUTO-001`。

### REQ-API-001 结构化 API 环境

- 必须：用户可以在 live 网站/服务下创建、编辑、删除、恢复和清理多个 API Environment。Environment 保存用户可见
  名称、`production/staging/development/local/other` 分类、canonical HTTP(S) origin、可选 base path、可选用户手动输入
  的 HTTP(S) `openapiUrl`、`none/bearer/basic/api-key` auth binding、最多 32 个结构化 fixed Header、单调 revision 与
  policy digest。所有 live Environment 均可以进入 Agent 安全目录，不设置独立的 Environment 级 Agent enable 开关。
- 必须：`vault-core` 是 Environment、canonicalization、typed credential relationship、revision/digest、trash/history 与
  rollback 的唯一所有者。Environment 只保存 Login/Secret opaque item/field reference 与 expected Secret kind；credential
  value、password、Token、API key 或派生表示仍只由原 item 拥有，不得复制到 Environment。
- 必须：origin 拒绝 userinfo、非 HTTP(S)、path/query/fragment、控制字符、反斜线、scheme-relative 与 encoded
  separator/dot；base path 拒绝 absolute/scheme-relative target、query/fragment、dot/encoded segment 和 escape。
  `openapiUrl` 只作为 Agent 可见 safe metadata 原样保存，不由 VaultMesh 下载、解析、认证或用于请求 target/permission。
- 必须：Header 使用唯一 case-insensitive name 与 `literal`/`protected` source；数量、name/value 长度和字符有界。
  `Authorization`、`Cookie`、`Host`、`Proxy-*`、hop-by-hop、传输控制、重复 Header 和看似 credential 的 literal 必须拒绝；
  protected source 只保存 live typed reference。Agent 不得提交、查看、覆盖或选择 Header/auth/credential。
- 必须：Environment CRUD、picker 和 Header 编辑只由 desktop typed API 暴露。renderer detail 不包含 credential value；
  取消不写入，相同输入重复保存幂等，锁定、Vault 切换、窗口关闭和退出清除编辑草稿。
- 必须：Agent discovery 包含 Service/reference/lifecycle 均 live 的 opaque `environmentRef`/`accountRef`、
  Service + Environment label、environment kind、`http` semantic capability 与可选 `openapiUrl`；不得包含 origin、base path、
  Header、auth method、credential ref、username、scope 或 notes。目录 cursor 绑定查询与包含不可见 policy digest 的 catalog
  revision；配置、Service 或 credential kind/lifecycle 漂移使旧 cursor fail closed，且不得按 label 自动改绑。目录可见性
  不授予执行权限；每个 Agent 动作仍必须通过独立 Agent unlock，并按风险进入 Action Lease/逐次确认流程。
- 必须：本 Requirement 只承诺可配置与可发现，不承诺 ApiEnvironment 网络执行。`vaultmesh_http_request` 的 direct
  access-token Secret 兼容路径不自动转换或迁移授权；ApiEnvironment 执行由 `CHG-2026-028` 完成，首次执行必须重新 Ask。
- 验收：`CT-API-PROFILE-001`、`CT-ITEM-005`、`CT-AGENT-ACCOUNT-001`、`CT-AGENT-DISCOVERY-002`、
  `CT-AGENT-SECRET-001`、`CT-AGENT-AUTHZ-002`、`CT-AGENT-LIFECYCLE-001`、`CT-RECOVERY-001`、`CT-REL-001`、
  `CT-COMPAT-001`、`CT-PRIV-001`、`AT-API-PROFILE-001`。

### REQ-API-002 桌面特权 API request workbench

- 必须：用户可以从 live `ApiEnvironment` 打开桌面 request workbench，提交 `GET/HEAD/POST/PUT/PATCH/DELETE`、
  相对 base path 的 canonical path、唯一且有界的 query、普通 Header 和空/JSON/UTF-8 text body。发送前必须显示
  canonical method、origin/base path、target class 与非秘密配置摘要；GET/HEAD 不接受 body，所有 mutation 禁止自动重试。
- 必须：renderer 只能使用穷举的 prepare/execute/cancel typed operation，提交 environment opaque ID 与结构化请求，
  不得获得或提交展开的 Authorization/API key/Basic credential/protected Header。Rust prepare 绑定单次 request digest、
  Environment revision/policy digest、DNS 地址与 60 秒 execution reference；execute 在秘密使用前重新读取 live
  Environment/credential 并逐字段比较，drift、deleted reference、revoked/needs-review 或 kind mismatch fail closed。
- 必须：public target 只允许通过系统 WebPKI/hostname/expiry 校验的 HTTPS；public HTTP、invalid/self-signed certificate、
  metadata、link-local、unspecified、multicast/broadcast 和 public/private 混合 DNS 拒绝。Loopback/private HTTP(S)、
  mutation 与任何明文 HTTP 每次都必须经 Rust-owned 原生确认。DNS 最多固定 16 个同类地址到当次连接；redirect、
  proxy、Cookie jar、credential store、compression、retry 和连接池关闭，renderer/Profile 不能降低策略。
- 必须：response 只返回 status、安全 Header allowlist 与最大 1 MiB 的 JSON/UTF-8 text；Header count/bytes、JSON
  depth/items、content type/encoding、connect/overall timeout 和并发数必须有界。Binary、multipart、download、WebSocket、
  SSE、stream 与 raw library error 不返回。Exact credential、Basic 组合、Base64/URL-safe Base64/hex canary 命中时必须
  丢弃 body并返回 stable safe error；业务 response 视为可能敏感且只存在当前已解锁 renderer 内存。
- 必须：execution reference 单次使用；cancel、timeout、Vault lock/switch/restore、窗口关闭/隐藏、应用退出、成功和失败
  都必须幂等中止并清除 pending state、DNS、auth、request/response 与 parser buffer。Mutation 在请求可能送达后发生
  transport loss、timeout 或 cancel 必须返回 `execution-unknown`，UI 不得显示为“未执行”。工作台不得写 request/
  response history、audit body、telemetry、snapshot、argv、environment、proxy 或临时文件。
- 必须：桌面工作台不创建、迁移或继承 Agent pairing、unlock lease、permission、ActionPlan、MCP/IPC 或 Browser RPC；
  Agent direct Secret 与 ApiEnvironment execution 的公开 schema、授权和 output policy 不因本 Requirement 改变。
- 验收：`CT-API-REQUEST-001`、`CT-API-REQUEST-SEC-001`、`CT-API-PROFILE-001`、`CT-SEC-001`、
  `CT-AGENT-HTTP-001`、`CT-PRIV-001`、`AT-API-REQUEST-001`。

## Desktop 安全边界

### REQ-SEC-001 Renderer 隔离

- 必须：renderer 无 Node/filesystem/arbitrary IPC；Tauri 调用经 window-bound capability、
  穷举 operation 和 Rust payload/authorization 校验。
- 验收：`CT-SEC-001`、`CT-TAURI-COMMAND-001`。

### REQ-SEC-002 Quick unlock、锁定与剪贴板

- 必须：quick unlock 只包装随机 Vault Key，不保存主密码；锁定撤销授权；剪贴板值按配置过期。
- 必须：macOS 桌面端已启用 Touch ID 时，每次进入锁定解锁页必须自动发起一次系统 Touch ID；
  取消或失败后保留手动重试和主密码/PIN fallback，不得因重渲染重复弹出认证。
- 必须：PIN/生物识别两项无凭据状态查询作为同一轮并发读取并共用在途事件检查；后台最多接纳两项此类只读查询，仍逐项验证来源、会话、版本、期限和防重放，不能与受控工具写操作并行。解锁、设置及其他特权操作不得借此绕过串行保护。
- 验收：`CT-SEC-002`、`CT-NATIVE-PRIVILEGED-001`、
  `CT-NATIVE-QUICK-UNLOCK-001`、`CT-NATIVE-CLIPBOARD-001`、`CT-TAURI-DESKTOP-001`、`AT-SEC-001`、
  `AT-NATIVE-MACOS-003`。

### REQ-SEC-003 Desktop 窗口内容捕获保护

- 必须：每个 VaultMesh 自有 Tauri 产品窗口从创建起请求平台内容捕获保护；renderer 不得获得
  关闭保护的 capability，保护在锁定和解锁状态均保持启用。
- 必须：Windows 10 2004+ packaged app 使用平台公开的窗口捕获排除能力，并通过系统截屏和
  录屏验收；该能力是纵深防御，不是 DRM，不覆盖被攻陷 OS、非公开捕获路径或外部相机。
- 必须：macOS 启用 Tauri/AppKit 可用的窗口保护提示，但平台不提供受支持的通用截屏阻断保证；
  产品不得把该提示描述为“无法截屏”，且必须继续依赖失焦锁定和敏感值最小披露。
- 验收：`CT-SEC-003`、`AT-TAURI-MACOS-002`、`AT-TAURI-WINDOWS-002`。

### REQ-IMPORT-001 Import 与本地 SSH scan

- 必须：文件选择和 SSH scan 由 main 发起，内容存在有界临时 session；renderer/extension 只收安全预览与 opaque ID。
- 必须：扫描到仅含私钥的 SSH 候选时，用户可以在导入前手动补充公钥，也可以不补充直接导入；仅私钥记录必须允许之后在 SSH 密钥编辑器中补充公钥。手动输入的公钥必须经过格式校验，扫描所得私钥不得返回 renderer。
- 验收：`CT-IMPORT-001`、`CT-SSH-SCAN-001`、`CT-NATIVE-IMPORT-001`、`AT-NATIVE-MACOS-004`。

### REQ-NATIVE-001 macOS 原生桌面工作流

- 必须：解锁后的 macOS 原生客户端提供保险库、安全中心和设置三个已实现目的地；保险库支持搜索及按 login、card、identity、SSH、developer secret 类型筛选。
- 必须：目的地和操作入口只有在对应端到端能力可用时显示，不得使用静态数据或无行为占位页面表示 parity。
- 失败：锁定必须清除当前选择、筛选之外的 decrypted DTO、创建/导入临时状态并返回 lifecycle；重复提交不得产生重复 mutation。
- 验收：`CT-NATIVE-DESKTOP-001`、`CT-NATIVE-IMPORT-001`、`AT-NATIVE-MACOS-004`。

### REQ-TAURI-001 macOS/Windows 统一桌面运行时

`Superseded by REQ-TAURI-002 on 2026-07-23`。以下保留历史语义，不再作为当前验收 owner。

- 必须：Tauri 2 桌面客户端复用同一 React presentation 与 Rust runtime，在 macOS/Windows
  提供全部当前 Required desktop workflow，不依赖 Electron、N-API 或长期 Node sidecar。
- 必须：Tauri 达到 feature/security/Browser/package/upgrade/rollback parity 后成为默认桌面入口；
  Electron removal 必须保留可验证回滚证据。
- 失败：未知 command、越权 scope、锁定状态、非法 payload、重复提交和持久化失败必须 fail closed，
  不得发布新状态或残留受保护值。
- 验收：`CT-TAURI-SHELL-001`、`CT-TAURI-COMMAND-001`、`CT-TAURI-VAULT-001`、
  `CT-TAURI-DESKTOP-001`、`CT-TAURI-BROWSER-001`、`AT-TAURI-MACOS-001`、
  `AT-TAURI-WINDOWS-001`。

### REQ-TAURI-002 Tauri-only 桌面源码与运行时

- 必须：Tauri 2 是 macOS/Windows 唯一桌面产品源码和运行时 owner，复用同一 React
  presentation 与 Rust runtime，提供全部当前 Required desktop workflow，不依赖 Electron、
  N-API、SwiftUI/WinUI presentation、C ABI 或长期 Node sidecar。
- 必须：renderer、typed API/contracts、Browser RPC policy、UI tests 和 product assets 由
  Tauri 路径拥有；workspace、默认脚本、lockfile 和 CI 不得保留 Electron/Native build owner。
- 必须：macOS 系统托盘使用平台模板图标；Windows 系统托盘在启动时按 Windows 系统明暗模式
  选择高对比度黑/白图标，并在模式变化后无需重启立即更新。
- 必须：源码移除不得删除旧 Electron 加密 user-data、迁移 receipt、backup 或系统 credential；
  未完成的平台 AT 继续阻止 Verified/Released。
- 失败：未知 command、越权 scope、锁定状态、非法 payload、重复提交和持久化失败必须 fail closed，
  不得发布新状态或残留受保护值；Windows 主题读取或监听失败不得阻止启动，必须回退为深色任务栏
  可读的白色托盘图标。
- 验收：`CT-TAURI-SOURCE-001`、`CT-TAURI-SOURCE-002`、`CT-TAURI-SHELL-001`、`CT-TAURI-COMMAND-001`、
  `CT-TAURI-VAULT-001`、`CT-TAURI-DESKTOP-001`、`CT-TAURI-BROWSER-001`、
  `CT-TAURI-TRAY-THEME-001`、`AT-TAURI-MACOS-001`、`AT-TAURI-WINDOWS-001`、
  `AT-TAURI-WINDOWS-003`。

### REQ-DESKTOP-001 登录时静默启动

- 必须：macOS/Windows 桌面端首次运行默认注册为当前用户登录项，并在设置中显示系统当前真实
  注册状态，允许用户启用或关闭；用户关闭后，后续手动启动不得擅自重新开启。
- 必须：登录项只携带固定的非秘密启动参数；由登录项启动时 Vault 保持锁定，只进入系统托盘，
  不得显示或聚焦主窗口；用户手动启动时必须正常显示主窗口。
- 必须：用户关闭主窗口时必须销毁其 WebView、保留受 Rust runtime 管理的托盘进程；托盘“显示”或系统重开事件必须按当前主窗口配置重建、显示并聚焦新窗口，不得将旧 renderer 留在后台。
- 失败：系统登录项查询或变更失败不得阻止 VaultMesh 启动，不得把未生效的选择显示为成功，
  并且必须允许用户从设置页重试。
- 验收：`CT-DESKTOP-STARTUP-001`、`AT-DESKTOP-STARTUP-MACOS-001`、
  `AT-DESKTOP-STARTUP-WINDOWS-001`。

### REQ-UPDATE-001 桌面测试通道自动更新

- 必须：macOS aarch64/x86_64 与 Windows x86_64 release build 从编译期固定的 HTTPS test channel
  自动检查更高 SemVer，并且只安装通过内置 Tauri updater public key 验证的目标平台 artifact；debug/local
  build 不得访问远程更新通道，renderer 不得获得 updater plugin capability。
- 必须：macOS/Windows release build 必须在原生应用菜单提供“检查更新…”入口；主动检查必须与自动检查互斥，
  在无更新或检查失败时显示明确的原生反馈，并在发现更新后复用相同的确认、验签、清理和安装路径。
- 必须：发现更新后由 Rust-owned 原生对话框让用户选择立即更新或稍后处理；确认安装后必须先锁定
  Vault、撤销 Browser/Agent 临时 authority 并清理敏感临时资源。Windows installer exit 与 macOS restart
  必须走等价的退出清理路径。
- 必须：CI 必须使用与目标 OS/architecture 匹配的标准 GitHub-hosted Runner 原生构建 updater artifact：
  `macos-15` 对应 aarch64、`macos-15-intel` 对应 x86_64、`windows-2025` 对应 Windows x86_64，发布 job
  使用标准 Ubuntu Runner；发布 workflow 不得依赖 `self-hosted` 或自定义 Runner 标签。版本化不可变对象
  必须先写入 R2，并且只在三个平台的 URL、非空签名和安装包全部验证后最后发布
  `channels/test/latest.json`；R2 写凭据和 updater private key 不得进入仓库、应用包、更新清单或日志。
- 必须：完整三平台 workflow 必须固定精确 Rust toolchain，并按 OS、host architecture 与 target triple 隔离
  Cargo 下载和第三方 dependency build-object cache。cache key 必须绑定该 toolchain、Rust manifests、Cargo
  配置和 `Cargo.lock` 中的依赖图，但必须忽略只改变 workspace 自身 SemVer 的元数据；workspace package
  object、最终 binary/bundle、签名/R2 credential 与编译期 OAuth 值不得进入 cache，保存前必须清除 workspace
  release object。矩阵必须继续 `fail-fast: false`；任一平台失败时，已成功平台的同 run artifact 必须保留，
  publisher 必须以失败而不是 skipped 结束，使“Re-run failed jobs”只重跑失败平台和发布链。publisher 在
  三平台全部成功前不得写 R2。
- 可以：标准 GitHub-hosted Windows target Runner 可以通过独立 workflow 在同一个 Windows job 内构建作为 updater 的
  Windows NSIS 测试包和供手动部署的 MSI，并直接上传 immutable experimental prefix，不通过其他
  Runner 或 GitHub artifact 中转；该流程不得写入 `channels/test/latest.json` 或冒充 Windows 平台验收
  证据，并且必须明确输出两个安装器的直接下载链接和未验收状态。
- 可以：标准 GitHub-hosted macOS target Runner 可以通过独立 workflow 在同一个与目标架构匹配的 macOS job 内构建
  Tauri updater archive 和 DMG，并直接上传 immutable experimental prefix，不通过其他 Runner 或
  GitHub artifact 中转；该流程不得写入 `channels/test/latest.json` 或冒充 macOS 平台验收证据，并且
  必须明确输出 updater archive、DMG 的直接下载链接和未验收状态。
- 失败：无更新、用户取消、超时、离线、HTTP/TLS、清单、目标、版本或签名失败不得退出当前应用、
  不得宣称成功，也不得启用 downgrade。需要回滚时必须发布更高版本的补偿 build 或明确手动重装。
- 验收：`CT-UPDATE-001`、`AT-UPDATE-MACOS-001`、`AT-UPDATE-WINDOWS-001`。

### REQ-UPDATE-002 Review 发布基线与独立通道

- 必须：`0.0.1-review` 是 fresh-install 基线；每个后续 Review build 的 workspace、Rust package、
  Tauri desktop、Chromium extension 和 Firefox extension 必须统一为同一个严格递增的规范 Review SemVer，当前更新版本为
  `0.1.0-review`；打包输出和 updater descriptor 不得丢失 `review` prerelease 标识。
- 必须：Review build 从编译期固定的 HTTPS `channels/review/latest.json` 检查更新，并继续使用
  `REQ-UPDATE-001` 的 Rust-owned 检查、用户确认、Tauri 签名验证、安装前 lock/cleanup 和 latest-last
  发布、Cargo cache 与失败任务恢复约束；完整 Review 发布同样必须使用三个标准 GitHub-hosted 原生架构
  Runner，renderer 不得获得 updater plugin capability。
- 必须：Review 与 test channel 独立读取和写入清单。首次 Review 发布可以没有现有 Review manifest，
  后续 Review 版本必须严格递增；不得覆盖、删除或把 `channels/test/latest.json` 复制为 Review 基线。
- 必须：完整三平台 Review build 与 R2 latest-last 发布成功后，自动化必须为同一 source SHA 创建或恢复
  GitHub Draft Prerelease，并只上传 Apple Silicon DMG、Intel DMG、Windows x64 NSIS/MSI installers 与
  同 source SHA 的 Chrome/Chromium、Firefox extension ZIP。Draft
  必须保持 prerelease 状态且不得创建 Git Tag；它不计为正式 Release、平台 AT 或已发布。只有 GATE-6、
  Work Verified/封存、Release record 与 Tag 门禁全部满足后才可以公开该 Draft。任一 build、R2 publish 或
  extension job 失败时，Draft job 必须以可重跑失败结束；同 run 重跑不得重新构建已经成功的平台。
- 可以：小规模 Review 验收可以在目标平台 signed updater artifact 已 immutable 发布后，把
  `channels/review/latest.json` 原子发布为只含已验证目标平台的阶段性 manifest；该 manifest 必须从
  `0.0.1-review` 开始并保持版本严格递增，使已安装基线先返回“无更新”，再从 `.1` 发现并安装 `.2`。
  当前版本的目标平台 artifact 后续就绪时，可以在 version、notes、pub_date 与既有 platform entry 全部
  不变的前提下只追加一个尚不存在的平台；重复平台、不同版本、失去 immutable/signature 证据或并发变更
  必须 fail closed。阶段性 manifest 不得计为完整 Review 发布或平台 AT；完整发布仍必须包含三个目标平台。
- 必须：完整 Review 发布按 `ADR-0048` 同时构建 Android release APK：armeabi-v7a、arm64-v8a、x86_64
  三个按 ABI 拆分的 APK 与一个 universal APK，各自只包含对应 ABI 的 JNI runtime 且不得含其他 ABI；
  versionName 与 Review SemVer 一致，versionCode 由版本单调派生并以个位区分 ABI。所有 APK 必须由 CI
  Secret 中同一 release keystore 签名，证书 SHA-256 必须匹配仓库固定指纹；缺少签名配置、指纹不一致、
  ABI 或版本漂移时 fail closed。Android APK 与其他产物一样先 immutable 发布到同版本 R2 路径并公网校验，
  再上传到 Draft Prerelease；Android job 失败时 publisher 与 Draft job 必须以可重跑失败结束。
  Review APK 不计为 Android 平台 AT 或已发布。
- 失败：现有 `0.1.x` test 安装不得接收 `0.0.1-review` 自动降级。加入 Review 必须使用明确的手动
  重装路径；失败或取消必须保留既有安装和 Vault 数据。
- 验收：`CT-UPDATE-REVIEW-001`、`CT-ANDROID-RELEASE-001`、`AT-UPDATE-REVIEW-MACOS-001`、`AT-UPDATE-REVIEW-WINDOWS-001`、`AT-ANDROID-RELEASE-001`。

### REQ-FEEDBACK-001 React 客户端瞬态反馈

- 必须：Tauri React renderer 与 Chromium extension popup 使用 Sonner toast
  展示成功、失败、警告和普通瞬态反馈，并由客户端根 Toaster 统一放置在页面上方中间。
- 必须：Toast description 使用客户端语义前景色，保持与 toast 背景清晰可读的对比度。
- 必须：需要用户确认的 AlertDialog 和字段级内联校验保持原交互；状态未变化时不得因重渲染
  重复产生 toast。
- 验收：`CT-FEEDBACK-001`。

## Android

### REQ-ANDROID-001 Compose 客户端 Vault 生命周期

- 必须：Android 应用图标以桌面端图标为品牌参考生成透明背景 PNG，保留紫蓝配色、保险库锁盘、青色钥匙孔与六个连接节点；PNG 原图必须保留透明通道。Android 自适应图标必须使用纯白背景，并在主体四周保留少量边距，不得重新套用桌面紫色底板。
- 必须：Android 客户端使用 Jetpack Compose 原生 UI 与 Kotlin 平台 shell，通过固定、窄且可测试的 JNI operation 调用 Rust Android runtime；JNI 不得暴露 `vault-core` 对象、裸 Rust pointer、Vault Key、持久 secret handle 或通用方法分派。
- 必须：首个切片支持在应用私有目录创建 format 4 Vault、以主密码解锁、读取锁定状态和显式锁定；已存在 Vault 时 create 必须拒绝覆盖，错误密码、损坏文件、未知格式和 IO 失败必须 fail closed。
- 必须：Rust runtime 只有在加密 Vault 原子落盘成功后才发布新解锁会话；锁定必须幂等并清除解密 payload 与 Vault Key。Kotlin 不得缓存主密码，operation 完成或失败后必须清空 Compose 输入状态。
- 必须：创建和主密码解锁的进度反馈只在对应提交运行时显示，进度环及提示文字必须位于提交按钮内部；初始状态刷新不得显示为正在解锁。
- 必须：PIN 提交或生物识别系统验证成功后，打开保险库期间必须显示带进度动画的加载状态；创建或任一解锁方式验证成功后，读取脱敏摘要期间必须继续显示加载状态和说明文字。摘要就绪前不得显示空列表或允许列表操作，失败或后台锁定时必须清除加载状态。
- 必须：主 Activity 从创建起启用 `FLAG_SECURE`，应用禁止 Android backup 与 cleartext traffic；进入后台或收到显式系统锁定信号时必须锁定 Rust runtime。应用重启不得恢复解锁状态或持久化明文 UI 状态。
- 必须：短信、通知等系统权限弹窗触发暂停后，无论允许、拒绝或隐藏，返回 Activity 时必须恢复可操作的锁定页；仅发生 `onPause → onResume` 而未经过 `onStart` 时也必须重新读取快捷解锁可用状态，不得持续显示空白或复活旧解锁会话。
- 必须：解锁后的保险库页面顶栏必须避让系统状态栏，以顶部类型标签切换安全摘要和适用回收站，以底部导航分别进入保险库、工具、设备和设置；搜索只留在当前前台会话，切换底部页面时清空查询与临时条目操作状态。全部标签只聚合已有脱敏摘要，不预读受保护值，也不得把固定类型操作替换为通用路由。全部页和类型页的条目行必须直接提供可用字段的复制入口与更多操作菜单；当前可见条目支持逐项选择、全选和取消选择，批量删除须明确确认，Secret 的不可恢复删除须单独告知，失败后不得报告全部成功。桌面托管的 SSH alias 不得被选入删除。
- 必须：保险库“全部”、各类型和适用回收站列表每次最多追加 30 条脱敏摘要，滚动接近当前列表底部时继续追加并显示加载提示；切换类型、回收站或搜索条件时从首批重新开始。全选仅作用于当前已展示的可选条目，托管 SSH 仍不可选。
- 必须：Android 首切片不得注册网络、Autofill、Credential Manager、Passkey、外部文件、后台同步或通用 WebView 权限；后续局域网发现与配对仅由 `REQ-ANDROID-021` 独立扩展，前台新版本检查由 `REQ-ANDROID-027` 独立扩展，系统自动填充与识别保存由 `REQ-ANDROID-023/024` 独立扩展，其他能力仍须独立扩展 Requirement、ADR 和平台验收。
- 验收：`CT-ANDROID-RUNTIME-001`、`CT-ANDROID-JNI-001`、`CT-ANDROID-HOME-001`、`AT-ANDROID-001`。

### REQ-ANDROID-002 Compose 客户端 Login CRUD

- 必须：Android 客户端在 Vault 解锁后通过固定 JNI operation 展示 Login 安全摘要，并支持创建、编辑和删除 Login。基础操作覆盖标题、用户名、密码和 URL；列表不得返回密码、notes、TOTP、恢复码或 custom field 值。
- 必须：编辑时空密码表示保留原密码，不得为了编辑普通字段把现有密码返回 Kotlin。删除前必须由用户确认，删除沿用 core 的加密回收站语义；锁定后所有列表与修改操作必须 fail closed。
- 必须：每次 Login mutation 必须先由 `vault-core` 修改候选状态并生成加密 Vault，再原子提交文件；提交失败必须恢复旧内存 payload 和旧文件。Compose 编辑草稿不得持久化，取消、完成、失败、进入后台或锁定时必须清除密码和解密列表。
- 验收：`CT-ANDROID-JNI-002`、`AT-ANDROID-002`。

### REQ-ANDROID-003 Compose 搜索与 Login 回收站

- 必须：Android 客户端只在当前已解锁进程内对 Login 与回收站安全摘要执行标题、用户名和适用 URL 的大小写不敏感搜索；查询不得发送到 JNI、写入持久化状态或在锁定后保留。
- 必须：Login 删除进入 `vault-core` 加密回收站；Android 可以读取不含秘密的回收站摘要、恢复条目、永久删除单项或清空回收站。永久删除和清空必须分别显式确认，恢复不读取条目密码。
- 必须：恢复、永久删除与清空复用原子提交和内存回滚；锁定、迟到响应、未知 ID、IO 失败和重复操作必须 fail closed，不得自动重试或把回收站秘密返回 Kotlin。
- 验收：`CT-ANDROID-JNI-003`、`AT-ANDROID-003`。

### REQ-ANDROID-004 Compose 其他 Item 类型的基础管理

- 必须：Android 在解锁后通过各类型固定 JNI operation 管理 Payment card、SSH credential、Identity 和 Developer/service secret 的基础字段；列表只返回安全摘要，不返回完整卡号、安全码、PIN、SSH 认证值或 Secret 值。搜索只在当前进程的安全摘要上执行。
- 必须：Card、SSH 和 Secret 编辑中的空秘密输入表示保留原值；明确清除与替换不得同时提交。Identity 基础字段编辑必须保留未修改的多邮箱、电话、地址及其 ID。所有类型编辑必须保留 UI 未提供的 core 元数据，不能因移动端字段较少而清除。桌面管理的 SSH alias 在 Android 只读；Passkey 记录不得经普通 Secret 操作展示、编辑或删除。
- 必须：Card、SSH 和 Identity 删除进入各自加密回收站，可恢复、单项永久删除或清空，永久操作必须确认。Secret 删除不可恢复，必须明确告知并确认。未知 ID、重复操作、锁定、迟到响应或提交失败不得自动重试或显示成功；mutation 复用原子提交与内存回滚。
- 必须：新增类型的编辑草稿和列表在取消、完成、后台化或锁定后清除，不得进入持久化 UI 状态。当前基础管理不授予卡号、密钥或 Secret 值的查看/复制、Autofill、SSH 执行或 Android 系统服务权限。
- 验收：`CT-ANDROID-JNI-004`、`AT-ANDROID-004`。

### REQ-ANDROID-005 Compose 主密码轮换

- 必须：Android 仅在当前 Vault 已解锁时允许用户输入旧密码、新密码及确认值；确认不一致或空值不得调用 JNI。提交前必须从 Compose 状态清空输入，取消、失败、后台化与锁定后不得保留密码草稿。
- 必须：固定 JNI operation 在 Rust runtime 中以旧密码从当前加密 Vault 构造候选会话，复用 `vault-core` 轮换包装材料，再原子写盘；写盘成功后才替换当前会话。旧密码错误、无效输入、序列化或写盘失败必须保留旧文件和原会话，不得自动重试未知结果。
- 必须：成功后旧密码不能解锁，新密码在锁定和进程重建后可以解锁，payload 不变；密码、Vault Key、header 和文件内容不得作为结果返回 Kotlin 或写入持久化 UI 状态。
- 验收：`CT-ANDROID-JNI-005`、`AT-ANDROID-005`。

### REQ-ANDROID-006 Compose 受保护值复制

- 必须：Android 仅在已解锁界面由用户明确选择具体条目与字段、重新输入当前主密码后，通过固定字段 JNI operation 复制 Login 密码、Card 卡号/安全码/PIN、SSH 密码/公钥/私钥/口令及普通 Secret 值。Passkey、未知 ID、缺少字段、错误主密码和锁定必须封闭拒绝；受保护值不得进入列表、持久化 UI state 或日志。
- 必须：Kotlin 特权服务把成功返回的有界值写入系统剪贴板并标记 sensitive。30 秒到期时只允许清理仍属于本应用的 clip；检测到他人替换或无法确认所有权时不得清除用户新内容。Compose 提交前清空主密码草稿；取消、锁定、后台化与迟到结果不得复制或自动重试。
- 验收：`CT-ANDROID-JNI-006`、`AT-ANDROID-006`。

### REQ-ANDROID-007 Compose 条目历史

- 必须：Android 在已解锁会话中通过各类型固定 JNI operation 查看 Login、Card、SSH、Identity 的历史安全摘要；摘要只含版本 ID、标题、非秘密副标题与保存时间，不含历史秘密。Secret 不展示不存在的历史入口，桌面管理的 SSH alias 在 Android 不得恢复或清空历史。
- 必须：恢复绑定当前条目 ID 与版本 ID，由 core 校验归属并把当前版本写入历史；清空绑定当前条目 ID。恢复与清空都必须显式确认，经原子写盘成功后才生效，失败保留原文件与会话，不得自动重试未知结果。
- 必须：切换类型/条目、取消、锁定或后台化清除历史列表与确认；迟到响应不得重新打开历史或执行 mutation。
- 验收：`CT-ANDROID-JNI-007`、`AT-ANDROID-007`。

### REQ-ANDROID-008 Compose Login TOTP

- 必须：Android 对现有 Login 通过固定 JNI operation 设置、替换或移除 TOTP 密钥。`vault-core` 归一化 Base32 或支持的 `otpauth://totp` URI 并保存；安全摘要只返回存在性，不能返回 seed。无效密钥、缺失 Login、锁定或原子提交失败不得改变文件和会话；其他 Login 字段、恢复码、URI 与自定义字段必须保留。
- 必须：用户明确选择复制验证码并重新输入当前主密码后，由 core 在当前系统时间生成代码；密钥不能离开 core。Kotlin 特权剪贴板服务写入 sensitive clip 并执行仅清理本应用 clip 的期限；错误密码、未设置、锁定、后台化和迟到结果必须封闭拒绝。
- 必须：Compose 替换和移除明确告知结果；密钥输入在提交前清空 UI 状态，取消、失败、后台化或锁定后不得保留。设备时间偏差与代码自然到期必须在平台验收。
- 验收：`CT-ANDROID-JNI-008`、`AT-ANDROID-008`。

### REQ-ANDROID-009 Compose 加密备份与恢复

- 必须：Android 在解锁后可把当前加密 format 4 Vault envelope 导出到用户通过系统文档选择器选择的 `content:` 文档。Rust runtime 先将加密字节写入应用私有固定 staging 文件；文件选择期间沿用后台锁定。Kotlin 只复制有界密文，写入关闭后重新读取比对；取消、失败或完成须删除 staging，写入未验证不得报告成功。
- 必须：用户选择恢复文档后，Kotlin 仅从 `content:` URI 有界读取至固定私有 staging 文件；用户确认替换并输入备份主密码。固定 JNI 操作在 core 验证 format 4 与密码、重置同步副本 epoch 和授权并建立 checkpoint 后，原子替换本机 Vault；成功后才发布新会话。错误密码、坏文件、超限、取消、写盘失败或后台化不得改变旧 Vault 或发布候选状态，不得自动重试未知结果。
- 必须：JNI 不接受任意外部 URI、路径或 Vault 字节；文件 staging 仅存密文且不进入 Android backup。Android 必须明确拒绝 format 3；其主密码升级按 `NFR-COMPAT-001` 只在 desktop 执行。恢复后 LAN 设备须重新授权。
- 验收：`CT-ANDROID-JNI-009`、`AT-ANDROID-009`。

### REQ-ANDROID-010 Compose 密码健康

- 必须：Android 仅在已解锁会话由用户主动打开密码健康报告。固定 JNI operation 调用 `vault-core` 的现有弱密码、重复使用和过期规则，只返回分数及对应 Login ID；密码、哈希、长度、候选与规则中间值不得返回 Kotlin。
- 必须：Compose 只用当前安全摘要关联标题并展示各类计数/条目。报告不持久化，关闭、切换、后台化、锁定后必须清除；迟到结果不得重新打开，计算在主线程外执行。
- 验收：`CT-ANDROID-JNI-010`、`AT-ANDROID-010`。

### REQ-ANDROID-011 Compose 凭据生成器

- 必须：Android 可由用户主动生成密码、用户名和邮箱别名，使用平台安全随机源。密码的字符集、选中字符类至少各一位、长度边界、用户名首位与长度、邮箱域名校验必须与桌面当前生成规则一致；无效参数不得生成值。
- 必须：生成结果只留在当前内存界面，用户可以显式复制到带 sensitive 标记与所有权清理的剪贴板，或填入当前 Login 编辑草稿。关闭、切换、后台化或锁定后必须清除结果；不得保存生成历史、写入持久状态或自动保存 Login。
- 验收：`CT-ANDROID-GENERATOR-001`、`AT-ANDROID-011`。

### REQ-ANDROID-012 Compose Login 恢复码

- 必须：Android Login 安全摘要只返回恢复码存在性。用户可以在当前解锁弹窗粘贴每行一个恢复码，或从系统文档选择器选择有界 UTF-8 文本；固定 JNI 在 Rust 解析普通行和完整 Google 编号双栏文本，并由 core 验证后原子替换。明确清除和替换互斥；无效输入、缺失条目或写盘失败必须保留旧文件、旧会话和已有恢复码。普通 Login 编辑必须保留恢复码。
- 必须：每次查看与每次逐码复制都重新验证当前主密码，不受 Login 普通 re-prompt 设置影响。查看值只可留在当前前台弹窗；复制仅写入 sensitive 系统剪贴板并按本应用 clip 所有权清理。错误密码、缺失字段、锁定、取消、后台化和迟到结果不得暴露或复制值。
- 必须：文件选择期间按现有生命周期锁定。Android 只保留一次性 `content:` URI，重新解锁后才在内存中有界读取并显示待确认导入草稿，不得写明文 staging 文件。仅当原样导入内容保存成功后才可另外确认删除源文档；删除前复读比对内容、检查提供者支持删除，失败时保留源文档。
- 验收：`CT-ANDROID-JNI-011`、`AT-ANDROID-012`。

### REQ-ANDROID-013 Compose 受保护字段查看

- 必须：Android 用户在已解锁页面明确选择 Login 密码、Card 卡号/安全码/PIN、SSH 密码/公钥/私钥/口令或普通 Secret 值后，每次输入当前主密码，复用相应固定字段 JNI 及 core 鉴权。Passkey、未知 ID、缺失值、错误密码和锁定必须拒绝；TOTP 当前代码不进入静态值查看入口。
- 必须：成功时只有当前前台弹窗持有单个有界值；30 秒到期、用户关闭、切换页面、后台化、锁定或迟到响应必须清除。主密码在提交前从 Compose 状态移除；值不得进入普通列表、持久化 UI state、日志或剪贴板。主 Activity 保持 `FLAG_SECURE`。
- 验收：`CT-ANDROID-REVEAL-001`、`AT-ANDROID-013`。

### REQ-ANDROID-014 Compose 卡片完整字段编辑

- 必须：Android 卡片新建与编辑覆盖标题、持卡人、卡号、到期、安全码、PIN、发卡机构、卡组织、账单地址、备注、文件夹、收藏和主密码复验设置。卡片列表仍只返回安全摘要；补充字段仅在用户明确打开编辑器时经固定详情操作读取，不得包含完整卡号、安全码或 PIN。
- 必须：基础与补充字段通过固定完整卡片操作在同一次 core mutation 中验证并原子提交。编辑留空卡号保留旧值，安全码/PIN 的清除与替换互斥；未知字段、超限输入、无效卡片、锁定或写盘失败必须保留旧文件、旧会话和全部字段。旧基础操作保留兼容。
- 必须：编辑详情与草稿只在当前前台会话存在；取消、切换、后台化、锁定或迟到详情必须清除。账单地址和备注不得进入普通列表、持久 UI 状态或日志。
- 验收：`CT-ANDROID-JNI-012`、`AT-ANDROID-014`。

### REQ-ANDROID-015 Compose 服务密钥完整字段编辑

- 必须：Android 普通 Secret 新建与编辑覆盖标题、类型、服务商、账号、值、环境、Scopes、到期日、网站、备注、文件夹、收藏与主密码复验设置。列表只返回安全摘要；补充字段只在明确打开编辑器时由固定详情读取，秘密值不得随详情返回。Passkey 不得进入普通 Secret 详情、编辑或删除入口。
- 必须：基础与补充字段经固定完整 Secret 操作在同一次 core mutation 中验证并原子提交。编辑留空值保留原秘密，类型保持原类型；core 必须保留内部生命周期 Scope，并拒绝用户伪造。未知字段、超限输入、无效日期/网站、锁定或写盘失败必须保留旧文件、旧会话和已有值。旧基础操作保留兼容。
- 必须：补充字段草稿只在当前前台会话存在，取消、切换、后台化、锁定或迟到详情必须清除；值和备注不得进入普通列表、持久 UI 状态或日志。
- 验收：`CT-ANDROID-JNI-013`、`AT-ANDROID-015`。

### REQ-ANDROID-016 Compose SSH 凭据完整字段编辑

- 必须：Android 普通 SSH 凭据新建和编辑覆盖标题、主机、端口、用户名、密码、公钥、私钥、口令、备注、文件夹、收藏和主密码复验设置。列表只返回安全摘要；补充字段仅在明确打开编辑器时由固定详情读取，不得包含认证值。桌面托管的 OpenSSH alias 在 Android 只读。
- 必须：基础与补充字段经固定完整 SSH 操作在同一次 core mutation 中验证并原子提交。编辑留空认证值保留旧值，明确清除与替换互斥；未知字段、超限输入、无效 SSH、锁定或写盘失败必须保留旧文件、旧会话和全部字段。旧基础操作保留兼容。
- 必须：补充字段草稿只在当前前台会话存在，取消、切换、后台化、锁定或迟到详情必须清除；认证值和备注不得进入普通列表、持久 UI 状态或日志。
- 验收：`CT-ANDROID-JNI-014`、`AT-ANDROID-016`。

### REQ-ANDROID-017 Compose Identity 完整字段编辑

- 必须：Android Identity 新建与编辑覆盖标题、名/中间名/姓、生日、多邮箱、电话、地址、组织、部门、职位、网站、备注、文件夹和收藏。多值项必须保留稳定 ID、标签、值及首选标志；编辑未修改字段不得丢失桌面已有资料。普通列表只返回安全摘要，完整详情仅由用户明确打开编辑器时通过固定 JNI 读取。
- 必须：完整结构经严格类型化、有界固定 JNI 输入，在一次 core mutation 中验证并原子提交。未知字段、超限文档或集合、无效邮箱/日期/网址/地址/首选项、锁定或写盘失败必须保留旧文件、旧会话和全部字段；旧基础操作保留兼容。
- 必须：完整个人资料草稿只在当前前台会话存在，取消、切换、后台化、锁定或迟到详情必须清除；不得进入普通列表、持久 UI 状态或日志。
- 验收：`CT-ANDROID-JNI-015`、`AT-ANDROID-017`。

### REQ-ANDROID-018 Compose Login 完整常规字段编辑

- 必须：Android Login 新建与编辑覆盖标题、用户名、密码、主网址、附加网址、自定义字段、备注、文件夹、收藏、页面加载自动填充和主密码复验设置。普通列表只返回安全摘要；补充字段仅在用户明确打开编辑器时由固定详情读取，不得包含密码、TOTP seed 或恢复码。
- 必须：基础与补充字段经固定完整 Login 操作在同一次 core mutation 中提交。编辑留空密码保留原值；TOTP seed 与恢复码由 core 保留并继续通过独立受保护操作管理。未知字段、超限输入、锁定或写盘失败必须保留旧文件、旧会话和全部字段；旧基础操作保留兼容。
- 必须：补充字段草稿只在当前前台会话存在，取消、切换、后台化、锁定或迟到详情必须清除；自定义字段值、备注和密码不得进入普通列表、持久 UI 状态或日志。
- 验收：`CT-ANDROID-JNI-016`、`AT-ANDROID-018`。

### REQ-ANDROID-019 Compose 生物识别快捷解锁

- 必须：Android 用户在主密码解锁后可明确启用或关闭强生物识别快捷解锁。启用时由 Rust/core 包装当前 Vault Key，固定 JNI 仅短时交付随机包装秘密；Kotlin 用逐次 `BIOMETRIC_STRONG` 授权的 Android Keystore 密钥封存该随机秘密，不得保存主密码、把 Vault Key 传给 Kotlin 或把包装秘密放入 Compose/持久 UI state。
- 必须：本机封存记录与 Keystore key 均存在且 Vault 锁定时，Android 进入前台后必须直接请求一次系统 `BiometricPrompt.CryptoObject`，不先展示自定义生物识别页；同一次前台停留中取消或失败不得自动反复弹出。系统只可使用符合 `BIOMETRIC_STRONG` 的已录入方式。Rust 验证包装记录和当前磁盘 Vault 后才发布会话；取消、认证失败、注册变化、文件损坏、锁定、后台化或迟到结果须封闭失败并切换到单一的 PIN 或主密码解锁页，主密码始终可选。关闭后本机封存与 Rust 包装均删除；主密码轮换后仍按当前 Vault Key 验证。
- 验收：`CT-ANDROID-JNI-017`、`AT-ANDROID-019`。

### REQ-ANDROID-020 Compose PIN 快捷解锁

- 必须：Android 用户在主密码解锁后可设置或关闭六位数字 PIN。Kotlin 以 Android Keystore 封存独立随机设备秘密；固定 JNI 将 PIN 与设备秘密交给 Rust，Rust/core 包装当前 Vault Key。主密码、Vault Key 和长期解锁 handle 不得进入 Kotlin，PIN 和设备秘密不得进入持久 UI state、日志或 backup。
- 必须：锁定页一次只展示一种解锁输入方案；仅在本机封存与 Rust 包装记录均存在且剩余次数大于零时展示六位 PIN 页面并允许尝试。PIN 页面必须遮蔽输入并可切换到主密码；连续五次失败后必须清空 PIN 草稿并切换到主密码。每次失败由 Rust 在返回前原子持久化；成功的主密码解锁重置失败计数；解锁仍须由 core 验证当前磁盘 Vault 后才发布 session。取消、写盘失败、后台化、锁定、重启和迟到结果不得复活授权；关闭删除两份记录。
- 验收：`CT-ANDROID-JNI-018`、`AT-ANDROID-020`。

### REQ-ANDROID-021 Android 与桌面局域网发现和配对

- 必须：解锁后进入底部“设备”页即在页面内显示已配对设备列表及重命名、撤销操作；空列表显示明确空态，读取失败可重试，不得要求打开弹窗或开启发现才能查看已配对设备。发现与配对操作位于同一页面，发现仍须显式开启。
- 必须：设备页使用 Material 3 分组列表与发现区域；每个设备条目右侧的更多按钮必须直接打开该设备的设置弹窗，集中提供同步开关、号码与短信互通授权、重命名和撤销入口，不得在列表页重复展开逐设备配置。输入配对码、重命名、撤销确认各使用单一弹窗，切换操作时必须关闭原设置弹窗；设备被移除或离开页面时清除所选设备。提交中必须防重复操作；配对请求接受不等于成功，必须等待双方持久化确认完成的信任出现在状态中才关闭弹窗并反馈成功；仅本机写盘完成但仍等待对端确认时不得显示成功；失败留在弹窗内可重试，过期或设备离开必须清理临时输入。权限或网络失效停止发现后仍可查看已配对列表；读取失败不得显示为空列表。
- 必须：Android 与 macOS/Windows 桌面端使用同一 LAN protocol 2.0 发现与配对协议；双方均可显示本机六码、发现对方、发起输入码配对、显示安全状态、重命名和撤销。Android 不得要求桌面安装另一种协议或把设备身份、IP、证书、配对码交换帧暴露给 Compose。
- 必须：只有当前 Vault 已解锁、附近设备页面处于前台、用户显式启动且本地网络权限允许时，Android 才能开启最多十分钟的 mDNS 与 TLS listener。Activity 暂停、系统锁定、离页、权限撤销、停止、超时或进程终止必须关闭 listener 并清除本次码和待处理会话；重新进入不得自动重开。Android 17 及以上必须先请求 `ACCESS_LOCAL_NETWORK`；拒绝时保持关闭并提供可理解的错误。配对使用的 Wi-Fi 多播资源仅在发现期间持有；同步服务的独立资源按 REQ-ANDROID-022 管理。
- 必须：Android 设备私钥、设备 ID 和 peer proof 使用 Android Keystore 封存并仅存应用私有目录；固定 JNI 操作不得返回私钥、证书、公钥、指纹、IP、port、nonce、PAKE 消息或 Vault Key。新配对须绑定当前 Vault 的同步授权；撤销须移除本机授权与设备信任。配对 transport 不传 Vault 数据，Android 后台同步仍由独立需求定义。
- 验收：`CT-ANDROID-LAN-PAIRING-001`、`AT-ANDROID-021`。

### REQ-ANDROID-022 Android 局域网自动双向同步

- 必须：已配对授权的 Android 与桌面在同一 LAN 自动双向同步；扫描关闭、离开设备页不影响同步。数据范围、版本、冲突、删除、收据与限额遵循 REQ-LAN-SYNC-001。
- 必须：Kotlin 非导出前台服务独立管理连接和多播资源；常驻通知只显示通用状态并提供停止操作。后台化与锁屏立即清除解密 session，已建立通道仅收发密文，重新解锁后验证合并；首次通道建立和旧授权升级须双方解锁。
- 必须：设备设置弹窗提供当前设备的同步开关、状态和上次成功时间，设备页保留全局重试和加密冲突历史入口；授权和恢复操作须已解锁。拒绝/撤销本地网络权限、Wi-Fi 丢失或切换必须关闭旧连接，恢复后重连补齐。任务移除、停止与服务销毁释放资源，不自行启动解锁或开机监听。
- 必须：先原子提交 Vault 再发布密文缓存，失败不确认合并；恢复/替换 Vault 不继承授权，冷启动缓存须校验 Keystore 保护的路由证明和 Vault 指纹。同步事件刷新可见摘要但不得复活后台 UI 或覆盖编辑输入。
- 验收：`CT-ANDROID-LAN-SYNC-001`、`AT-ANDROID-022`。

### REQ-ANDROID-023 Android 系统自动填充

- 必须：设置页提供系统自动填充启用入口和状态；受系统绑定权限保护的 AutofillService 识别原生/网页登录用户名和密码字段。仅有两个可编辑字段、其中一个明确为密码时，可以把其前方唯一无标签的普通 AutoCompleteTextView 识别为用户名。QQ 精确注册手机号 Activity 中唯一聚焦的原生无提示数字字段，可以在输入类型、长度和结构均满足窄范围守卫时识别为仅填手机号的用户名字段；该字段不得显示字母随机用户名或单独触发保存。其他混合 origin、歧义、不可编辑字段和本应用密码输入必须拒绝。不得自动提交表单。
- 必须：系统下拉框在认证前可以显示最多五个当前目标的相关 Login 安全摘要候选，按最近选择、精确关联、HTTPS origin 和名称相似性排序；点选具体账号后才使用非导出认证 Activity 的主密码、已启用的设备生物识别或六位 PIN 授权并填充。无预览时保留通用入口；同一请求已有未消费的有效授权时直接消费，不重复验证，新请求或锁定态不得凭预览免验证。填充授权与通用入口的账号选择使用同一底部弹窗，认证区一次只展示一种方式，生物识别直接使用系统提示，取消后可在弹窗内切换 PIN 或主密码。弹窗标题显示 VaultMesh 与目标应用名称，目标应用包名与可选 HTTPS origin 随标题展示；账号选择时搜索框紧接标题区，不另设填充标题与说明或搜索按钮。输入停止后自动筛选候选，必须限制查询频率、合并相同输入或重复事件并丢弃旧输入的迟到结果；本次请求已取得的相同查询结果可以在请求内复用，搜索输入与结果不得记录到日志或持久化状态。账号列表以卡片展示最近使用和其他账号。主界面仍随后台锁定；独立授权仅供当前请求，120 秒到期，绑定包签名、origin、字段和请求，填充单次消费。要求再次验证主密码的条目不得通过快捷认证直接填充。
- 必须：锁定态预览只含有界条目 ID、用户名、标题和 HTTPS 主机，以 Android Keystore 加密写入私有不备份文件并绑定当前加密 Vault 指纹；文件缺失、损坏或 Vault 变化时预览失效。预览和选择历史均不是授权依据。认证前、认证后的账号与密码候选及系统填充结果必须以用户名为主标签，标题或网址只能作次级说明；用户名为空时才以标题代替。点选预览后 Rust 必须重新验证当前 Vault、目标和条目。已保存应用关联按包名、当前签名集合及 origin 精确匹配，网页声明只能作为建议。应用包名的有效片段或显示名称与条目标题、HTTPS 主机标签相近时可以标记“可能相关”，但该推测不得视为可信关联。当前目标已成功选择过的候选按最近一次优先排列；选择历史仅存 Android 私有加密记录，不含用户名或密码，不参与授权判断。未匹配条目或未经关联验证的网站凭据在交付前必须额外明确确认；用户可以只填充本次，或明确选择记住关联。记住时须在交付凭据前原子写入当前包名、签名与 origin 的加密关联，失败不得交付；下次仅精确绑定可自动排在已关联组。
- 必须：用户名栏选择登录项可以填入该账号的用户名与密码；密码栏必须提供只填密码的独立候选，重新选择密码不得改写已填写的用户名。最终秘密仅经固定 JNI 进入 Kotlin 特权 Dataset 构造器并交付系统；点击底部弹窗外的空白区域与显式取消执行同一撤销路径，必须清除当前认证授权并以新的一次性请求重新提供候选，不交付秘密；弹窗内的输入、滚动和选择不得触发外部点击取消。后台、锁屏、锁定、过期、签名改变、迟到响应和进程重建必须拒绝，禁止持久化请求或解锁状态。
- 必须：可识别且账号字段可填文本的注册或仅有账号字段的表单必须提供点选后直接填入用户名字段的随机账号建议；随机值不得读取 Vault、填入密码或自动提交，未选中时不得修改字段，注册成功后的账号保存仍遵循 `REQ-ANDROID-024`。用户名字段可以在“使用 VaultMesh 填充”上方提供独立的本机电话号码建议；VaultMesh 登录候选与通用入口使用应用图标；最近选择及已精确关联账号先展示，随机账号（适用时）、本机号码和通用入口随后展示，其他相关候选排在它们之后。候选行只显示末四位，点选后仍把完整本地号码只填入该用户名字段，不填密码或自动提交。国际格式号码填充时必须去掉国家拨号前缀（例如 `+86`），无法可靠识别前缀时不得提供该号码。SIM 号码只在用户于设置中授予 `READ_PHONE_NUMBERS` 后读取；拒绝权限、无值或格式无效时使用用户手动设置的备用号码。备用号码必须经 Android Keystore 加密存于应用私有且不备份的文件，可以删除；号码不得进入 Vault、非秘密 settings、请求 Intent 或日志。没有有效号码时不得显示建议；Vault 登录项的认证与填充规则保持适用。
- 验收：`CT-ANDROID-AUTOFILL-001`、`CT-ANDROID-AUTOFILL-002`、`CT-ANDROID-AUTOFILL-003`、`AT-ANDROID-023`、`AT-ANDROID-024`。

### REQ-ANDROID-024 Android 登录识别保存

- 必须：登录、注册及修改密码表单的系统 SaveRequest 才可捕获所选用户名/新密码；发现阶段不读取或保留字段现有值。多步表单只能组合相同系统 Autofill 会话、Activity、应用身份与 origin 的上下文，歧义与不一致确认密码必须拒绝。
- 必须：捕获只在特权内存中有界保留 120 秒，系统提示后打开保存确认弹窗。用户可在同一底部弹窗使用主密码、已启用的强生物识别或六位 PIN 授权当前保存请求，再明确新建或选择同账号更新；要求主密码再次验证的已有条目仍须主密码。密码不得显示于普通摘要、Bundle、通知或日志。
- 必须：关联保存在既有加密 Login URL 集合；更新只替换本次用户名/密码与明确关联，保留其他资料与历史。同目标、同账号、同密码的重复保存不得生成重复条目或历史；未知结果不得自动重试。
- 必须：成功提示只能发生在原子写盘完成后；失败保持旧文件/状态，过期、点击弹窗外空白区域、取消、后台、进程终止或锁定清除临时授权和捕获。空密码和超限值必须拒绝。
- 验收：`CT-ANDROID-AUTOFILL-001`、`CT-ANDROID-AUTOFILL-002`、`AT-ANDROID-023`。

### REQ-ANDROID-025 Android 短信验证码自动填充

- 必须：Android 9 及以上、Google Play 服务可用且 VaultMesh 为用户指定的系统 Autofill 服务时，只对明确标识为短信一次性验证码的当前聚焦可编辑字段提供“填充短信验证码”候选。目标应用正在使用自己的 SMS Retriever、用户已拒绝短信验证码授权或服务状态检查失败时不得显示候选；普通密码、TOTP、银行卡和无标签数字字段不得推断为短信验证码。
- 必须：用户点选候选后，非导出 Activity 以不透明、上下居中的等待卡片和应用主题加载环展示进度，经 Google Play SMS Code Autofill API 请求系统授权并等候最近或新收到的验证码；卡片外点击与取消按钮均撤销等待。仅从要求发送方权限的动态接收器接受成功结果，验证码必须有界；仅将验证码作为当前字段的系统 Dataset 交付，不自动提交、不填其他字段。本地 Autofill 不得申请 `READ_SMS` 或 `RECEIVE_SMS`，不得读取整条短信或将验证码写入 Vault、日志、持久化 UI 状态、Intent extras 或登录保存流程。
- 必须：每次候选绑定请求目标包名与当前签名、Activity、HTTPS origin、字段及短期期限，单次消费。取消、超时、后台、签名变化、迟到结果和进程重建必须拒绝并清除请求；不可用设备安全退回无候选。
- 验收：`CT-ANDROID-AUTOFILL-004`、`AT-ANDROID-025`。

### REQ-ANDROID-026 后台设备填充互通

- 必须：已解锁设备页的逐设备设置弹窗提供号码/短信授权与当前设备的手动请求输入，说明锁屏交付和两分钟缓存；页面仅保留全局后台服务开关及状态。首次开启须由用户从可见 Activity 操作“保持设备互通”开关，默认关闭并在本机保存；已启用时，允许在 Vault 锁定、应用冷启动、系统恢复服务及系统用户解锁后的开机通知中恢复已授权互通，划除任务不关闭互通。常驻通知只显示通用状态；关闭开关或通知停止必须保存关闭并立即清除连接和验证码，不得自动重开。系统强制停止不绕过，同步与互通独立。
- 必须：号码复用默认 SIM 与加密备用；用户启用短信互通后可以申请 RECEIVE_SMS，仅处理系统交付的新短信，不申请 READ_SMS、不读历史或发送短信。明确验证码语义且唯一 4–10 位字母数字码才可成为候选，延迟旧短信、歧义数字与普通交易消息必须拒绝。
- 必须：无 Google 服务仍可使用系统允许的接收路径。Android/安装器限制接收时明确提示，并提供绑定当前电脑请求的手动输入/主动粘贴交付；不降低 targetSdk 或申请默认短信身份。既有本地 Google SMS Autofill 授权不得跨设备复用。
- 必须：固定 JNI 不返回 Vault Key、设备私钥或通用执行能力；正文仅短时存在于本机解析过程，号码和 OTP 不进入普通状态、日志、备份或同步。后台锁 Vault 行为保持。锁定恢复必须验证由平台凭据库封存的 Vault/副本绑定及当前密文指纹；记录缺失、损坏、Vault 替换或恢复时封闭失败并提示重新解锁建立恢复记录，恢复记录不得包含解锁凭据。
- 验收：`CT-DEVICE-ASSIST-001`、`CT-DEVICE-ASSIST-002`、`AT-DEVICE-ASSIST-001`。

### REQ-ANDROID-027 新版本提示

- 必须：按 `ADR-0049`，Release 构建从编译期固定的 HTTPS `channels/review/android.json` 读取 Android 更新清单；未配置地址的 Debug/本地构建不得显示或执行检查。检查只在 Activity 前台执行，自动检查每 24 小时最多一次，设置页提供默认开启的自动检查开关与手动“检查更新”。请求不得携带 Cookie、设备标识、Vault 或同步状态，不得跟随重定向，响应超过 64 KiB、超时或格式无效时静默失败（手动检查显示失败）。
- 必须：清单只有 versionCode 基数（去除 ABI 个位）严格高于已安装版本时才提示；客户端按 `Build.SUPPORTED_ABIS` 顺序选择 ABI APK，无匹配时回退 universal。下载地址必须是与清单同 host 的 HTTPS 同版本 immutable 路径和规范文件名，否则视为无效清单。
- 必须：提示框显示新版本、覆盖安装保留数据及 SHA-256，并提供“下载”“稍后”“跳过此版本”；下载只通过系统浏览器打开地址，应用不得下载或安装 APK，不得申请 `REQUEST_INSTALL_PACKAGES`。跳过的 versionCode 与上次检查时间只保存在非秘密偏好中，更高版本出现时重新提示。
- 必须：发布 workflow 在 APK immutable 发布并公网校验后、`latest.json` 之前发布 `android.json`；清单 versionCode 必须严格递增，同版本仅在资产哈希完全一致时允许重发。
- 验收：`CT-ANDROID-UPDATE-001`、`AT-ANDROID-UPDATE-001`。

## Browser

### REQ-BROWSER-001 配对与独立授权

- 必须：扩展通过固定 ID/native host 配对；桌面 unlock 不授权扩展，撤销立即清除浏览器访问。
- 必须：当前 WXT 原插件的 popup 使用 Broker `browser.autofill.candidates` 作为 Login、Secret 与 SSH 当前页建议的权威来源，不得以本地 hostname 猜测替代；无来源字段上下文时不得把全部 card/identity 误标为当前页建议。摘要列表、搜索和类型筛选覆盖完整授权集合，每页最多 25 条；单条与批量删除必须明确区分可恢复条目和永久删除的 Secret/Passkey。
- 必须：当前 WXT popup 打开期间持续读取桌面授权与事件序列；锁定、配对撤销、Host 停止或断连立即清除摘要、候选、编辑页、恢复列表、确认、生成结果与历史，并使迟到响应失效。Login、card、identity、SSH 与 Secret 编辑草稿隐藏时清除且最长保留 5 分钟；恢复码原生文件框只允许既有 45 秒有界例外，不能延长编辑期限。
- 必须：插件必须接受 Broker 发出的 `vault-changed` 事件并在仍获授权时重新读取安全摘要；该事件不得被误判为桌面断连。空闲锁定产生的既有 `vault-locked` 事件在 PIN、主密码或生物识别重新解锁后，不得使已恢复的会话错误地进入断连状态。
- 必须：初始化等待必须区分浏览器权限、桌面状态和登录列表读取；状态与列表读取各自至多等待 10 秒，超时退出初始化并丢弃迟到结果，不得因状态已响应而无限等待列表或宣称主页已就绪。
- 必须：重复点击刷新与后台轮询必须复用同一轮初始化，不得不断使前一轮结果失效；授权失效可以启动新一轮读取，但旧轮次的迟到结果不得覆盖新状态。
- 必须：无变化轮询仍读取桌面授权及事件状态，仅在明确的 background session/revision 与条目数量均未变时复用当前可见 popup 的摘要集合；缺少版本标识、变化、手动刷新和写操作完成后必须重新读取列表。不得跨 popup 关闭保存摘要或以缓存替代授权检查。
- 必须：首次启动、只读初始化、连接权限和用户主动解锁的加载反馈必须即时显示，不人为延迟请求、响应、错误或超时提示。
- 必须：登录及其他类型摘要列表以每页至多 25 条渲染，搜索覆盖当前授权的完整摘要集合，不得截断结果或读取详情；搜索变化回到首页，列表缩短时页码收敛，锁定/断连清除列表和分页状态。Login 展示模型仅为当前页创建，按钮可用性不得逐行重复扫描全量列表。
- 必须：页面路由和历史只留在当前 popup 内存，不改写独立编辑窗口已授权的精确文档 URL，不放宽窗口/tab/URL 校验。切换页面清除离开页的草稿与搜索，丢弃其迟到详情；锁定、断连或关闭 popup 清空瞬态摘要。连接权限仍必须由用户点击申请，不借用桌面解锁授权。
- 必须：首次异步加载后的条目类型筛选区无需滚动或点击即可显示；筛选区无内容或页面加载时必须收起且不保留空白高度，恢复内容时同步恢复显示。
- 验收：`CT-BROWSER-001`、`CT-NATIVE-BROWSER-001`、`AT-BROWSER-001`。

### REQ-BROWSER-002 RPC 策略

- 必须：RPC 请求有版本、大小、认证、关联、过期和防重放；每个操作分类并执行 unlock/gesture/confirmation policy。
- 必须：Broker 仅判断解锁授权时使用 runtime 的轻量授权状态，不得为布尔检查构造各类条目摘要；磁盘变更、撤销、锁定和逐操作权限验证不得被性能优化跳过。
- 验收：`CT-BROWSER-002`。

### REQ-BROWSER-003 插件非秘密偏好持久化

- 必须：生成器结果支持显式插入合格的空目标与桌面受控复制；保持文档/授权/期限绑定、无历史、无自动提交，失败及未知结果不得自动重试。
- 必须：用户明确选择的生成器类型与全部生成参数、插件安全策略和按 origin 记住的
  Login 选择跨 popup 关闭和浏览器重启保留；desktop-owned 安全设置、PIN、生物识别与配对
  继续由 privileged desktop runtime 持久化。
- 必须：插件锁定策略的读取、选择和保存不得被桌面设置读取失败或超时阻塞；仅修改插件策略不得提交未变更的桌面设置。插件策略与桌面设置分别保存时必须明确提示部分成功，不得声称跨所有者原子提交。
- 必须：固定尺寸 popup 内的插件空闲锁定时长、桌面剪贴板清除时长和插件 PIN 失败次数上限必须可选择且明确显示当前选择；剪贴板时长变更只由 desktop runtime 持久化。
- 必须：扩展持久化设置经过 schema 校验；生成结果与历史、搜索/筛选、表单草稿、秘密、
  popup workspace 和授权/确认会话保持瞬态，不得进入 extension storage。
- 验收：`CT-BROWSER-003`。

### REQ-BROWSER-004 跨浏览器扩展打包与分发

- 必须：同一 WXT 扩展源码生成版本一致的 Chrome/Chromium MV3 ZIP 和 Firefox MV2 ZIP；Chrome
  使用固定 manifest key 派生 ID，Firefox 使用固定 `browser_specific_settings.gecko.id`。Review
  本地安装 ZIP 必须显式选择仓库固定的 `sideload-review` 公共身份；商店或正式发布必须提供独立
  Chrome key。构建不得隐式退回其他身份、使用空 Firefox ID、目标不匹配的 manifest 或未检查 ZIP。
- 必须：Firefox manifest 省略 Chromium-only `minimum_chrome_version`、manifest key 和
  `webAuthenticationProxy` permission；Firefox 不提供 Passkey proxy，其他 Browser RPC、瞬态状态、
  secret 最小化、lock/revoke 和 assignment 边界与 Chromium 等价。
- 必须：macOS/Windows 桌面包分别安装 Chrome/Edge `allowed_origins` 与 Firefox
  `allowed_extensions` Native Messaging manifest。Host 必须在读取配对 secret 前验证精确的编译期
  Chrome origin，或精确的 Firefox manifest path 与 Gecko ID；缺失、伪造或混合参数必须拒绝。
- 必须：完整 Review workflow 从同一 source SHA 构建并验证两个扩展 ZIP，并在桌面 R2 发布成功后，
  先把它们发布到同一版本的不可变 R2 `releases/v<version>/` 路径并验证公网下载内容，再与四个桌面
  安装包一起上传到无 Git Tag 的 GitHub Draft Prerelease；扩展 ZIP 不进入桌面 updater manifest，
  重复执行不得覆盖同名不同内容资产。
- 失败：任一浏览器 manifest、版本、identity、permission、ZIP CRC、Native Host 注册或 source SHA
  不一致时不得发布扩展资产；平台 AT 未完成时不得把 Draft 或 ZIP描述为商店签名或正式发布。
- 验收：`CT-BROWSER-PACKAGE-001`、`AT-BROWSER-001`、`AT-BROWSER-FIREFOX-001`。

### REQ-AUTOFILL-001 安全 discovery 与 fill

- 必须：discovery 不发送页面现有值；assignment 绑定 origin/tab/frame/document/handle/expiry；自动填充仅限符合策略的空 login/OTP 字段且不提交表单。
- 必须：页内选择和页面自动填充使用来源 frame 内的短期不透明目标引用，将 discovery 限定到所属表单簇；主密码二次确认不得丢失原目标或覆盖策略。目标过期、移动、失去资格或文档改变时必须拒绝，不得回退全页填充；逐次写入必须继续校验表单归属。
- 必须：自动 discovery 的 mutation burst 合并为 100 毫秒调度，不因连续 mutation 无限延期；collector 忙时只延后发现，不重试已发出的页面写入。已尝试的表单簇必须在整页目标采集前排除；首次 focus 可以等待正在进行的只读 capture 采集，但不得复用过期 DOM 绑定。图标失效必须立即撤下，重建可以短暂合并；同一目标的在途候选读取必须去重。
- 必须：页内填充图标出现后必须为当前短期目标预取只读候选，同一 `targetRef` 的图标点击必须复用在途或已完成读取；点击必须立即展示候选浮层或加载态，不得等待 Broker 往返后才提供视觉反馈。预取结果不得跨字段、导航、失焦或目标期限复用，迟到的 OTP 候选必须清除。
- 必须：自动 Login 填充不读取未使用的 custom-field profile；显式选择的无值 DOM 采集与只读 profile 可以并行，但两者完成后及最终 assignment 前后仍须重验页面和授权。压缩网站注入脚本仍须保持既有字段识别、写入语义与逐动作安全检查。
- 必须：页内图标和菜单按具体字段的可填充类型与角色判定；页面或表单场景不得使无关字段获得图标。搜索、筛选、评论、优惠码、图形验证码、禁用和只读字段不得展示填充图标；字段动态失去资格时必须撤下图标并丢弃迟到候选。支付表单内的个人资料字段必须按其自身类型处理，分段 OTP 不得使同簇无关字段被判为验证码。
- 必须：content script 先在同一真实或最小可见伪表单内识别账号、当前密码、新密码、确认密码和 OTP 字段角色，再按显式字段语义、同表单结构、form action/page path/submit 语义与排除导航链接后的弱上下文依次推导场景；表单外或导航注册链接不得把登录表单识别为注册，密码生成只允许可靠的新密码角色。
- 必须：同页保存 TOTP 后使 OTP 候选重新查询 broker；填充仍使用绑定文档的一次性 assignment，
  不覆盖非空字段且不提交表单。可靠识别为修改密码表单时，用户显式选择 Login 并成功填入当前密码后，
  content script 必须使用本地密码生成器自动生成一次新密码并同步填入同簇的空新密码与确认密码字段；
  已有任一新密码值、低置信度角色、失败 assignment 或非显式/page-load fill 不得触发或覆盖。
- 验收：`CT-AUTOFILL-001`、`CT-AUTOFILL-003`、`CT-AUTHENTICATOR-001`、`AT-AUTOFILL-001`。

### REQ-AUTOFILL-002 显式选择与捕获

- 必须：显式选择经 desktop revalidation 后产生一次性 assignment；捕获只在用户 Save/Ignore 后写入，不把观察到的 submit 当作服务端成功。
- 必须：生成和保存捕获共享真实表单、`form=` 关联或局部伪表单的归属；不得混入相邻表单的账号或生成密码。必须处理可访问 Shadow DOM 内的非 composed submit 与 SPA 提交时同步移除控件；生成后用户编辑的实际密码优先于旧生成值。
- 必须：提交候选观察覆盖 submit、formdata、保存按钮和非输入法组合态的 Enter；观察行为不证明提交成功，且不得读取任意 FormData 附加项。新密码与确认值不一致或确认留空时不得提供密码更新候选。
- 必须：插件从网页识别并经用户确认保存 developer/service secret 时默认关闭主密码二次验证；
  用户可以在保存后显式开启，既有项目保持原设置。
- 必须：TOTP QR 捕获必须由用户在插件 popup 内主动发起；content script 不得自动展示 QR 入口。
  解码结果只加入当前 Login 编辑草稿，不得静默保存、静默覆盖或创建独立 Secret。
- 验收：`CT-AUTOFILL-002`、`CT-AUTHENTICATOR-001`、`AT-AUTOFILL-002`。

### REQ-PASSKEY-001 软件 Passkey

- 必须：旧 BE=0 Passkey 不参与同步且不得改变备份资格；新注册 Passkey 使用 BE=1、counter=0，副本持久化成功后才设置 BS。私钥只经已授权 Rust 同步通道复制，使用仍执行逐次原生确认。

- 必须：Chromium WebAuthn proxy 的 ES256 私钥保存在加密 secret 中，签名在 main 完成，每次 registration/assertion 显示 native confirmation。
- 必须：Passkey 创建或导入使用当前 RP/origin 的默认 Login 作为归属提示，并由 desktop 重新验证；无有效默认值时可以唯一用户名匹配，仍不确定时作为 Passkey-only Login，禁止进入普通 Secret/密钥分类。
- 必须：Chromium 扩展必须在后台启动时即挂载 WebAuthn proxy，并在插件锁定、native 连接重连或桌面端暂时不可达期间保持挂载；此时的 registration/assertion 与平台认证器探测不得绕过 VaultMesh，必须保留请求、打开插件解锁界面并在桌面端可用且解锁后由 VaultMesh 继续。仅当用户在该界面明确选择不解锁时，当前请求以 `NotAllowedError` 结束，proxy 暂时 detach 5 分钟以便网站重试交给浏览器；在此期间解锁则立即重新挂载。页面取消或 5 分钟未完成时请求失败，但不绕过。仅确认未配对时 detach。
- 验收：`CT-PASSKEY-001`、`CT-PASSKEY-002`、`AT-PASSKEY-001`。

## 本地 Agent Capability Broker

### REQ-AGENT-001 本地配对与连接 session

- 必须：用户只可以显式配对当前用户会话中的本地 stdio MCP integration；Agent authorization
  独立于 desktop/browser unlock。每个 stdio 连接任一时刻只关联一个内部短时 session，用于 TTL、配额、重放防护、
  session 内 authority 和资源清理；session 到期必须清除旧 session/pending/resource 并为仍存活、已验证且已配对的 transport
  自动轮换基础 session，不得要求 MCP 客户端重连。明确选择的 connection permission lease 绑定真实 transport，
  不得因内部 session 轮换而清除；真实断连、App 重启、Vault 锁定或撤销必须清除。session 不持久化、不可由用户或 Agent 创建/扩大，也不作为
  另一层产品授权。Vault 锁定必须清除特权 session，但可以保留当前已验证 transport identity；后续 Vault 动作
  必须返回明确的锁定错误，解锁后在同一连接上签发新的基础 session。撤销 pairing 仍必须终止该连接的 authority。
- 必须：首次未配对连接必须主动显示独立、置顶且 content-protected 的系统配对窗口，不得打开主窗口，
  也不得要求用户进入设置或安全中心寻找批准入口。配对只批准本地 integration identity，不要求、创建或
  继承任何 Vault 解锁状态；完成配对后的首个 Vault 调用必须进入独立 MCP 解锁流程。
- 必须：Agent unlock scope 默认 `connection`，每个已配对 stdio connection 拥有独立、不可持久化的 MCP unlock
  lease；用户可以显式切换为 `client`，使相同 OS 用户、client key、protocol epoch 与 Vault namespace 对应的
  已配对客户端并行连接共享一个 memory-only lease。desktop、browser、不同 client 或不同 Vault 已解锁不能创建
  或借用该 lease；共享身份只能由 Rust broker 推导。用户可以在安全中心或当前独立 Agent unlock window 显式切换
  scope；unlock window 只能修改该非秘密 enum。用户只能在独立、置顶、content-protected 且仅具有 Agent unlock
  typed API 的系统窗口中以主密码或 Agent 专用 PIN/biometric 解锁。解锁成功可以在 30 秒内继续同一调用；
  超时后窗口可以保留，但后续必须由显式重试使用新 lease。MCP/IPC 不得存在接收 factor 的 unlock operation。
- 必须：同一 unlock scope 内的并发 Vault 调用必须合并为一个 pending unlock request，单次成功 factor 必须唤醒
  该 request 的全部等待调用；同一窗口已经可见时，重复等待不得反复显示、刷新或抢焦点。已完成 request 不得在
  lease 再次锁定后复用；不同 connection scope owner 仍必须保持独立 request 和 lease。
- 必须：Agent unlock lease 使用独立的空闲自动锁定和最长连续解锁策略。默认分别为 15 分钟和 8 小时，用户
  只能从 5/15/30/60 分钟与 1/4/8 小时/直到关机的有界选项中配置；“直到关机”只关闭绝对截止时间，不持久化
  unlock lease。MCP 活动刷新空闲时限但不得延长有限的最长连续时限。任一适用时限到期必须撤销该连接的 Agent
  authority/resource，最后 lease 到期必须锁定 Agent-only runtime。
  desktop/browser 自动锁定设置不得替代或修改该策略，系统锁定/睡眠、断连、撤销和退出清理不得关闭。
- 必须：`connection` 与 `client` scope 使用相同的空闲、最长连续和强制终止策略。`client` scope 下单条并行
  transport 断开只清理该 transport 的 session/authority/resource；同一客户端最后一条真实 transport 断开时必须
  清除共享 lease。切换 scope 必须立即清除全部 Agent unlock lease 和下游 authority，不得迁移已解锁状态。
- 必须：配对与动作授权必须使用不同的结构化状态和 UI 路由。只有 `pairing-required/approve-pairing` 可以
  打开系统配对窗口；已配对客户端的 permission 与 authorization 必须打开独立、全局置顶、
  content-protected 且仅具有授权 typed API 的系统授权窗口，不得打开或聚焦主窗口，也不得复用配对窗口。
  授权窗口必须预热并在请求产生时立即显示，以进度条展示本次调用剩余的 30 秒等待时间；broker 的实际等待
  到期必须主动通知窗口立即将进度归零并切换为下次调用授权状态；倒计时结束只终止
  本次调用，窗口必须保留并明确显示失败状态，直到用户授权、拒绝或主动关闭。已显示的配对窗口不得因同一
  pending identity 的重复 hello 或工具调用错误而反复聚焦、刷新或重建 WebView。
- 必须：配对窗口只能调用安全状态和当前 pairing approve/deny 的最小 typed API。MCP config
  必须通过 `--client <client-key>` 提供长度和字符受限的稳定、自定义 integration key；Codex、OpenCode 与其他
  本地 MCP client 使用同一流程，不得形成产品枚举或白名单。该 key 是用户批准的本地集成标识，不是经过 MCP
  标准验证的软件品牌，配对窗口必须按原值展示并提示可被同用户进程自报。PID、parent PID、进程创建时间、
  当前路径、binary hash 与 MCP `clientInfo` 只作为当前 IPC 连接校验信息，不得成为持久
  identity 或恢复 pairing 的条件。
- 必须：短生命周期 MCP 探测进程退出后，同一 `client-key` 的待配对申请可以在内存中有界保留至窗口完成
  或 10 分钟到期，同一 key 重连只刷新该申请。批准时若没有当前连接，pairing proof 必须成功持久化，使同一
  OS 用户下使用该 key 的下一次连接直接获得基础 metadata 与权限申请能力。拒绝或关闭窗口必须终止该 key 的当前连接；批准或拒绝的
  命令响应返回后必须立即关闭配对窗口。
- 必须：每次连接必须验证 owner-only IPC peer 与 packaged shim；持久 pairing proof 绑定规范化 client key、
  当前 OS 用户与 protocol epoch 并由 OS 保护。client key、pairing record 或已解锁状态均不直接授予账号操作；
  active session 不跨断连或应用重启恢复。撤销必须删除 proof，使该 key 的下一次连接重新进入配对。
- 必须：VaultMesh 应用重启或 broker IPC 断开不得要求重启仍存活的 stdio MCP shim。Shim 必须使用原稳定
  client key 重新连接并握手，broker 必须把它作为全新 transport 签发新基础 session；只可复用仍有效的 pairing
  proof 与持久授权，不得恢复旧 unlock lease、connection permission、pending、continuation 或资源。请求帧未完整
  送达时可以用同一 request ID 重送；完整送达后响应丢失时只允许自动重放 R0 幂等操作，R1–R4 必须返回 typed
  `execution-unknown`，要求先检查目标状态，禁止静默重复执行。
- 验收：`CT-AGENT-PROTOCOL-001`、`CT-AGENT-AUTH-001`、`CT-AGENT-UNLOCK-001`、
  `CT-AGENT-LIFECYCLE-001`、`AT-AGENT-PAIRING-001`、`AT-AGENT-UNLOCK-001`。

### REQ-AGENT-002 动作级 MCP 能力

- 必须：Agent 只可以通过稳定公共工具 schema 查询非秘密 capability/account metadata 并调用 Agent 专项 Spec
  穷举的动作工具；不得存在 secret getter、通用 shell/curl/DOM、Vault dump、unlock 或 reveal/copy/export 等价能力。
- 必须：`vaultmesh_accounts_list` 在已解锁 Vault 上以有界 cursor 分页返回 Login、SSH account 与
  developer/service secret 的 opaque ID、类型和用户标签；不得返回 username、URL、host、scope、notes 或
  任何受保护字段。内部 ConnectorDefinition 的存在性、来源与 ID 不得进入 discovery；结果只发布账号可用的
  semantic capability 与命名 action/tool 映射。
- 必须：MCP 可以稳定声明 Agent 专项 Spec 穷举的公共工具 schema，但工具可见性不得被解释为授权；每次
  `tools/call` 必须继续以当前 pairing/session/account/permission/policy fail closed，授权变化不得依赖
  Codex/OpenCode 重启。
- 必须：MCP stdio shim 只负责 framing 与 owner-only IPC forwarding，不得打开 Vault、拥有策略或持有秘密。
- 必须：除本地 UI 请求外，所有 MCP tool 都必须先通过当前连接自己的 MCP unlock lease；MCP 不提供 session
  状态查询或锁定操作，解锁、锁定和 lease 清理由 VaultMesh 软件控制，且不得锁定 desktop、browser 或其他
  MCP client。
- 验收：`CT-AGENT-PROTOCOL-001`、`CT-AGENT-SECRET-001`、`CT-AGENT-UNLOCK-001`。

### REQ-AGENT-003 账号、目标与请求绑定

- 必须：每次调用绑定已配对 client key、当前 connection session、opaque account reference、capability、精确 target、
  canonical request 与 expiry；unknown、歧义、漂移、重放、过期和参数替换全部 fail closed。
- 必须：多账号按 exact reference、唯一候选确认、原生 picker、拒绝的固定顺序选择；
  Agent 自报 label 或模型推断不能选择生产账号。
- 必须：Agent Profile、Profile permission rule、Profile CRUD 与 format-2 兼容读取不得存在。只有 managed-web
  recipe 与 SSH tunnel endpoint 可以保存在 Rust-owned internal ConnectorDefinition 中；该记录不拥有账号、
  credential 或 client permission，也不通过 MCP/renderer 暴露。所有 Vault 必须统一写入 format 4；format 3 仅由 desktop 主密码验证的迁移入口读取，兼容规则由 NFR-COMPAT-001 所有。
- 验收：`CT-AGENT-POLICY-001`、`CT-AGENT-ACCOUNT-001`。

### REQ-AGENT-004 SSH 动作

- 必须：Rust SSH adapter 可以按 exact SSH Vault item 执行 non-PTY exec、SFTP、公钥安装和显式启用的 PTY/tunnel，
  并逐次执行 host identity、命令/路径、风险、输出配额与生命周期策略。
- 必须：Agent 可以提交受限 OpenSSH alias，请求 Rust broker 为 exact SSH Vault item 生成专属 ED25519
  密钥、把生成的密钥自动保存为软件内 SSH key 记录、安装公钥、验证新密钥登录并写入 VaultMesh 管理的
  本机 SSH config fragment。alias/account/target/Host Key 绑定必须由加密 Vault 记录拥有，本地不得保存
  `manifest.json`。软件必须在生成的 SSH key 信息卡片上独立显示 `ssh <alias>`，并在编辑表单中以只读字段
  显示 alias；修改普通名称不得改变 alias，公私钥不得在普通表单中替换或清除。Agent 不得提交或获得
  host、username、port、算法、私钥、公钥原文或本地路径；既有 alias、key、config、symlink、target 或
  Host Key 冲突必须拒绝且不得覆盖。该动作属于 R3 exact-only，每次执行必须由原生授权窗口明确提示它会建立
  不再受 VaultMesh 逐命令 Action Lease 控制的持久本机 OpenSSH authority。
- 必须：密码、私钥和 passphrase 不进入 shell、PTY、argv、环境或临时 identity 文件；`sudo` 不自动输入密码。
- 验收：`CT-AGENT-SSH-001`、`CT-AGENT-PTY-001`、`AT-AGENT-SSH-001`。

### REQ-AGENT-005 认证 HTTP 动作

- 必须：`access-token` Secret item 是 authenticated HTTP 的唯一 account/credential owner；其 exact HTTP(S)
  `website` 固定 canonical origin 与可选 base path。Agent 只能提交公共 schema 允许的 uppercase method、相对
  base path 的精确 absolute path、有界 query/JSON body 与 `status/json` response mode，不得提交完整 URL、origin、
  Authorization/header policy、redirect policy、通配符、risk、显示文案或 credential。HTTP/access-token 不得创建、
  读取或要求 AgentProfile/ConnectorDefinition。
- 必须：Broker 必须只解析并 canonicalize path 一次，拒绝 dot segment、反斜线、控制字符、encoded separator/dot、
  scheme-relative/absolute URL、query/fragment 混入与 base-path escape；Canonical ActionPlan 必须绑定 Secret item、
  origin/base path、method、canonical path/query/body digest、response mode、risk、target digest 与 matcher revision，
  executor 在 secret use 前重新读取 item 并逐字段比较。Token 值轮换不得改变 target identity；kind、website、
  base path 漂移必须回到 Ask。
- 必须：Rust HTTP adapter 在内部注入 Bearer，并对每次请求执行 exact origin、当次 DNS 解析固定、header、redirect、
  size、JSON reconstruction 与 secret-canary policy；credential 不跨 origin。Adapter 不得因 HTTP scheme、
  public/private/loopback/link-local/metadata 地址类别或 HTTPS 证书错误拒绝账户 exact `website`，也不得引入
  `EndpointTrust`、private-host allowlist 或 certificate pin 作为额外账户配置。初版不得开放任意 header、raw text、
  HTML、binary 或 redirect；`status` 必须丢弃 body，`json` 必须在有界重建后返回且授权 UI 明确业务响应会提供给 Agent。
- 必须：method 定义风险下限：`GET/HEAD=R1`、`POST=R2`、`PUT/PATCH=R3`、`DELETE=R4`；typed
  credential 或 destructive action 可以提高风险，不得降低 method floor。
- 验收：`CT-AGENT-HTTP-001`、`CT-AGENT-HTTP-PATH-001`、`AT-AGENT-HTTP-001`。

### REQ-AGENT-006 隔离 managed web

- 必须：Agent 只能操作 VaultMesh-owned、per-account 隔离浏览器 session 中批准的 navigate/extract/action
  recipe；credential fill/login submit 是 broker-owned 原子阶段。
- 必须：Agent 不得读取密码、Cookie/storage/header、raw DOM/CDP、任意 selector 或跨 account session。
- 验收：`CT-AGENT-WEB-001`、`AT-AGENT-WEB-001`。

### REQ-AGENT-007 固定 CLI connector（已移除）

状态：Removed by `CHG-2026-020` before release。固定 CLI 代理不再是当前 Required 能力；相关数据模型、
公共工具和执行链全部删除。Agent 应使用类型化 SSH、HTTP、
managed web 或 protected-action 工具完成受支持的任务。

### REQ-AGENT-008 受保护认证动作

- 必须：TOTP、Email OTP、recovery code 与 Passkey 只通过绑定 target 的
  fill/submit/sign 动作消费，返回状态或公共协议结果，不返回秘密值。
- 必须：Passkey 请求只能由 broker 在绑定 managed-web session 内从批准 recipe 捕获；Agent 只接收绑定
  client/account/managed-web session/origin/operation/expiry 的单次 opaque requestRef，不能提交或读取 request、
  challenge、RP/origin 或页面 completion channel；公共响应必须由 broker 直接交回同一目标页。
- 必须：recovery code 只在远端成功证据后原子标记 consumed。
- 必须：Broker 不得公开生成、测试、轮换或撤销凭据的专用 Agent 工具，也不得接受 managed/control credential、
  apply/test/rollback 或 revoke/restore transaction descriptor。凭据 CRUD、生成、轮换和撤销只由本地 UI 拥有；
  普通受认证 HTTP 动作不构成凭据生命周期事务。既有开发 Vault 中的 revoked/needs-review 内部标记只能继续
  fail closed，不能恢复为 Agent 可用 authority。
- 验收：`CT-AGENT-AUTHN-001`、`AT-AGENT-AUTHN-001`。

### REQ-AGENT-009 动态权限申请与持久裁决（Superseded by REQ-AGENT-010/011）

状态：Superseded before release。旧的独立权限申请、第二账号配置和 memory-only compatibility bridge 已删除，
没有读取或迁移路径。当前行为完全由 `REQ-AGENT-010/011`、`ADR-0009` 与 `ADR-0012` 拥有；
`CT-AGENT-PERMISSION-001`、`AT-AGENT-PERMISSION-001` 仅保留为 retired historical Test ID。

### REQ-AGENT-010 账号搜索与直接动作授权

- 必须：`vaultmesh_accounts_list` 必须提供有界搜索、类型/能力/环境筛选与 cursor 分页；搜索只使用
  label、kind、environment、favorite、tag 等非秘密索引。结果只返回 opaque `accountRef`、label、kind、
  environment、可用 semantic capability 与命名 action/risk/tool 安全摘要，不得返回 username、host、URL、
  notes、target、selector、binary path、command body 或凭据。内置 Vault item action 与内部 ConnectorDefinition
  必须使用同一目录投影，Agent 不需要知道二者来源。`capabilities[]` 必须使用 `ssh-exec` 等公共语义能力名，
  `actions[].tools` 必须使用 `vaultmesh_ssh_exec` 等实际工具名；未知能力必须明确拒绝，不得静默返回空目录。
- 必须：账号发现不得依赖既有动作授权，也不得暴露或筛选 Ask/Allow/Deny 等授权状态；授权只能在 Agent 选定
  exact `accountRef` 并调用动作工具后裁决。存在兼容动作的账号必须在未预授权时仍可发现。
- 必须：Agent 获取 exact `accountRef` 后必须直接调用 SSH、HTTP、Web 或 protected-action 工具；不得先
  调用独立 permission tool，也不需要创建、选择或理解内部 definition。Broker 必须从 Vault item、内置规则或内部
  typed internal definition 编译不可变 Canonical ActionPlan；HTTP/access-token 必须直接从 Secret 与当前 method/path
  编译计划。所有动作在取用 secret 前完成 account、target、capability、
  canonical parameters、risk、expiry 与 permission 裁决。
- 必须：Ask 发生时，broker 必须让原始工具调用等待最多 30 秒；用户在独立授权窗口允许后，broker 必须以同一
  request ID 和不可变 ActionPlan 内部继续调用，不要求 Agent 重试。权限窗口必须显示 broker 生成的风险、账号、目标、
  工具类型与动作摘要；R0 自动通过硬策略，R1–R4 在该窗口完成当前动作的显式 Allow 与权限裁决，不得再打开第二个 action confirmation 窗口。
  拒绝、关窗或 30 秒超时必须终止本次等待并返回稳定的 denied/timeout 错误。Permission challenge 在 connection session
  内继续保留，用户超时后选择 once、connection 或 persistent Allow 必须作用于后续显式重试；其中 once 只允许下一次匹配
  调用执行一次。R2/R3 即使存在 connection 或 persistent permission lease，每次具体执行仍必须复用该窗口取得
  exact action 的一次性执行票据；R4 Allow 只允许 exact + once，persistent Deny 仍可用。
- 必须：每条 stdio connection 只有一个 broker-owned connection session。MCP shim 不得在每次工具调用前轮询
  session snapshot 或自行解释 allowed tool；它对每次 MCP 调用只构造一个带稳定 request ID 的工具请求，除
  `REQ-AGENT-001` 定义的未完整送达重送和 R0 transport-safe 重放外不得复制调用。Broker 按已验证 connection
  绑定 session 并权威 fail closed。授权变化不得要求 tools/list 重新发现或客户端重启。
- 验收：`CT-AGENT-DISCOVERY-002`、`CT-AGENT-AUTHZ-002`、`CT-AGENT-AUTHZ-003`、`AT-AGENT-AUTHZ-002`。

### REQ-AGENT-011 类型化 Action Lease 与 SSH 命令范围

- 必须：授权规则统一绑定 client key、Vault namespace、opaque account、精确 target identity、capability、typed
  action predicate、risk ceiling、policy revision、effect 与 lifetime。Predicate 至少支持 exact canonical action、版本化 action
  class 与 capability 内所有结构化动作；lifetime 支持 once、connection 与 persistent；effect 支持 Allow/Deny。
  Once 必须原子消费；connection lease 绑定真实 Agent transport，内部 15 分钟防重放 session 轮换不得清除它，
  但真实 disconnect、App restart、revoke 或 final lock 必须清除；持久规则损坏或存储不可用
  必须解释为 Ask。若用户在本次调用 30 秒等待结束后签发 once Allow，该 lease 必须由下一次匹配调用消费。
- 必须：SSH exec 直接引用 SSH Vault item，不创建第二账号配置。命令必须使用结构化 program + arguments；
  target、Host Key、credential、risk 与 output policy 由 broker 构建。权限 UI 必须显著显示 R0–R4 风险、工具类型、
  当前目标和 broker 生成的动作摘要；SSH 命令使用等宽 Markdown code-block 风格展示。UI 必须支持当前命令、安全命令目录、
  所有结构化命令三个范围，以及允许一次、当前连接、始终允许、拒绝本次、当前连接拒绝、始终拒绝；Allow 按风险等级使用明显不同的颜色，
  但颜色不得改变 scope、duration、deny、target 或 policy 语义。R1 默认推荐 safe + connection；R3 只提供 exact scope，
  R4 Allow 只提供 exact + once。R2/R3 每次执行仍在同一窗口 fresh confirm，任何风险等级都不得再创建独立 action confirmation；Agent 不能选择
  scope、target、risk 或显示文案。
- 必须：安全命令由版本化机器可读 catalog 的 executable 与参数 grammar 判定，禁止 shell operator、redirect、
  substitution、通用解释器、sudo/su、网络转发、环境/历史输出和修改型参数。Catalog 变化必须使既有 safe Allow
  回到 Ask。所谓安全只表示低风险结构化语法，不保证远端 binary 或业务输出绝对可信。
- 必须：persistent all-command 只授予 exact SSH account/Host Key 下的 exec capability，不授予 PTY、tunnel、
  upload 或其他工具，也不能绕过 risk ceiling、destructive enablement 或 adapter hard policy。HTTP/Web 使用同一 lease engine，
  但 managed-web recipe/selector 继续由不拥有 account、credential 或 client permission 的内部
  ConnectorDefinition 提供；HTTP method/path 直接来自当前 Agent request 与 access-token Secret target。
- 必须：HTTP permission 使用版本化 typed `http-path-v1` predicate，并绑定 exact account、canonical origin/base path、
  exact method、response mode 与 matcher revision。Agent 调用只能提交精确 path；只有原生授权 UI 可以从当前 canonical
  path 生成 exact request、exact path、完整 segment `*` 或 terminal `**` pattern。Method 不串权，任一匹配 Deny
  优先；R1 可以记住 path pattern，R2/R3 可以记住 permission scope 但每次 canonical request 仍 fresh confirm，
  R4 Allow 只允许 exact + once。Pattern grammar/normalization 变化必须使旧规则回到 Ask。
- 必须：Web permission predicate 必须同时绑定 exact canonical origin、账号与命名 recipe；“此网站此能力”
  不能扩展到其他 origin、capability 或任意 selector。Upload/download 的 exact scope 表示当前有界传输，
  connection/persistent 仍只记住同账号、同 target、同 capability 的 permission，不授予文件系统路径或原始 bytes 访问。
- 必须：持久授权使用 OS-protected random key 与 AEAD owner-only local store；AAD 绑定 protocol epoch、Vault
  canonical-path namespace 与当前 OS 用户。Vault 移动、key/file 缺失、损坏、身份漂移或解密失败统一回到 Ask。
  撤销 pairing 必须删除对应 client 的持久规则。
- 验收：`CT-AGENT-AUTHZ-002`、`CT-AGENT-AUTHZ-003`、`CT-AGENT-SSH-SAFE-001`、`AT-AGENT-AUTHZ-002`。

## Email OTP

### REQ-EMAIL-001 Provider 授权与只读访问

- 必须：Gmail/Outlook 使用 OAuth API，其他 Provider 使用 TLS read-only IMAP；Token/app password 保存在加密内部记录中。
- 必须：Gmail 只请求 `gmail.readonly`，通过 Gmail Profile 获取邮箱地址，并在保存账户前拒绝未实际授予该 scope 的部分授权；不得把身份 Sign-In scope 成功误判为 Gmail 读取授权成功。
- 验收：`CT-EMAIL-001`、`AT-EMAIL-001`。

### REQ-EMAIL-002 候选生命周期

- 必须：增量 cursor、短时 boost、dedup 和 expiry 由 main 管理；最后授权锁定后清除连接和候选。
- 必须：受信任的网页获取/重发验证码点击立即检查一次，并启动或刷新 90 秒、3 秒间隔的高频监听；超时后回到普通轮询，导航、锁定或 final lock 停止对应监听。
- 必须：验证码提取支持 4–8 位、至少包含一个数字的 ASCII 字母数字 token，保留原始大小写和完整 token 边界；反向上下文不得跨越品牌名或无关字母数字文本形成候选。
- 验收：`CT-EMAIL-002`、`AT-EMAIL-002`。

### REQ-EMAIL-003 浏览器候选与填充

- 必须：独立解锁的插件 popup 或 OTP 字段页内图标可以在任意 HTTP(S) 网站展示全部未过期邮箱验证码候选，不得按当前网站与发件域名过滤；Provider credential、邮件正文、收件地址、subject 和 message ID 不得进入 Browser RPC。
- 必须：用户显式选择候选后，desktop 必须重验 origin、candidate、expiry 和 discovery，并只返回绑定 tab/frame/document/handle/expiry 的单次 assignment；只填空 OTP 字段且不提交表单。
- 必须：popup/页内候选关闭、导航、断开、锁定、撤销、失败、成功或过期清除插件侧候选/assignment；验证码不得进入 extension storage、通知正文、日志、audit 或持久化 UI state。
- 验收：`CT-EMAIL-003`、`AT-EMAIL-003`。

## 非功能需求

### NFR-REL-001 原子持久化

- 必须：所有 Vault mutation 在加密文件提交成功后才发布新状态；失败恢复旧状态。
- 验收：`CT-REL-001`、`CT-NATIVE-VAULT-001`、`CT-AUTHENTICATOR-001`。

### NFR-COMPAT-001 版本兼容

- 必须：未知 Vault/RPC 版本 fail closed；兼容字段使用明确 default；版本变化具备迁移和回滚策略。
- 必须：Vault 只创建和写入 format 4。format 3 仅允许 desktop 主密码驱动的受控升级，升级前必须保存原加密备份，失败保留旧文件；所有其他版本在 KDF 前拒绝。Agent、Browser 与 quick unlock 不执行迁移，旧客户端必须拒绝 format 4。 PIN/指纹遇到旧格式时必须明确提示先在桌面使用主密码升级，不得仅显示通用操作失败；升级后原 Vault Key 对应的快速解锁必须继续有效。
- 必须：备份恢复轮换副本 epoch 与 Vault 同步绑定身份、清除同步授权，重新授权后才同步。升级回退仅通过升级前备份，不包含升级后的修改；所有 mutation 与 backup/restore 保持原子提交和失败回滚。
- 验收：`CT-COMPAT-001`、`CT-AGENT-ACCOUNT-001`。

### NFR-PRIV-001 秘密最小化

- 必须：秘密不进入日志、telemetry、crash data、扩展 storage、非秘密 settings 或测试 snapshot。
- 必须：popup 主动识别的 TOTP URI 只能在当前 popup 编辑状态和既有特权更新调用中短暂存在；
  不得建立 background inline capture session，关闭 popup、锁定、断开、取消、失败或保存完成必须清除。
- 验收：`CT-PRIV-001`、`CT-NATIVE-MEMORY-001`、`CT-AUTHENTICATOR-001`、`CT-RECOVERY-CODES-001`、`AT-NATIVE-MACOS-002`。

### NFR-AGENT-001 Agent 边界秘密最小化

- 必须：凭据及其可逆表示不进入 MCP/IPC response、stdout/stderr、日志、audit、crash、snapshot、普通
  child environment、命令行、Agent 可读临时状态或 managed browser 可导出状态。
- 必须：Agent 业务结果由 typed schema、字段/PII policy、secret canary、大小和速率限制重新构造；失败不得回退 raw output。
- 验收：`CT-AGENT-SECRET-001`、`CT-AGENT-AUDIT-001`、`CT-AGENT-CODEX-001`、
  `CT-AGENT-OPENCODE-001`、`AT-AGENT-MACOS-001`、`AT-AGENT-WINDOWS-001`。

### NFR-AGENT-002 Agent 资源终止清理

- 必须：revoke、final lock、disconnect、cancel、timeout、process exit、broker shutdown 和 expiry 先阻断新请求，
  再有界取消/关闭 session、confirmation、continuation、SSH/PTY、HTTP、browser、child process 与敏感 buffer；重复清理幂等。
- 必须：真实 transport disconnect、pairing revoke、系统锁定/睡眠、应用退出与显式 MCP lock 清除对应 unlock
  lease；client-shared scope 下，单条并行 transport disconnect 清理自身 authority，最后一条同身份 transport
  disconnect 才清除共享 lease。最后一个 Agent unlock lease 消失时必须锁定 Agent-only runtime。内部 15 分钟 connection session 透明
  轮换不得继承旧 action authority，也不得误清除仍有效的同一 transport unlock lease。Agent 空闲时限或配置的
  有限最长连续解锁时限到期必须按 client 清除 lease、authority、continuation 与子资源；执行中的动作不计为空闲，
  但不得绕过有限最长连续解锁时限。“直到关机”不得绕过本节的任何强制清理事件。
- 验收：`CT-AGENT-LIFECYCLE-001`、`CT-AGENT-UNLOCK-001`、`CT-AGENT-CODEX-001`、`CT-AGENT-OPENCODE-001`、
  `AT-AGENT-MACOS-001`、`AT-AGENT-WINDOWS-001`。
