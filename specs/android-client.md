# Android 客户端规格

## 当前范围

Android 客户端是 `CHG-2026-047` 推进中的 Partial surface。当前切片是 Compose 前台应用通过 Kotlin/JNI 创建、解锁、读取状态、锁定和轮换本地 Vault 主密码，并在解锁后管理 Login、Payment card、SSH credential、Identity 与 Developer/service secret；Login、Card、SSH 和 Identity 使用各自的加密回收站及历史。`CHG-2026-049` 增加受保护字段的用户主动复制，`CHG-2026-051` 增加 Login TOTP，`CHG-2026-052` 增加 format 4 加密备份/恢复，`CHG-2026-053` 增加密码健康，`CHG-2026-061` 与 `CHG-2026-062` 增加生物识别/PIN 快捷解锁。用户已选择后续继续追齐适用桌面能力，Agent 工作流除外；系统 Autofill 与识别保存由 REQ-ANDROID-023/024 接入；Credential Manager、Passkey 与其他导入仍未接入，LAN 同步由 REQ-ANDROID-022 定义；发布仍需平台验收。format 3 升级按当前兼容规格只由 desktop 主密码入口执行，Android 保持拒绝。

当前构建基线为 minSdk 26、compileSdk/targetSdk 37 与 NDK 28.2；这些是首切片的可构建基线，不构成正式发布设备范围承诺，调整时必须保持本规格的 lifecycle、安全与真机 Gate。

Debug application ID 必须使用 `.debug` 后缀，与产品 application ID 的文件、偏好和签名空间隔离；真机开发不得以清除或覆盖产品应用数据作为 fresh-install 手段。

解锁后的首页使用 Material 3 保险库布局，顶栏必须使用系统状态栏 Insets 避让状态栏内容：顶部水平标签为全部、登录、卡片、身份、SSH 与密钥，类别页保留适用回收站；底部导航为保险库、工具、设备、设置。全部页只聚合当前已加载的脱敏摘要，不以没有实际访问时间的数据声称“最近使用”。新增入口按类型打开现有编辑器。全部页与类型页的条目行直接显示复制和更多入口：复制菜单只列已有字段，受保护值继续逐次主密码复验；更多菜单放编辑、查看、历史和删除等适用操作。当前可见条目可以逐项选择、全选、取消和批量删除，删除先确认并逐项使用对应固定操作，任一项失败即停止并刷新以显示部分完成；Secret 永久删除须在确认时告知，桌面托管的 SSH alias 不参与选择或删除。工具页按生成器、密码健康和备份恢复分组，设置页按系统自动填充与解锁安全分组，入口仍调用现有能力。附近设备配对位于设备。切换底部页面或锁定时必须清除查询和临时条目状态；所有页面继续通过固定 JNI operation 执行原有授权操作。

保险库“全部”、各类型和回收站列表先展示最多 30 条脱敏摘要，滚动接近底部时每次再追加最多 30 条并在末尾显示加载提示。搜索、类型或条目/回收站切换重置到首批；全选只覆盖已展示且允许选择的条目。分页仅控制当前前台的列表展示，现有固定 JNI 列表读取与本地搜索继续覆盖完整安全摘要集合。

## 组件与所有权

`apps/android` 拥有 Compose UI、ViewModel、Activity/Application lifecycle、`FLAG_SECURE`、应用私有路径和 Android Manifest。它不得复制 Vault 数据模型、解析 envelope、持有 Vault Key 或保存解锁状态。

`crates/vault-android-runtime` 拥有唯一进程内 session、原子文件提交、固定 JNI operation 和稳定错误映射。`crates/vault-core` 继续唯一拥有密码学、format 4、payload、mutation 与 zeroize。JNI 不得返回文件内容、内部路径、KDF 参数或 Rust 地址；受保护值只可经已授权的固定复制、查看或系统自动填充操作有界返回相应 Kotlin 特权处理器。

## Vault lifecycle 操作

- `initialize(path)`：只接受 Kotlin 从 `filesDir` 构造的固定 Vault 路径；重复初始化同一路径幂等，不同路径先锁定旧 session 后替换。
- `status()`：只返回 `missing`、`locked` 或 `unlocked`。
- `create(masterPassword)`：目标已存在时拒绝；创建 format 4 空 Vault并原子提交，提交成功后保持当前进程解锁。
- `unlock(masterPassword)`：读取有界 Vault 文件，以 core 验证并建立 session；错误密码、损坏或未知格式不改变旧状态。
- `lock()`：清除当前 session，重复调用成功。
- `changeMasterPassword(current, next)`：仅当前会话已解锁时可调用，先用旧密码从当前磁盘 Vault 建立候选 session；core 验证旧密码并重新包装 header，原子写盘成功后才替换当前 session。失败时旧文件和当前会话保持有效；Kotlin 不接收 Vault Key、header 或文件字节。

创建与主密码解锁提交期间，锁定页仅在相应按钮内部显示有界进度环和状态文字，并保持按钮尺寸稳定。普通状态刷新和其他快捷解锁操作不得触发该按钮的进度动画；操作完成、失败或生命周期锁定后必须清除提交态。

PIN 提交或生物识别系统验证成功后，Compose 在打开保险库期间显示“正在打开保险库…”及进度动画；创建或任一解锁方式验证成功后，在固定 JNI 读取各类型脱敏摘要期间改为“正在加载保险库条目…”。摘要完成前不展示空列表或列表操作；失败或进入后台时清除加载状态。生物识别系统弹窗前不显示自定义页面，主密码验证阶段仍只显示按钮内的提交进度。

系统权限弹窗导致 `onPause` 时仍清除解锁会话、输入及临时状态。权限允许、拒绝或隐藏后，即使只有 `onResume` 而没有 `onStart`，也必须重新读取 PIN 可用状态并恢复锁定页；读取失败降级为主密码输入。同一次可见前台停留已尝试过自动生物识别时，暂停恢复必须显示 PIN 或主密码，不得再次自动弹窗或停留在空白等待态；真正停止后重新进入才开始下一次自动尝试。迟到的生物识别回调不得清理新会话的认证状态。

## 生物识别快捷解锁

用户在主密码解锁后明确启用时，固定 `prepareBiometricUnlock()` 由 Rust/core 生成随机 32 字节包装秘密，以 XChaCha20-Poly1305 和独立随机 nonce 包装当前 Vault Key，并原子写入有界应用私有记录。JNI 返回的只是包装秘密，Kotlin 不得持有 Vault Key、主密码或 core handle。Android Keystore 创建 AES-GCM 密钥，配置逐次 `BIOMETRIC_STRONG` 认证和注册变化失效；`BiometricPrompt.CryptoObject` 成功后将包装秘密加密到应用私有封存记录。包装秘密不进入 Compose 状态、日志或 Android backup。

本机封存记录和 Keystore alias 同时存在且 Vault 锁定时，每次进入前台直接请求一次系统 `BiometricPrompt.CryptoObject`，底层不显示自定义生物识别页。同一次前台停留中取消或失败不重复自动请求；用户可从其他解锁方式手动重试。系统选择符合 `BIOMETRIC_STRONG` 的指纹或面容等已录入方式。授权后解密封存记录，固定 `unlockWithBiometricSecret(secret)` 在 Rust 验证包装记录、解密 Vault Key 并由 core 验证当前磁盘 Vault，成功后才替换会话。失败、取消、后台化、注册变化、文件损坏或迟到响应保持锁定；取消后优先显示可用 PIN 页面，否则显示主密码页，并始终允许切换到主密码。`disableBiometricUnlock()` 删除 Rust 包装记录，Kotlin 同时删除本地封存与 Keystore alias；恢复其他 Vault 后需要重新启用。

PIN 设置只接受两次一致的六位数字。Kotlin 生成独立随机设备秘密，用应用私有 Android Keystore AES-GCM key 封存；固定 `enablePinUnlock(pin, deviceSecret)` 由 Rust 以 scrypt 派生包装密钥、加密当前 Vault Key 并原子写入与生物识别分离的记录。`pinStatus()` 仅返回启用和剩余次数，Kotlin 同时确认本机封存可用才显示 PIN 页面。锁定 UI 一次只显示 PIN 键盘或主密码输入，不并排展示两者；其他解锁方式通过选择器切换。PIN 键盘只显示六个遮蔽进度点，第六位输入后提交并立即清空草稿。固定 `unlockWithPin` 在错误时先原子增加失败次数，五次后拒绝 PIN 并切换到主密码；成功时 core 验证当前磁盘 Vault 后才发布会话。主密码成功解锁重置计数；关闭时 `disablePinUnlock()` 与 Kotlin 本地封存都删除。PIN 和设备秘密只作短时输入，不进入持久 UI state、日志或 backup。

## Login CRUD 操作

- `listLogins()`：只返回 ID、标题、用户名、URL 和 `hasPassword`；不得包含密码、notes、TOTP、恢复码或 custom field 值。
- `addLogin(title, username, password, url)`：标题不能为空；成功时创建 Login 并原子提交 Vault。
- `updateLogin(id, title, username, password, replacePassword, url)`：兼容旧基础操作；`replacePassword=false` 时保留原密码且不读取原值，core 中其他字段必须完整保留。
- `deleteLogin(id)`：只在 Compose 二次确认后调用，沿用 core 的加密回收站，不直接永久清除。
- `listTrash()`：只返回 trash/item ID、标题、用户名和删除时间，不读取密码或其他受保护字段。
- `restoreLogin(trashId)`：从加密回收站恢复条目，不向 Kotlin 返回条目秘密。
- `purgeLogin(trashId)` 与 `emptyTrash()`：分别在 Compose 明确确认后永久清除单项或全部 Login 回收站及适用历史。

列表使用固定 operation 的有界 JSON DTO，不构成通用 method router。所有 mutation 在写盘失败时必须恢复调用前 payload，且不得显示成功或自动重试。

Login 常规补充字段仅在用户明确打开编辑器时通过固定 `loginEditorDetail(id)` 读取，包含附加网址、自定义字段、备注、文件夹、收藏与填充/复验策略，不含密码、TOTP seed 或恢复码。`addLoginComplete`、`updateLoginComplete` 把基础与严格有界补充字段在单次 core mutation 中提交；更新留空密码、未触碰的 TOTP seed 与恢复码由 core 保留。取消、切换、锁定和迟到详情清除草稿，旧基础操作保留兼容。

## 其他 Item 类型

- Card：固定操作支持安全摘要列表、完整字段创建/编辑/删除和 Card 回收站。摘要只能包含标题、持卡人、掩码卡号、到期信息及安全码/PIN 存在性。编辑不读取完整卡号、安全码或 PIN；留空保留原秘密，明确清除安全码/PIN 时不得同时替换。
- SSH：固定操作支持安全摘要列表、主机/端口/用户名、密码/公钥/私钥/口令与补充字段的创建/替换/明确清除、删除和 SSH 回收站。摘要只含认证值存在性，不含认证值。由桌面管理的 OpenSSH alias 在 Android 只读，不得绕过其外部配置所有权。
- Identity：固定操作支持摘要列表、完整资料创建与编辑、删除和 Identity 回收站。编辑时由固定操作按用户动作读取完整资料；多值邮箱/电话/地址及其 ID、标签和首选标志必须随更新保留。
- Developer/service secret：固定操作支持安全摘要列表、kind、服务商、账号、秘密值与补充字段的创建/替换及不可恢复删除。编辑留空保留原值；core 中内部 lifecycle Scope 必须保留。Passkey 记录不得进入 Android 普通 Secret 列表或 mutation。

四类搜索只读取 Kotlin 当前解锁进程持有的安全摘要，不新增搜索 JNI。各类型列表、编辑草稿与确认状态必须在后台/锁定时清除；可恢复类型的永久删除及清空、Secret 的不可恢复删除均须先由 Compose 显式确认。基础管理操作不读取这些类型的受保护值；复制只由下述独立特权切片执行。

卡片完整编辑在用户明确打开编辑器时以固定 `cardEditorDetail(id)` 读取发卡机构、卡组织、账单地址、备注、文件夹、收藏和主密码复验设置；响应不含完整卡号、安全码或 PIN。Compose 新建/编辑使用固定 `addCardComplete`、`updateCardComplete`，基础字段与严格类型化的有界补充字段在同一次 core mutation 中原子提交。旧基础操作保留兼容。编辑留空卡号保留旧值，安全码/PIN 的明确清除与替换互斥；取消、切换、锁定和迟到详情清除补充字段草稿。

普通服务密钥的固定 `secretEditorDetail(id)` 仅在明确编辑时返回环境、Scopes、到期日、网站、备注、文件夹、收藏和主密码复验设置，不返回密钥值，并拒绝 Passkey。`addSecretComplete`、`updateSecretComplete` 把基础与有界、严格类型化的补充字段在单次 core mutation 中提交；更新空值保留原秘密与类型。core 继续保存内部生命周期 Scope 并拒绝用户伪造，Kotlin 不复制内部标记；取消、切换、锁定和迟到详情清除草稿。旧基础操作保留兼容。

普通 SSH 凭据的固定 `sshEditorDetail(id)` 仅在明确编辑时返回备注、文件夹、收藏和主密码复验设置，不返回密码、公钥、私钥或口令，并拒绝桌面托管 alias。`addSshComplete`、`updateSshComplete` 将基础与有界、严格类型化的补充字段在单次 core mutation 中提交；空认证值保留原秘密，明确清除与替换互斥。取消、切换、锁定和迟到详情清除草稿；旧基础操作保留兼容。

Identity 的固定 `identityEditorDetail(id)` 仅在明确编辑时返回完整结构化个人资料，普通列表继续只含安全摘要。`addIdentityComplete`、`updateIdentityComplete` 使用有界、严格类型化 JSON，在单次 core mutation 中提交，保留多值邮箱、电话、地址的稳定 ID 与首选标志；core 验证日期、邮箱、网址、地址及首选约束。取消、切换、锁定和迟到详情清除草稿；旧基础操作保留兼容。

## 受保护字段复制

用户在已解锁页面选择具体条目和字段后必须重新输入当前主密码。固定字段 JNI operation 仅返回该字段的有界值或封闭错误码；普通 Secret 操作不得复制 Passkey。Kotlin 特权剪贴板服务接收值并写入系统剪贴板，标记 `ClipDescription.EXTRA_IS_SENSITIVE`，以非秘密标签追踪本应用 clip。30 秒后只有确认仍为本应用 clip 时才清除；用户后续复制的其他内容不得被清空。锁定、后台化或迟到结果不得写入剪贴板。主密码在提交前从 Compose 状态清空，值不得进入列表、持久化状态、日志或分析。该切片不授权通用 reveal、Autofill 或 Credential Manager。

## 受保护字段查看

用户显式选择字段并重新输入主密码后，查看复用已有按字段固定 JNI 访问。可查看 Login 密码、Card 卡号/安全码/PIN、SSH 密码/公钥/私钥/口令和普通 Secret 值；Passkey、缺失字段和错误密码拒绝，TOTP 当前代码只走即时复制。响应值只留在当前前台弹窗，不进入剪贴板、普通列表或持久状态；30 秒后自动关闭，用户关闭、切换、后台化、锁定及迟到响应立即清除。长值按需分块呈现，Activity 保持 `FLAG_SECURE`。

## 条目历史

Login、Card、SSH、Identity 各有固定历史列表、恢复版本与清空历史操作；Secret 无此入口。列表只返回 core 投影的版本 ID、标题、非秘密副标题和保存时间，不预读旧秘密。恢复同时绑定当前条目与版本，core 验证归属并保留当前版本；清空只作用于当前条目。桌面管理的 SSH alias 在 Android 不可恢复或清空历史。Compose 对恢复和清空分别确认，切换、关闭、后台或锁定后清除历史列表与确认；迟到结果不得重新打开。所有历史 mutation 复用原子提交和失败回滚。

## Login TOTP

现有 Login 的固定设置操作接收 Base32 seed 或受 core 支持的 `otpauth://totp` URI，可替换或明确移除；core 归一化密钥并原子提交。普通列表只增添 `hasTotpSecret`，不得返回 seed 或当前代码。复制当前代码是独立固定操作：core 重新验证主密码，使用当前系统时间生成 6 位代码，再经 Kotlin 特权服务写入 sensitive 剪贴板。Compose 替换/移除须明示，提交前清除 seed 草稿；取消、失败、锁定、后台化与迟到结果不得保留 seed 或复制代码。设备时钟差异与代码自然过期由真机验收，不以剪贴板 30 秒清除期限表示代码仍有效。

## Login 恢复码

`listLogins` 仅附加 `hasRecoveryCodes` 存在性。`setLoginRecoveryCodes(id, input, clear)` 是固定 mutation：输入最多 32 KiB，普通文本每非空行一个恢复码；完整 Google 编号双栏文本按编号排序。每项最多 256 UTF-16 单元，总数最多 100；明确清除与替换互斥。core 更新保持其他 Login 字段并复用原子提交和回滚。

`viewLoginRecoveryCodes(id, masterPassword)` 每次由 core 验证主密码，返回有界列表至当前前台弹窗；`copyLoginRecoveryCode(id, index, masterPassword)` 再次验证并只返回单码至 Kotlin 特权剪贴板。列表、普通编辑、历史摘要均不得包含值。弹窗关闭、导航、锁定或后台化必须解除引用，迟到结果不得重新显示。

系统 `OpenDocument` 仅保存当前 Activity 中的一次性 `content:` URI；选择器触发锁定后，用户重新解锁才可读取最多 32 KiB 的 UTF-8 内容到内存草稿，不创建明文文件。导入内容原样保存成功后可以另行确认删除源文件；Kotlin 删除前复读比对 SHA-256 并检查 `FLAG_SUPPORTS_DELETE`，提供者不支持、内容改变或失败均保留源文件。URI、摘要与删除确认不会跨进程持久化。

## 加密备份与恢复

Rust 在用户解锁后通过固定 `prepareEncryptedBackup` 把当前加密 format 4 envelope 写到 `filesDir/vaultmesh-backup-export.vault`。系统 `CreateDocument` 返回 `content:` URI 后，Kotlin 只复制密文；提供者写入关闭后必须重新读取并比对密文摘要。文件选择使 Activity 后台化并锁定，不保留解密 session。取消、失败、完成和下次启动清理 staging；提供者最终云同步不属于本机成功判定。

`OpenDocument` 选择的 `content:` URI 只可有界读取到 `filesDir/vaultmesh-backup-import.vault`，中间写入通过私有 partial 文件同目录原子替换。用户明确确认替换并输入备份主密码；固定 `restoreStagedBackup` 用 core 验证 format 4，重置同步 epoch/授权并 checkpoint，随后原子写盘并发布新 session。错误密码或写盘失败保留旧 Vault，允许用户重新输入密码；锁定、取消和启动清理 staging。format 3 文件封闭拒绝，升级按 `NFR-COMPAT-001` 仅由 desktop 主密码入口执行。

## 密码健康

用户主动打开时，固定 `passwordHealth` JNI 在解锁会话内调用 core 当前健康算法，仅返回分数与弱、重复、过期 Login 的 ID。Kotlin 用当前安全摘要匹配标题，列表按需渲染；不得接收密码、哈希或中间值。关闭、切换、后台或锁定清除报告，迟到结果不得重新打开。

## 凭据生成器

Kotlin 生成器使用 `SecureRandom`，沿用桌面端的密码小写/大写/数字/符号字符池及每个选中类至少一位、长度不超过 128 的规则；用户名为小写字母开头、后续小写或数字，长度 6–64；邮箱别名先校验并标准化域名。结果仅保留在当前弹窗，可以显式复制到 sensitive 剪贴板或填入当前 Login 编辑草稿；关闭、导航、后台或锁定清除，不保存生成历史，也不自动提交 Login。

Login 与各类型搜索只对 Compose 当前持有的脱敏摘要执行，不增加 JNI operation。查询切换页面时清空，且随后台锁定和 ViewModel 敏感状态一起丢弃。

create、unlock、list 与所有 Item mutation 必须在 Compose 主线程之外执行；lifecycle lock 可以同步执行以先于后台展示清除授权。Kotlin 在调用结束或失败后清空密码输入；编辑草稿与解密列表在取消、锁定或后台切换时清除，不得把它们放入 `SavedStateHandle`、Bundle、日志、异常文本或 analytics。后台切换后到达的异步结果必须按 lifecycle generation 失效，并再次锁定 runtime，不得重新发布解锁状态或 DTO。

## Lifecycle 与平台策略

主 Activity 在 `super.onCreate` 后、绘制敏感内容前设置 `FLAG_SECURE`。应用进入 `ON_PAUSE` 时同步失效前台回调并调用 lock；`ON_STOP` 再执行幂等锁定，覆盖快速离开后立即返回或异常生命周期顺序。UI 重新进入前台后重新读取 status，不通过 saved state 恢复数据。进程冷启动必须从 locked/missing 开始。

Manifest 必须设置 `allowBackup=false`、`fullBackupContent=false`、`dataExtractionRules` 拒绝 cloud/device-transfer、`usesCleartextTraffic=false`；除生物识别所需权限外，仅前台 LAN 配对可声明 `INTERNET`、网络状态、Wi-Fi 多播和 Android 17 `ACCESS_LOCAL_NETWORK`，不得声明外部存储权限。系统 Autofill 服务及按请求包名验证签名的可见性由 REQ-ANDROID-023/024 授权；后台 LAN 服务由 REQ-ANDROID-022 授权。

## Android 与桌面局域网配对

Android 附近设备页面复用独立 Rust LAN protocol 2.0 实现，与 desktop 直接互相发现、输入当前对方六码并经 TLS 内 PAKE 完成双向信任。Kotlin 只负责 Android Keystore 封存凭据包装密钥、本地网络运行时权限、Wi-Fi 多播锁、Activity 生命周期和安全状态 UI；固定 JNI 只返回本机短期六码、opaque peer ref、状态和本机标签。设备私钥、证书、公钥、指纹、地址、nonce、PAKE 帧和 Vault Key 不得进入 Compose。底部“设备”页必须直接读取并展示已配对列表与空态，不得放入入口弹窗或以开启发现为读取前提；每行更多按钮直接打开该设备的设置弹窗，集中展示同步与互通配置和重命名/撤销入口；读取失败必须支持重新加载。发现和配对操作位于列表下方；配对网络只能在用户显式开启的十分钟窗口运行，暂停、锁定、离页、权限或 Wi-Fi 失效必须停止并清理。Android 17 target 37 在开始前请求 `ACCESS_LOCAL_NETWORK`，系统权限页导致暂停时保持锁定，用户重新解锁后再次显式开启。新配对与撤销经 core 原子修改当前 Vault 的同步授权，独立同步服务按 REQ-ANDROID-022 运行。

设备 UI 必须以列表展示已配对与附近设备，已配对行的更多菜单打开重命名或撤销确认；配对码输入使用单一 Material 3 弹窗，显示同步授权说明。配对中必须显示进度并禁止重复提交；用户停止配对时调用现有停止发现操作。异步状态中的已保存信任是成功反馈的依据，不得以 `lanBegin` 返回已接受提前显示成功。错误码、认证、连接、身份变化和存储失败必须以已有安全状态映射为文案；次数耗尽禁止继续提交。发现到期或设备消失清空配对输入，重命名/撤销失败保留确认上下文；离页、锁定、后台化仍清空全部临时状态。列表读取中、空列表、读取失败和发现网络错误必须分别呈现，发现网络错误不隐藏可用的已配对列表。

## 错误与日志

JNI 只返回 `ok`、`not_initialized`、`already_exists`、`missing`、`locked`、`unlock_failed`、`invalid_vault` 或 `io_error` 等稳定 code；LAN 启动失败可细分为不含端点的监听、发现、扫描和身份存储 code。公开 message 不包含底层错误、路径、输入长度或加密参数。Rust 与 Kotlin 不记录 operation 参数。

## 验收

Host Rust 测试覆盖 create、拒绝覆盖、unlock、wrong password、lock、重新构造 runtime、损坏文件、各类型 CRUD/适用回收站与历史持久化、秘密与元数据保留及 mutation 回滚、快捷解锁错误秘密/失败限制/禁用/写入失败；contract 测试扫描 JNI、脱敏 DTO、本地搜索、破坏性确认、Manifest、Compose 编辑、Kotlin lifecycle 与 Keystore 边界。Android target 编译覆盖 arm64 与 x86_64；`AT-ANDROID-001` 至 `AT-ANDROID-020` 必须在 arm64 真机执行。

## Android LAN 同步

Android 同步遵循 `specs/lan-vault-sync.md`，Kotlin connectedDevice 服务拥有网络权限、多播资源和通用通知，Rust 平台适配器复用共享 transport/cache 与 core。服务只由可见 Activity 启动，扫描与服务使用独立生命周期；Activity 暂停仍锁定 Vault。任务移除/用户停止不自动重启；系统暂停期间不保证实时送达，网络恢复后补齐。现有配对的同步授权可由用户显式开启升级，双方解锁建立方向通道。冲突摘要不得含标题或正文。

## 系统自动填充与识别保存

短信验证码执行 `REQ-ANDROID-025` 与 `ADR-0046`。仅 Android 9 及以上用户指定的 Autofill 服务通过 Google Play SMS Code Autofill API 在明确的当前聚焦短信验证码字段显示候选；不把无标签数字框推断为验证码。服务先检查目标应用自己的 SMS Retriever 请求及 VaultMesh 的授权状态。用户点选后由非导出 Activity 执行系统授权、等待 Google Play 服务的受发送方权限保护的结果，并只向原字段交付一次性 Dataset。验证码不经过 Vault 解锁、登录保存、电话候选或持久化状态，取消、后台与超时清除请求。无 Google Play 服务或被拒绝授权时不显示候选。

执行 `REQ-ANDROID-023/024` 与 `ADR-0040/0041`。Autofill 服务只接收系统授权请求，认证页与捕获容器均不可外部直接调用；PendingIntent 单次使用且只带随机请求 ID。填充与保存认证及后续账号选择使用同一底部弹窗，保留系统调用方背景；可使用主密码、已启用的强生物识别或六位 PIN。标题采用“VaultMesh · 应用名称”，包名与可选 HTTPS origin 位于标题区，搜索框直接位于标题区下方；搜索框聚焦时弹窗扩展到键盘上方的可用区域，列表回到顶部并保持可见。输入停顿 450 毫秒后自动筛选，两次后端查询至少间隔 600 毫秒。相同查询和重复输入事件不重复调用 JNI，本次请求内少量最近查询可复用脱敏结果，旧查询结果不得覆盖新输入；请求结束后清除缓存。认证区一次只显示一种输入方式，生物识别直接弹系统提示，取消后在弹窗内切换 PIN 或主密码。认证采用独立短时 Rust session，不使主界面变为 unlocked。生物识别与 PIN 复用主界面的 Keystore 包装秘密和失败次数约束，但只生成当前请求的授权；已有条目要求再次验证主密码时，必须回到主密码方式。主密码在提交时从输入状态清除，仅在 Rust 授权内为当前条目策略保留至消费/失效。

候选与显式应用关联执行 `ADR-0042`。当前目标成功选择过的账号按最近一次优先排列，弹窗中分为“最近使用”和“其他账号”卡片；其余候选依次为精确包名/签名/origin 关联、表单 HTTPS origin 精确匹配的网站账号、应用包名片段或显示名称与标题或 HTTPS 主机标签相近的“可能相关”账号。认证后的账号、密码选择列表及返回给系统的填充结果均以用户名为主标签，网址或标题只作次级说明；用户名为空时回退到标题。选择历史仅在 Android 私有加密记录中保存目标与条目 ID，不含用户名或密码，也不改变关联或授权状态。后两类相似建议不构成信任证明，必须显示目标并确认；用户可选择仅本次填充或原子写盘后记住当前应用绑定。绑定成功前不交付 Dataset，取消、失败、超时或磁盘变化不得留下关联或交付凭据。

锁定态系统下拉候选执行 `ADR-0044`。前台已解锁列表或当次授权后的候选更新 Keystore AES-GCM 加密的私有不备份预览，只保存有界 ID、用户名、标题和 HTTPS 主机，并绑定当前加密 Vault 的 SHA-256；无效时退回通用入口。当前包签名/origin、应用名称相似性和加密选择历史仅筛出最多五条显示，具体候选各绑定一次性请求和用户名成对或仅密码填充范围。点选后先授权，再重新查询并由 Rust 检验目标与条目；未关联条目额外确认，要求主密码复验的条目仍使用主密码。同一请求已有未消费授权时可直接填充；新请求不得复用授权。

系统下拉框的每条 `RemoteViews` 使用紧凑行内布局：VaultMesh 登录候选与通用入口使用应用图标，账号候选以用户名为主行、标题为次行，标题等于当前包名时显示应用名称；用户名与密码字段的通用入口均标为“使用 VaultMesh 填充”；最近选择和已精确关联账号先展示，随后是随机账号建议（可识别且账号字段可填文本的注册或仅有账号字段的表单）、本机号码建议（仅用户名字段）和通用入口，其他相关候选最后展示。随机账号使用系统安全随机源生成，只在点选后填入用户名字段，不读取 Vault、不填密码或自动提交。电话号码行使用电话图标，预览只显示末四位，实际 Dataset 保持完整有效号码。外层弹窗和可见行数仍由 Android 系统控制，通用入口无法固定在滚动区域之外。

本机号码建议执行 `ADR-0043`；QQ 注册页的无提示纯数字手机号字段按 `ADR-0045` 的精确包名、Activity、唯一字段、输入类型和长度守卫识别。该数字字段只提供手机号与通用入口，不显示字母随机用户名或独立保存提示。系统 Autofill 表单含用户名字段时，在最近选择及已关联账号之后、VaultMesh 通用入口之前添加独立电话号码 Dataset，只关联用户名 `AutofillId`；用户点选后才填入，密码字段不参与。填充国际格式号码时借助 Android 电话格式化规则识别并去掉国家拨号前缀，不能可靠拆分时不提供该号码。设置页主动申请 `READ_PHONE_NUMBERS` 后，API 33+ 从默认订阅读取，旧版从默认电话线读取；SIM 无值、权限拒绝或格式不合格时使用用户手动设置的备用号码。备用号码仅存 Android Keystore AES-GCM 加密的私有不备份文件，可在设置中删除；服务读取时无需解锁 Vault。号码不进入登录项、请求 Bundle 或持久化普通设置。

用户名栏的认证候选可以填入同一登录项的用户名与密码；密码栏使用独立的密码候选，认证结果只含密码 `AutofillId`，不得覆盖此前填入的用户名。点击底部弹窗上方空白区域、显式取消或返回时撤销旧请求与临时授权，并用新的单次认证请求返回等价系统候选；取消本身不填任何字段。弹窗内容区域的点击与滚动不得取消请求。保存请求取消仍保持不保存。

系统新建的 Login 条目默认与普通新建 Login 一样不要求额外主密码验证；用户之后在编辑页启用该保护时，填充与更新保存均需主密码。

结构解析优先使用 autofillHints/HTML autocomplete，再使用输入类型与资源名/hint；仅当表单恰有两个可编辑字段、一个已明确识别为密码且前一个是同 origin、无标签、普通文本 AutoCompleteTextView 时，才把后者推断为用户名。最多 2048 节点、64 层、64 个输入字段、8 个上下文。字段必须来自同一目标，优先聚焦表单；多密码只能明确区分当前、新建和确认字段，其他歧义拒绝。发现不读取值，SaveRequest 读取最多 256 字符用户名和 4096 字符密码，并验证确认密码。username-only 步骤可通过系统上下文参与后续保存，不能跨系统会话、Activity 或 origin 组合。

设置页通过系统选择器启用服务。API 28+ 使用 SaveCallback 的认证 IntentSender；API 26/27 在系统保存请求后启动同一确认 Activity。本切片使用系统下拉候选入口，支持提供标准 Autofill 结构的应用和浏览器；不提供无障碍抓取或不支持 Autofill 的页面保证。已填充值交付后的秘密所有权转移给 Android 系统及用户确认的目标应用。

## 已配对设备填充互通

REQ-DEVICE-ASSIST-001 / REQ-ANDROID-026 与 [独立互通规格](../specs/device-fill-assist.md) 定义逐设备一次授权、锁屏号码/短信交付及短时秘密生命周期。既有禁止 RECEIVE_SMS 的条款限于手机本地 Autofill；独立互通服务仅在用户主动启用后可以请求 RECEIVE_SMS，不使用 READ_SMS。短信正文仅本机瞬态解析，验证码不进入 Vault、备份、日志、同步或普通 DTO。系统限制自动读取时使用显式手动交付。
