# Android 客户端规格

## 当前范围

Android 客户端是 `CHG-2026-047` 推进中的 Partial surface。当前切片是 Compose 前台应用通过 Kotlin/JNI 创建、解锁、读取状态和锁定本地 Vault，并在解锁后管理、搜索基础 Login 字段及处理 Login 回收站。Autofill、Credential Manager、Passkey、quick unlock、外部文件、后台服务、LAN 同步与发布不属于当前切片。

当前构建基线为 minSdk 26、compileSdk/targetSdk 37 与 NDK 28.2；这些是首切片的可构建基线，不构成正式发布设备范围承诺，调整时必须保持本规格的 lifecycle、安全与真机 Gate。

Debug application ID 必须使用 `.debug` 后缀，与产品 application ID 的文件、偏好和签名空间隔离；真机开发不得以清除或覆盖产品应用数据作为 fresh-install 手段。

## 组件与所有权

`apps/android` 拥有 Compose UI、ViewModel、Activity/Application lifecycle、`FLAG_SECURE`、应用私有路径和 Android Manifest。它不得复制 Vault 数据模型、解析 envelope、持有 Vault Key 或保存解锁状态。

`crates/vault-android-runtime` 拥有唯一进程内 session、原子文件提交、固定 JNI operation 和稳定错误映射。`crates/vault-core` 继续唯一拥有密码学、format 4、payload、mutation 与 zeroize。JNI 不得返回文件内容、内部路径、KDF 参数、受保护值或 Rust 地址。

## Vault lifecycle 操作

- `initialize(path)`：只接受 Kotlin 从 `filesDir` 构造的固定 Vault 路径；重复初始化同一路径幂等，不同路径先锁定旧 session 后替换。
- `status()`：只返回 `missing`、`locked` 或 `unlocked`。
- `create(masterPassword)`：目标已存在时拒绝；创建 format 4 空 Vault并原子提交，提交成功后保持当前进程解锁。
- `unlock(masterPassword)`：读取有界 Vault 文件，以 core 验证并建立 session；错误密码、损坏或未知格式不改变旧状态。
- `lock()`：清除当前 session，重复调用成功。

## Login CRUD 操作

- `listLogins()`：只返回 ID、标题、用户名、URL 和 `hasPassword`；不得包含密码、notes、TOTP、恢复码或 custom field 值。
- `addLogin(title, username, password, url)`：标题不能为空；成功时创建 Login 并原子提交 Vault。
- `updateLogin(id, title, username, password, replacePassword, url)`：`replacePassword=false` 时保留原密码且不读取原值；当前 UI 只修改基础字段，core 中其他字段必须完整保留。
- `deleteLogin(id)`：只在 Compose 二次确认后调用，沿用 core 的加密回收站，不直接永久清除。
- `listTrash()`：只返回 trash/item ID、标题、用户名和删除时间，不读取密码或其他受保护字段。
- `restoreLogin(trashId)`：从加密回收站恢复条目，不向 Kotlin 返回条目秘密。
- `purgeLogin(trashId)` 与 `emptyTrash()`：分别在 Compose 明确确认后永久清除单项或全部 Login 回收站及适用历史。

列表使用固定 operation 的有界 JSON DTO，不构成通用 method router。所有 mutation 在写盘失败时必须恢复调用前 payload，且不得显示成功或自动重试。

搜索只对 Compose 当前持有的脱敏 Login/回收站摘要执行，不增加 JNI operation。查询切换页面时清空，且随后台锁定和 ViewModel 敏感状态一起丢弃。

create、unlock、list 与 Login mutation 必须在 Compose 主线程之外执行；lifecycle lock 可以同步执行以先于后台展示清除授权。Kotlin 在调用结束或失败后清空密码输入；编辑草稿与解密列表在取消、锁定或后台切换时清除，不得把它们放入 `SavedStateHandle`、Bundle、日志、异常文本或 analytics。后台切换后到达的异步结果必须按 lifecycle generation 失效，并再次锁定 runtime，不得重新发布解锁状态或 DTO。

## Lifecycle 与平台策略

主 Activity 在 `super.onCreate` 后、绘制敏感内容前设置 `FLAG_SECURE`。应用进入 `ON_STOP` 时调用 lock；UI 重新进入前台后重新读取 status，不通过 saved state 恢复数据。进程冷启动必须从 locked/missing 开始。

Manifest 必须设置 `allowBackup=false`、`fullBackupContent=false`、`dataExtractionRules` 拒绝 cloud/device-transfer、`usesCleartextTraffic=false`，且当前切片不得声明 `INTERNET`、外部存储、biometric 或后台 service 权限。

## 错误与日志

JNI 只返回 `ok`、`not_initialized`、`already_exists`、`missing`、`locked`、`unlock_failed`、`invalid_vault` 或 `io_error` 等稳定 code。公开 message 不包含底层错误、路径、输入长度或加密参数。Rust 与 Kotlin 不记录 operation 参数。

## 验收

Host Rust 测试覆盖 create、拒绝覆盖、unlock、wrong password、lock、重新构造 runtime、损坏文件、Login CRUD/回收站持久化和 mutation 回滚；contract 测试扫描 JNI、脱敏 DTO、本地搜索、破坏性确认、Manifest、Compose 编辑与 Kotlin lifecycle。Android target 编译覆盖 arm64 与 x86_64；`AT-ANDROID-001`、`AT-ANDROID-002` 与 `AT-ANDROID-003` 必须在 arm64 真机执行。
