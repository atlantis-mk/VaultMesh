# ADR-0049：Android 新版本提示

- 状态：Accepted
- 日期：2026-09-27
- 关联 Work：`CHG-2026-075-android-update-notice`
- 关闭 OPEN：无

## 背景

`ADR-0048` 让 Review 发布产出签名的多 ABI APK，但 Android 客户端不知道新版本何时可用。桌面由 Tauri updater 读取 `channels/review/latest.json`；Android 没有对应机制。应用内下载安装需要 `REQUEST_INSTALL_PACKAGES`，这是密码管理器不必要的敏感能力，并阻碍日后上架应用商店。系统在覆盖安装时已强制签名证书一致，篡改 APK 无法替换现有安装。

## 决策

用户于 2026-09-27 选择“仅提示、系统下载安装”：

- 发布 workflow 必须生成独立的 `channels/review/android.json`，包含版本、versionCode 基数、各 ABI APK 的 URL、SHA-256、字节数与签名证书 SHA-256；它在 APK immutable 发布与公网校验之后、`latest.json` 之前发布，versionCode 严格递增，同版本只允许哈希完全一致的重发。
- Android Release 构建编译期固定该 HTTPS 地址；Debug 与未配置地址的构建不检查更新。检查只在前台执行，自动检查每 24 小时最多一次且可关闭，也可以手动检查。请求不携带 Cookie 或任何设备/Vault 信息，不跟随重定向，响应上限 64 KiB。
- 客户端只接受同 host HTTPS、同版本 `releases/v<version>/` 路径与规范文件名的地址，并按设备 ABI 选择 APK。提示只能用系统浏览器打开地址；应用不得下载、解析或安装 APK，不得申请 `REQUEST_INSTALL_PACKAGES`。
- 检查更新是 `INTERNET` 权限在 LAN 之外的唯一新增用途，不得扩展为遥测或其他联网功能。

## 原因

- 签名一致性由系统保证，应用内安装的安全增益很小，却会新增敏感权限与大量失败路径。
- 最小联网面：一个固定 GET、无身份、仅前台，可以直接审查。

## 后果

- 升级需要用户在浏览器下载并确认系统安装，体验弱于静默更新。
- 清单被篡改最多诱导打开同 host 的其他 immutable 地址；签名不同的 APK 仍无法覆盖安装。
- 新增一个发布对象与 JVM/contract 测试；真机验收使用 `AT-ANDROID-UPDATE-001`。

## 被拒方案

- 应用内下载并调用 PackageInstaller：需要敏感权限且与商店政策冲突；当不上架商店且用户规模需要静默升级时重新评估。
- 复用桌面 `latest.json`：其 platform 语义属于 Tauri updater，混入 APK 会破坏 updater 契约。
- 后台定时检查：需要 WorkManager 与后台联网，超出最小范围。

## 验证

`CT-ANDROID-UPDATE-001`、`AT-ANDROID-UPDATE-001`。
