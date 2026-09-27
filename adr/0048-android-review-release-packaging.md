# ADR-0048：Android Review 多 ABI 打包与 CI 签名

- 状态：Accepted
- 日期：2026-09-27
- 关联 Work：`CHG-2026-074-android-review-release`
- 关闭 OPEN：无

## 背景

Review 发布此前只产出 macOS/Windows 安装包与浏览器扩展，Android 只能本地构建 Debug APK。Android 设备同时存在 64 位 ARM、32 位 ARM 与 x86_64 模拟器；单一 APK 会携带所有 ABI 的 Rust runtime，体积翻倍。发布 APK 还需要长期稳定的签名证书，否则后续版本无法覆盖安装并保留 Vault 数据。

## 决策

用户于 2026-09-27 选择按 ABI 拆分并新增 32 位 armeabi-v7a，且使用 CI Secret 签名：

- Release 构建必须编译 armeabi-v7a、arm64-v8a、x86_64 三个 Rust JNI target，并输出三个单 ABI APK 与一个 universal APK；依赖自带但没有 Rust runtime 的 ABI（例如 32 位 x86）不得打入 APK。Debug 构建保持单一 APK 与 arm64/x86_64。
- versionName 必须等于 Review SemVer；versionCode 必须由 `major.minor.patch` 与 Review 迭代号单调派生，Review 低于同版本 Stable，个位固定区分 universal/ABI。
- 所有 Review APK 必须由存放在 GitHub Secrets 的同一 release keystore 签名；keystore 只在 runner 临时目录以 0600 权限存在并在 job 结束时删除，不得提交、上传为 artifact 或写入日志。证书 SHA-256 必须作为仓库变量固定，构建脚本逐个 APK 校验单证书一致且匹配。
- 缺少签名配置、指纹不匹配、ABI 或版本漂移时发布必须 fail closed。

## 原因

- 拆分 APK 让用户只下载所需 ABI；universal APK 提供不确定设备 ABI 时的回退。
- 固定证书指纹防止 Secret 被替换后悄悄更换签名身份，保证侧载升级连续性。
- 个位区分 ABI 使同一版本各 APK 可共存于分发渠道且不会降低 versionCode。

## 后果

- 新增 armv7 Rust target 与 32 位运行面；host 测试只覆盖 64 位，32 位行为必须由 `AT-ANDROID-RELEASE-001` 在真实设备或兼容环境验收。
- release keystore 丢失将无法为既有安装提供覆盖升级；必须离线备份 keystore 与密码。更换签名需要新 ADR 与明确的重装迁移说明。
- Review workflow 新增 Android job，其失败会阻止 R2 publish 与 Draft Prerelease。

## 被拒方案

- 只发布 universal APK：体积大，且无法按 ABI 分发；设备容量或流量受限时重新评估。
- Debug key 签名：签名身份不稳定，无法支撑版本连续升级。
- AAB：侧载 Review 不需要，待接入应用商店时重新评估。

## 验证

`CT-ANDROID-RELEASE-001`、`CT-UPDATE-REVIEW-001` 与 `AT-ANDROID-RELEASE-001`。
