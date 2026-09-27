# ADR-0026：Android Login TOTP 密钥与当前代码

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-051-android-login-totp`
- 关闭 OPEN：无

## 背景

Android Login 基础编辑保留既有 TOTP 密钥，但没有设置与使用入口。把密钥或完整 Login detail 返回 Kotlin 会扩大长期秘密暴露面。

## 决策

- Login 安全摘要只增加 `hasTotpSecret`。设置与移除使用固定 JNI mutation，core 归一化 Base32 或默认配置的 `otpauth://totp` URI；修改其他 Login 字段时保留未替换的密码、恢复码、URI、自定义字段和策略。
- 当前验证码使用独立固定 JNI operation：先由 core 重新验证当次主密码，再按 Rust runtime 当前系统时间调用 core 生成代码；密钥不返回 Kotlin。Kotlin 特权剪贴板服务沿用 sensitive 标记与仅清理本应用 clip 的期限。
- Compose 设置草稿只在当前会话存在，提交前移除密钥输入。移除或替换在 UI 明示；锁定、后台化和迟到结果不得提交或复制。

## 原因

core 是密钥归一化与算法的唯一所有者。固定操作把长期密钥输入和短期代码输出分开审核，复用 Android 已建立的原子提交及剪贴板所有权边界。

## 后果

设备时钟偏差会影响验证码有效性；复制到剪贴板的代码可能在系统清除前自然过期。真机验收须检查系统时间、后台与到期行为。此决策不授权 QR 自动扫描或 Android Autofill。

## 被拒方案

- 返回 TOTP seed 让 Kotlin 生成代码：复制算法和长期秘密所有权。
- 在普通 Login 列表中预生成代码：扩大瞬态秘密持有面。

## 验证

`CT-ANDROID-JNI-008`、`AT-ANDROID-008` 与 `GATE-3A`。
