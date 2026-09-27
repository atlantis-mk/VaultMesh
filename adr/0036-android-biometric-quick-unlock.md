# ADR-0036：Android 生物识别快捷解锁的双层包装

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-061-android-biometric-quick-unlock`
- 关闭 OPEN：无

## 背景

Android 要在锁定后使用系统强生物识别解锁现有 format 4 Vault。Kotlin 负责系统认证和 Keystore，`vault-core` 继续拥有 Vault Key 与解锁会话。

## 决策

- 已解锁且用户明确启用时，Rust 生成一次性随机包装秘密，以 XChaCha20-Poly1305 包装当前 Vault Key，并原子保存有界私有记录。固定 JNI 只短时返回随机包装秘密，不返回 Vault Key、core 对象或长期 handle。
- Kotlin 用仅限 `BIOMETRIC_STRONG`、逐次认证且随生物识别注册变化失效的 Android Keystore AES-GCM 密钥封存包装秘密。启用和解锁都由 `BiometricPrompt.CryptoObject` 完成认证；本地封存记录写入 app-private 文件，Android backup 排除应用数据。
- 解锁时 Kotlin 只把认证后恢复的包装秘密传入固定 JNI。Rust 先验证包装记录并解密 Vault Key，再由 core 验证当前磁盘 Vault；成功后才发布 session。取消、错误、注册变化、文件损坏、锁定或后台化均封闭失败，主密码始终可用。
- 关闭功能删除 Kotlin 封存记录/Keystore alias 与 Rust 包装记录。恢复不同 Vault 后旧包装不能解开新 Vault；用户应重新启用。

## 原因

系统认证只保护随机包装秘密，core 保持 Vault Key 与 Vault 格式的唯一所有权。逐次认证避免把系统生物识别结果当作可重用布尔授权。

## 后果

启用和解锁期间包装秘密会短时经过 JNI/Java 字符串，必须只在 Activity/IO 操作局部持有并尽快解除引用；无法像 Rust 缓冲区一样保证 Java 字符串归零。丢失 Keystore 密钥后只能以主密码解锁并重新启用。

## 被拒方案

- 把 Vault Key 或主密码直接存入 Keystore：扩大秘密所有权边界。
- 仅检查生物识别成功回调后直接解锁：回调结果不是密钥解封操作。
- 允许设备凭据代替强生物识别：超出本切片的认证策略。

## 验证

`CT-ANDROID-JNI-017`、`AT-ANDROID-019` 与 `GATE-3A`。
