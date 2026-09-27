# ADR-0037：Android PIN 快捷解锁的设备秘密与失败限制

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-062-android-pin-quick-unlock`
- 关闭 OPEN：无

## 背景

六位 PIN 的搜索空间很小，不能单独作为离线 Vault Key 包装密钥。Android 还需要在错误 PIN 后封闭限制尝试次数，主密码始终保持回退入口。

## 决策

- Kotlin 生成独立随机 32 字节设备秘密，以应用私有 Android Keystore AES-GCM key 封存；Keystore key 不导出，封存文件不参与 Android backup。设置和尝试时只把短时设备秘密与六位 PIN 交给固定 JNI，不交付 Vault Key。
- Rust 使用与桌面相同参数的 scrypt 将 PIN 和设备秘密派生为包装密钥，再以独立 nonce 的 XChaCha20-Poly1305 包装当前 Vault Key。仅在 core 验证当前磁盘 Vault 后发布解锁 session。
- Rust 将错误次数与包装记录原子持久化，连续五次失败后拒绝 PIN。错误计数写入失败时不得发布 session。成功的主密码解锁重置计数；本机封存和 Rust 记录都存在时才显示 PIN 入口，关闭时两者删除。
- 取消、后台化和迟到操作不得恢复解锁或持久 UI 草稿。设备秘密损坏/丢失时用户使用主密码并重新设置 PIN。

## 原因

PIN 与设备绑定随机秘密共同保护包装密钥，避免对窃取的 Rust 记录直接穷举六位 PIN。尝试次数由 Rust 所有，Compose 只展示剩余次数。

## 后果

本设计不保证抵抗已控制应用 UID/Keystore 调用权限的攻击者或可回滚应用私有文件的 root 对手；Java 字符串中的 PIN 和设备秘密不能可靠归零，只允许短时通过固定调用。设备秘密丢失或恢复为不同 Vault Key 后需重新设置 PIN。

## 被拒方案

- 仅以 PIN 派生包装密钥：六位空间可离线穷举。
- 在 Kotlin/Compose 持久化失败次数：可以绕过固定 Rust 解锁入口。
- 把 Vault Key 交给 Keystore 或 Kotlin：跨越 core 秘密所有权边界。

## 验证

`CT-ANDROID-JNI-018`、`AT-ANDROID-020` 与 `GATE-3A`。
