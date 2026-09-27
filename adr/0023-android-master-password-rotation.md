# ADR-0023：Android 主密码轮换的候选会话提交

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-048-android-password-rotation`
- 关闭 OPEN：无

## 背景

Android 已有 format 4 Vault 的创建、解锁和原子 Item mutation。`vault-core` 的主密码轮换会更新会话 header；现有 Item mutation 只快照 payload，不能在轮换写盘失败时恢复旧 header。Android 需要保持旧密码和旧文件有效，且不能让 Kotlin 接收 Vault Key 或 Vault 字节。

## 决策

- Android 通过唯一固定 JNI `changeMasterPassword` 接受旧、新密码，Kotlin 只负责当前表单和 lifecycle，不保存密码。
- Rust runtime 必须先确认当前 session 解锁，然后从当前磁盘 Vault 以旧密码建立候选 `VaultSession`。只在候选会话完成 core header rewrap、序列化并原子写盘成功后，用候选替换当前 session。
- 旧密码错误、无效输入、序列化或原子写盘失败均不得改变旧磁盘 Vault 或当前内存会话。成功后旧密码失效，新密码在冷启动后有效；不自动重试不确定结果。
- 新旧主密码不得返回 JNI、写入日志、Bundle、SavedStateHandle 或非秘密设置；Compose 在提交、取消、失败、后台化和锁定时解除引用。已解锁的其他 owner 不因 Android 轮换自动获得授权。

## 原因

候选会话使 header 和 payload 一起按新的包装材料提交，避免把只覆盖 payload 的回滚机制错误用于凭据轮换。所有格式和密码学仍由 `vault-core` 拥有，Android 只拥有本地文件的原子提交。

## 后果

- Android 轮换需要旧密码，即使当前 session 已解锁。
- Host 测试必须覆盖旧密码错误、写盘失败、当前 session 保留与冷启动后的新旧密码行为；arm64 真机仍须验证 UI 和 lifecycle。

## 被拒方案

- 直接在当前 session 上修改 header 并使用 Item payload 快照回滚：不能恢复 header，写盘失败会留下不一致的内存状态。
- Kotlin 重写 Vault 或持有 Vault Key：违反 Android 窄 JNI 所有权边界。

## 验证

`CT-ANDROID-JNI-005`、`AT-ANDROID-005` 与 `GATE-3A`。
