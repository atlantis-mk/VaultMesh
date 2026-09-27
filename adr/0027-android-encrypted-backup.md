# ADR-0027：Android 加密备份与恢复的文件边界

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-052-android-encrypted-backup`
- 关闭 OPEN：无

## 背景

Android 需要让用户导出与恢复加密 Vault。系统文档 Provider 由 Kotlin 使用 `content:` URI 访问，core 只拥有 Vault 格式和密码验证。文件选择器会使 Activity 进入后台，按现有策略锁定解密会话。

## 决策

- 导出时 Rust 在解锁后把当前加密 envelope 写入应用私有固定 staging 文件。Kotlin 随后通过 `CreateDocument` 选择 `content:` URI，仅复制该密文文件；取消、错误或完成后删除 staging。文件选择引起的后台锁定不延长解密 session。
- 导入时 Kotlin 通过 `OpenDocument` 选择 `content:` URI，有界读取至固定私有 staging 文件；用户再次明确确认替换并输入备份主密码。Rust 固定 JNI 操作只从该路径读取，在 core 验证 format 4 与密码，执行同步副本 epoch/授权重置和 checkpoint 后原子替换本地 Vault；成功后才发布候选 session。失败保留旧文件与旧 session，不自动重试。
- 不通过 JNI 传任意 URI、路径、Vault 文件字节、Vault Key 或通用文件操作。staging 仅存密文，禁止 Android backup，过期/取消/锁定时清理。当前仅支持 format 4；format 3 的保留旧格式备份与迁移须独立设计。

## 原因

Kotlin 负责 Android 文件权限与 Provider，Rust/core 负责格式、鉴权与原子写盘。固定 staging 路径使 JNI 权限有限，并允许文件选择期间继续执行既有后台锁定策略。

## 后果

文档 Provider 对写入提交与截断的行为因实现而异；流关闭成功只能说明 Provider 接受写入，平台验收必须重新打开校验。云 Provider 最终同步不由本应用保证。format 3 备份在当前 Android 入口明确拒绝。

## 被拒方案

- 把 Vault Key 或解密 payload 交给 Kotlin 序列化：复制格式和秘密所有权。
- JNI 接收任意外部路径或 URI：扩大文件读写权限。
- 为保持导出会话而取消文件选择器期间的后台锁定：破坏现有生命周期边界。

## 验证

`CT-ANDROID-JNI-009`、`AT-ANDROID-009` 与 `GATE-3A`。
