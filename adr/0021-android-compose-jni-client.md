# ADR-0021：Android Compose、Kotlin 平台服务与窄 JNI runtime

## 状态

Accepted。用户于 2026-09-12 明确选择 Jetpack Compose 原生 UI、Kotlin 平台服务与 JNI 复用 `vault-core`，并授权开始开发。

## 决策

Android 客户端必须使用 Jetpack Compose 作为唯一产品 UI，Kotlin 作为 Activity、Application、系统 lifecycle 与后续 Android Service 的所有者。Android 不使用 Tauri/WebView，不依赖或编译 `apps/tauri-desktop/src-tauri`。

Kotlin 必须只通过 `crates/vault-android-runtime` 暴露的固定 JNI operation 使用 Vault。该 runtime 可以依赖 `vault-core`，但不得向 Kotlin 暴露 core 对象、Rust pointer、Vault Key、解密 payload、通用 method router 或可跨进程恢复的 secret handle。首切片只包含 initialize、create、unlock、status 与 lock；JNI 返回稳定的非秘密结果。

Vault 文件必须由 Kotlin 选择应用私有目录并在初始化时交给 Rust；Rust runtime 拥有 session 和原子提交。Create 仅在目标不存在时执行，成功落盘后才发布解锁状态。应用后台化、系统锁定、显式锁定或进程终止后不得恢复解锁权限。Android backup、device transfer backup、cleartext traffic 和首切片全部网络权限必须关闭，主 Activity 必须启用 `FLAG_SECURE`。

Autofill、Credential Manager、Passkey、Keystore/biometric quick unlock、外部文件与后台 LAN 同步不由本 ADR 的首切片授权。引入时必须建立独立受控边界；系统级秘密使用必须由 Kotlin Service 直接调用受限 Rust operation，不经过 Compose 状态。

## 原因

- VaultMesh UI 规模不要求以 WebView 换取跨端复用，Compose 更贴近 Android lifecycle、无障碍、Autofill 与 Credential Manager。
- `vault-core` 已隔离加密、格式、模型和秘密 session，可以复用而不复制密码学实现。
- 现有 Tauri runtime 同时拥有桌面托盘、Agent、browser、SSH、邮件和 LAN 权限，直接移动会扩大 Android attack surface，并可能使 `cfg(unix)` 错误启用桌面 transport。
- 窄 JNI operation 能让平台边界、输入所有权、错误映射和清理行为分别测试，避免 Kotlin 成为第二个 Vault 模型所有者。

## 后果

- Android 需要独立维护 Compose/Kotlin、JNI binding 和目标平台构建链；共享的是产品规则与 Rust core，不是桌面 UI。
- JNI 字符串仍会经过 JVM 内存，因此首切片必须最小化主密码存活时间并立即清空 Compose 输入；后续应评估可控字节缓冲，但不得声称 JVM 字符串可可靠擦除。
- Android 平台验收必须在 arm64 真机执行；host Rust 测试、Android 交叉编译和模拟器只构成较早 Gate。
- 首切片不会提供完整 Android 密码管理器能力，范围矩阵保持 Partial，直到独立能力和发布 Gate 完成。

## 被拒方案

- Tauri 2 Android 复用 desktop runtime：拒绝，因为移动 lifecycle、原生 Service 与现有桌面 privilege composition 不匹配。
- 全 Kotlin 重写 Vault：拒绝，因为会形成第二套密码学、格式和 migration owner。
- JNI 直接暴露 `VaultSession` pointer 或通用 JSON method：拒绝，因为生命周期、类型和秘密边界无法稳定审计。
- 首版同时实现 Autofill、Passkey、quick unlock 和后台同步：拒绝，因为无法形成可独立验证的最小安全切片。

## 验证

`CT-ANDROID-RUNTIME-001`、`CT-ANDROID-JNI-001`、`AT-ANDROID-001`，以及 `GATE-1`、`GATE-2` 和 Android 平台 Gate。
