# ADR-0024：Android 受保护值复制与剪贴板所有权

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-049-android-protected-item-access`
- 关闭 OPEN：无

## 背景

Android 基础 Item 列表和编辑不返回已有秘密。为了让已保存凭据可在手机上使用，Android 需要用户主动触发的受保护字段复制。将完整详情或值放入 Compose 列表会违反最小披露；系统剪贴板还可能被其他应用读取或替换。

## 决策

- 每个可复制字段使用可枚举的固定 JNI operation。Rust runtime 必须先确认解锁并由 `vault-core` 重新验证当次主密码，再提取该字段；普通 Secret 入口必须拒绝 Passkey。未知 ID、缺少值、错误密码和锁定只返回封闭错误码。
- Kotlin 特权剪贴板服务在操作成功后直接接收有界 JNI 值并写入系统 `ClipboardManager`。受保护值不得写入 Compose 列表、草稿、日志、Bundle、SavedStateHandle 或长期 handle；JNI 响应及 JVM 字符串在调用结束后尽快解除引用。
- 写入的 `ClipData` 必须设置 Android sensitive 标志并带非秘密随机所有权标签。30 秒后只在本应用仍持有该 clip 时清除；剪贴板变更监听发现替换时不得清除用户的新内容。后台读取限制使标签不可见时不得猜测所有权，真机验收须核对各版本实际清理行为。
- 主密码输入在提交前清空 Compose state。锁定、后台化或迟到结果不得再执行复制；写入结果不确定时不自动重试。

## 原因

固定字段操作可分别审核核心鉴权、返回值和适用 UI。Kotlin 拥有 Android 系统服务，Rust 保持 Vault 秘密和密码验证的唯一所有者。所有权标签避免定时清理擦掉用户随后复制的其他内容。

## 后果

- Android 剪贴板在系统外部可见；敏感标志隐藏 Android 13+ 预览，但不能替代时限和用户明确动作。
- Android 10+ 后台可能无法读取剪贴板描述，因此到期清理需要平台真机验证；无法证明所有权时不得清除别的 clip。
- 受保护值复制是单独安全切片，不授权通用 reveal DTO、Autofill 或 Credential Manager。

## 被拒方案

- 把所有条目秘密加入列表或通用详情：扩大持有面且破坏摘要边界。
- 一个通用 `copy(type, field)` JNI 方法路由：让跨类型权限和返回值难以穷举审核。
- 到期时无条件清空系统剪贴板：可能删除用户随后复制的无关内容。

## 验证

`CT-ANDROID-JNI-006`、`AT-ANDROID-006` 与 `GATE-3A`。
