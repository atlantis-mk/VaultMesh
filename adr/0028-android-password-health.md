# ADR-0028：Android 密码健康安全投影

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-053-android-password-health`
- 关闭 OPEN：无

## 背景

桌面端已有由 `vault-core` 计算的 Login 密码健康报告。Android 需要显示相同结果，但不能读取密码后在 Kotlin 重算。

## 决策

- 固定 JNI 操作在当前解锁会话调用 core 的 `password_health`，只返回健康分数及弱、重复、过期 Login 的 ID。Kotlin 用当前安全摘要匹配标题，不返回密码、哈希、长度或规则中间值。
- 报告仅在用户主动打开时计算，Compose 状态只保留当前会话；锁定、后台化、切换页面或迟到响应必须清除。Android 不复制健康算法与阈值。

## 原因

core 继续拥有同一套判定，JNI 响应是最小可用的安全投影，Android 只负责呈现。

## 后果

报告依赖设备当前时间判断过期；大量条目可能产生可见计算延迟，需真机验收。健康分数不是密码强度保证。

## 被拒方案

- 把 Login 密码返回 Kotlin 重算：扩大秘密暴露面并复制策略。
- 每次列表刷新都计算报告：增加无请求时的成本和持有期限。

## 验证

`CT-ANDROID-JNI-010`、`AT-ANDROID-010` 与 `GATE-3A`。
