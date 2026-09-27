# ADR-0025：Android 条目历史边界

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-050-android-item-history`
- 关闭 OPEN：无

## 背景

Android 已能编辑 Login、Card、SSH 和 Identity，`vault-core` 会保存编辑前版本，但 Android 尚不能查看或恢复。历史记录包含旧秘密，不能把完整版本送到 Kotlin。

## 决策

- 每种适用类型各有固定 list、restore 和 clear JNI operation；Secret 没有此入口。list 只把 core 的历史安全摘要转换为版本 ID、标题、非秘密副标题和保存时间。
- restore 必须同时指定当前条目 ID 和版本 ID，由 core 验证归属并保存当前版本，再经 Android runtime 原子提交。clear 必须指定当前条目 ID，提交失败恢复原文件与内存状态。
- Compose 的历史列表只留在当前解锁会话，恢复与清空分别显式确认。切换类型/条目、锁定、后台化或迟到响应必须使目标和列表失效；写入结果不确定时不得自动重试。

## 原因

固定操作维持 JNI 权限可审查性，core 继续拥有历史结构、归属校验和加密数据。安全摘要可供用户选择版本而不预读旧密码、卡号或私钥。

## 后果

恢复会改变当前条目并产生新的历史版本。Android 只展示历史摘要，不提供旧秘密预览。真机验收必须确认破坏性提示、生命周期和重启后的结果。

## 被拒方案

- 把完整历史 payload 返回 Kotlin：扩大旧秘密暴露面。
- 单个通用历史路由器：跨类型鉴权难以穷举审查。

## 验证

`CT-ANDROID-JNI-007`、`AT-ANDROID-007` 与 `GATE-3A`。
