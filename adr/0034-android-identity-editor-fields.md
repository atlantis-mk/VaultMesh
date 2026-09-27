# ADR-0034：Android Identity 结构化编辑边界

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-059-android-identity-fields`
- 关闭 OPEN：无

## 背景

Android 基础 Identity 编辑只包含标题、名、姓和组织。core 中的中间名、生日、多邮箱/电话/地址、职业、网站、备注、文件夹与收藏无法编辑；多值字段的稳定 ID 和首选标志影响历史与跨端行为。

## 决策

- 用户明确打开 Identity 编辑器时，固定 `identityEditorDetail` 返回完整个人资料 DTO；普通列表仍只返回安全摘要。DTO 只在当前前台会话存在，取消、切换、后台、锁定与迟到详情必须清除。
- 固定 `addIdentityComplete`、`updateIdentityComplete` 接收严格类型化、有界结构化 JSON。邮箱、电话、地址保留 UUID、标签、值与首选标志；新增值只在草稿中生成 UUID。core 对完整候选执行既有校验，在单次原子 mutation 中提交并记录历史；旧基础操作保留兼容。
- JNI 拒绝未知字段、超限文档和超过桌面当前 20 条上限的各类多值集合。Kotlin 不直接操作 Vault payload 或自行维护另一套持久格式。

## 原因

完整替换是 core 现有 Identity 更新语义。保留多值 ID 并一次性提交，可避免移动端清空桌面资料和提交中途的不一致状态。

## 后果

个人资料在显式编辑期间短时进入 Compose 内存；真机需验证关闭、后台、锁定、冷启动与桌面共用 Vault 后的完整字段及 ID 一致性。

## 被拒方案

- 把完整 Identity 放入普通列表：会让未请求的个人资料进入列表状态。
- 只修改基础字段并永久不提供多值编辑：无法满足用户选择的适用桌面能力。
- 分步保存各个联系值：会留下部分资料并破坏历史的完整版本语义。

## 验证

`CT-ANDROID-JNI-015`、`AT-ANDROID-017` 与 `GATE-3A`。
