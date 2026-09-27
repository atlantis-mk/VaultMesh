# ADR-0032：Android 服务密钥补充字段边界

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-057-android-secret-fields`
- 关闭 OPEN：无

## 背景

Android 基础 Secret 编辑只覆盖标题、类型、服务商、账号和值。core 还保存环境、Scopes、到期日、网站、备注、文件夹、收藏和主密码复验设置；部分凭据有内部生命周期 Scope。移动端不能通过普通详情读取秘密值或把 Passkey 当普通 Secret 编辑。

## 决策

- 列表继续只返回安全摘要。明确打开普通 Secret 编辑器后，固定 `secretEditorDetail` 仅返回补充字段，不返回秘密值；Passkey 拒绝。取消、切换、后台、锁定或迟到详情必须清除草稿。
- 固定 `addSecretComplete` 和 `updateSecretComplete` 接收基础字段与严格类型化、有界 JSON 补充字段，core 在单次候选 mutation 中验证并原子提交。更新留空值保留旧秘密，类型沿用当前记录；旧基础操作保留兼容。
- 用户可编辑 Scope 列表；core 的 Secret 更新逻辑继续保留内部 `vaultmesh:credential-lifecycle:` Scope，并禁止用户伪造。其他补充字段按 core 现有日期、网站和 Secret 校验规则处理。

## 原因

按需编辑详情与单次提交能保留跨端元数据，避免两次写盘之间的部分状态，也不扩大秘密值和 Passkey 的普通编辑权限。

## 后果

备注和 Scope 短时进入 Compose 内存；Scopes、网站和到期日会影响其他平台的筛选或匹配，需跨端与真机验证。

## 被拒方案

- 将 Secret 值或备注加入普通列表：扩大无请求时的秘密暴露面。
- 由 Kotlin 合并内部生命周期 Scope：复制 core 所有权且可能丢失内部标记。
- 分步保存基础字段与补充字段：第二次失败会留下半完成编辑。

## 验证

`CT-ANDROID-JNI-013`、`AT-ANDROID-015` 与 `GATE-3A`。
