# ADR-0033：Android SSH 凭据补充字段边界

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-058-android-ssh-fields`
- 关闭 OPEN：无

## 背景

Android 基础 SSH 编辑只覆盖主机、端口、用户名及认证值。core 还保存备注、文件夹、收藏和主密码复验设置；桌面托管的 OpenSSH alias 有额外的外部资源所有权。

## 决策

- 用户明确打开普通 SSH 编辑器后，固定 `sshEditorDetail` 只返回补充字段，不返回任何认证值；托管 alias 拒绝。取消、切换、后台、锁定或迟到详情必须清除草稿。
- 固定 `addSshComplete` 与 `updateSshComplete` 接受基础字段及严格类型化、有界的补充字段。core 在单次候选 mutation 中验证并原子提交；空认证值保留旧值，明确清除和替换互斥。旧基础操作保留兼容。
- Android 不编辑托管 alias，不执行 SSH，也不接管桌面外部配置。

## 原因

按需详情和一次性提交保留跨端元数据，同时将认证值和外部资源所有权限制在既有边界内。

## 后果

备注短时进入 Compose 内存；完整字段和锁定行为需在 arm64 真机及桌面共用 format 4 Vault 上验收。

## 被拒方案

- 把认证值加入普通详情或列表：扩大无请求时的秘密暴露面。
- 分步保存基础字段和补充字段：第二次失败会留下部分编辑。
- 将托管 alias 当普通条目编辑：无法由 Android 原子维护桌面 OpenSSH 配置。

## 验证

`CT-ANDROID-JNI-014`、`AT-ANDROID-016` 与 `GATE-3A`。
