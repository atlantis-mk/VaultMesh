# ADR-0022：Android 多类型 Item 的固定 JNI 操作

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-047-android-compose-client`
- 关闭 OPEN：无

## 背景

Android 首个 Vault/Login 切片已建立 Compose、Kotlin lifecycle 与窄 JNI runtime。继续管理 Card、SSH、Identity 和 Secret 时，不能把桌面通用 runtime、完整 Vault payload 或受保护详情交给 Kotlin；移动端基础编辑也不能抹掉桌面保存的扩展元数据。

## 决策

- 每个类型必须使用固定且可枚举的 JNI list/create/update/delete 操作；有 core 回收站的类型必须使用固定 restore/purge/empty 操作。不得引入通用 operation router、Rust pointer、Vault Key 或完整 payload DTO。
- Kotlin 列表只能持有安全摘要。Card 仅展示掩码卡号及秘密存在性，SSH 仅展示认证值存在性，Secret 不展示值；Identity 的基础编辑详情只能在明确编辑动作后读取，并在取消、锁定或后台化时清除。
- 基础更新必须在 Rust/core 边界内保留未替换的秘密和移动端未提供的元数据。明确清除与替换必须互斥；所有 mutation 必须复用原子提交及内存回滚。
- Android 不得通过普通 Secret 操作处理 Passkey，也不得修改桌面管理的 OpenSSH alias。Secret 删除不可恢复；Card、SSH、Identity 删除使用各自的加密回收站。
- 当前 Item 切片不授予受保护值查看/复制、Autofill、SSH 执行、外部文件或后台服务。新增这些系统级能力必须另行定义平台边界。

## 原因

- 固定 ABI 让每个秘密输入和返回投影可以分别审计与测试。
- Core 已拥有类型验证、复杂元数据、历史、回收站和格式；Android 只执行受限操作并提交 core 生成的候选状态。
- 桌面管理的 SSH alias 与 Passkey 有额外所有权，普通 Android CRUD 无法安全完成其外部资源清理。

## 后果

- Android 需维护各类型的 Kotlin 表单、安全摘要和 JNI parity 测试。
- JVM 字符串无法可靠原位擦除，秘密表单必须在提交、取消、锁定和后台化时立即解除引用。
- Host 与交叉编译通过只证明早期 Gate；arm64 真机 UI、lifecycle、backup exclusion 与 release JNI 验收仍属于 `AT-ANDROID-001` 至 `AT-ANDROID-004`。

## 被拒方案

- 通用 JSON operation router：拒绝，因为会模糊可审计的类型、授权和返回值边界。
- Kotlin 读取完整 Item 后重写：拒绝，因为会泄露秘密并清除移动端未展示的元数据。
- 把 Secret 和 Passkey、普通 SSH 与 managed alias 一并编辑：拒绝，因为它们有不同的持久资源所有权。

## 验证

`CT-ANDROID-JNI-004`、`CT-ANDROID-RUNTIME-001`、`AT-ANDROID-004` 与 `GATE-3A`。
