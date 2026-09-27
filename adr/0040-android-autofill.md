# ADR-0040：Android 系统自动填充与登录识别保存

## 状态

Accepted。用户于 2026-09-26 明确要求完成 Android 自动填充和识别保存，使客户端能够正常使用。

## 决策

使用 Android Autofill Framework（API 26+），以受 `BIND_AUTOFILL_SERVICE` 保护的 Kotlin 服务接收 AssistStructure。非导出认证 Activity 由一次性 PendingIntent 启动，负责主密码输入、账号选择、目标告知与保存确认。登录凭据不通过普通 Compose state、Intent extras 或文件中转；只有最终系统 authentication result 包含有界 Dataset。Credential Manager、Passkey、辅助功能服务不在本切片。

Rust Android runtime 持有与主界面解锁状态隔离的 120 秒单请求授权。授权绑定随机 token、请求 ID、目标包名、当前签名摘要及可选 HTTPS origin；调用 core 验证主密码，终止、过期、锁定、后台化或进程死亡清除。填充/保存消耗授权且验证磁盘指纹，拒绝重放和并发旧快照。保存复用现有原子提交及回滚，结束后主 Vault 保持锁定。

为读取任意请求应用的签名，Manifest 声明 QUERY_ALL_PACKAGES；仅按系统请求中的精确包名查询，不枚举、记录或上传已安装应用。系统提供 activity component，Kotlin 使用 PackageManager 取得该包的当前 signer 集合，按排序后的 SHA-256 摘要建立身份。不得根据应用显示名称推断目标。已确认的关联保存在既有加密 Login `additional_urls` 中，使用 `androidapp://<package>/sha256/<signer-set-digest>`，网页目标另加编码后的精确 origin 查询参数；无需 Vault 格式迁移，旧客户端忽略非 HTTP URL 即可。签名变化或 origin 变化不得继承关联。

来自 AssistStructure 的 webDomain 仅是目标应用声明。已有 HTTPS URL 的精确 origin 可作为候选建议，但首次跨入没有已保存关联的应用必须再次明确告知应用包名和网页 origin 并确认；不把任意 WebView 或同名包当成可信浏览器，不做网络 DAL 请求。用户可以搜索其他登录项，但不匹配项同样必须明确确认。不会自动提交表单或在无人操作时发送秘密。

捕获只在系统 SaveRequest 后读取所选字段的值，秘密最多 120 秒留在 Kotlin 特权内存容器。系统保存提示后进入确认页，主密码验证后用户选择新建或同账号更新。更新保留其他字段、TOTP、恢复码和历史，重复相同保存不生成新条目；任何失败不得提前显示保存成功。

## 原因与替代方案

独立授权避免为了跨应用填充而放宽主 Activity 的后台锁定规则。既有 Login URL 集合避免新增格式 owner。采用系统表单和明确用户动作，拒绝全屏无障碍抓取、包名倒序猜测域名、后台保持通用解锁以及明文捕获持久化。

## 验证

`CT-ANDROID-AUTOFILL-001` 覆盖目标/签名/期限/重放、秘密投影、更新保留、重复保存和写入回滚；`CT-ANDROID-AUTOFILL-002` 覆盖识别、歧义、捕获有界、PendingIntent 和生命周期。`AT-ANDROID-023` 在真机验证系统启用、填充、保存、取消和锁定。
