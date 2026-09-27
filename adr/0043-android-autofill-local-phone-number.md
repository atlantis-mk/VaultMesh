# ADR-0043：Android 本机电话号码用户名填充

## 状态

Accepted。补充 `ADR-0040` 的系统 Autofill 候选，不改变 Vault 登录凭据的解锁与授权规则。

## 决策

电话号码候选只在系统请求经现有 `AutofillStructure` 验证且包含用户名 `AutofillId` 时生成，放在最近选择及已关联账号之后、“使用 VaultMesh 填充”候选之前；QQ 注册数字手机号字段的窄范围识别由 `ADR-0045` 补充。Dataset 只设置该用户名字段，不设置密码、新密码或确认字段。国际格式号码通过 Android 电话格式化规则确认国家拨号前缀后仅显示并填入本地号码；无法可靠拆分时不提供候选。候选必须由用户点选才填入目标应用，不自动提交，也不读取目标已有字段值。该值来自设备或用户主动设置，不属于加密 Vault 登录项，因此不要求解锁 Vault；Vault 凭据入口继续独立认证。

读取 SIM 默认订阅号码需要用户在 VaultMesh 设置中主动授予 `READ_PHONE_NUMBERS`。API 33+ 使用 `SubscriptionManager.getPhoneNumber(DEFAULT_SUBSCRIPTION_ID)`；旧版使用 `TelephonyManager.line1Number`。拒绝权限、无电话功能、无有效默认订阅、号码为空或格式无效时，不显示 SIM 候选，也不在 Autofill 请求过程中弹权限框。

用户可以在设置中手动提供一个备用号码。仅在 SIM 号码不可用时使用它。手动号码经长度和字符验证后，以 Android Keystore AES-GCM 加密写入应用私有且不备份的文件；AutofillService 可在 Vault 锁定时解密，以提供直接系统候选。文件损坏、密钥丢失或解密失败时不显示候选。用户可删除手动号码；号码不进入 Vault、普通设置、Intent、日志或分析。权限撤销立即停止 SIM 读取。

## 原因与替代方案

Android 电话号码接口不保证有值或格式正确；手动备用让无号码的 SIM 和仅数据设备仍可使用。只在用户选择后交付，避免将号码自动塞入任意应用；只用 `READ_PHONE_NUMBERS`，不申请更广的电话状态或短信权限。将号码放入 Vault Login 会要求先解锁、无法在原系统提示下提供直接候选，也会混淆个人号码和网站凭据的所有权。

## 验证

`CT-ANDROID-AUTOFILL-003` 覆盖电话号码规范化、权限拒绝、加密备用、用户名独立 Dataset 与密码字段排除；`AT-ANDROID-024` 在真机验证系统候选顺序、点选填入用户名、取消、权限撤销及无 SIM 号码回退。
