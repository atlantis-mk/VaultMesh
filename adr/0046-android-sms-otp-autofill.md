# ADR-0046：Android 短信验证码自动填充

## 状态

Accepted。用户于 2026-09-26 要求完成短信验证码自动填充。

## 决策

Android 9 及以上且 Google Play 服务支持时，用户指定的 VaultMesh Autofill 服务通过 `SmsCodeAutofillClient` 提供显式“填充短信验证码”候选。服务先检查目标应用是否已启动自己的 SMS Retriever 请求以及 VaultMesh 的 SMS Code Autofill 权限状态；目标已有请求、权限被拒或检查失败时不显示候选。Android 8 和无 Google Play 服务设备不提供该候选。

候选只出现在明确标识为 SMS 一次性验证码的、当前聚焦的可编辑字段；普通密码、TOTP、银行卡及无标签数字输入不猜测为短信验证码。点选候选后，非导出 Activity 以一次性内存请求启动 Google Play SMS Code Retriever，并由系统取得用户授权。动态 BroadcastReceiver 必须要求 Google Play 服务的 `SEND_PERMISSION`；只接受成功状态和有界验证码。结果仅作为当前 `AutofillId` 的 Dataset 返回系统，不保留整条短信、验证码或读取短信的 Android 权限。不自动提交。

请求绑定系统给出的目标包名、当前签名摘要、Activity、HTTPS origin、字段 ID 和短期期限。消费、取消、超时、后台、目标签名变化与进程死亡均结束请求；结果不得用于其他目标或字段。短信 OTP 不解锁 Vault，也不加入登录捕获、预览、选择历史或 TOTP 数据。Google Play `play-services-auth-api-phone` 为仅 Android 的生产依赖，失效时安全退回无候选。

## 原因与替代方案

Google 的 SMS Code Autofill API 为用户指定的 Autofill 服务提供经同意的验证码提取，并能避免申请 `READ_SMS` 或 `RECEIVE_SMS`。直接监听短信广播或读取收件箱扩大权限和数据接触面；无标签数字字段推测会把验证码误填到账号、支付或其他输入框。目标应用自行使用 SMS Retriever 时让目标应用完成其自身流程。

## 验证

`CT-ANDROID-AUTOFILL-004` 覆盖字段识别与反例、权限和目标已有请求、一次性绑定、取消、过期、签名变化及结果字段隔离。`AT-ANDROID-025` 在支持 Google Play 服务的 Android 真机验证首次授权、收到新短信后的当前字段填充，以及拒绝、取消、超时与目标自行读取短信的路径。
