# 设备填充互通实施与验收记录

主规格：`specs/device-fill-assist.md`；决策：ADR-0047。Work 保持 Active，下面的自动化和传输实机结果不替代完整平台验收。

## 实施

- 独立 `_vm-assist._tcp.local.` 服务、版本化 mutual TLS 协议、同链路校验、逐设备号码/短信授权、取消/期限/重放与全局一次消费。
- Android 设备页授权、独立前台服务/通知停止、系统受保护 SMS 接收、保守解析、20 项两分钟缓存，以及当前请求的手动输入。权限拒绝或系统限制保留手动路径。
- Desktop Rust broker、Browser RPC v2 六项新操作、能力探测、Chromium/Firefox 页内及 popup 候选、原始文档字段 assignment。完整值不进入候选 DTO，候选显示设备、来源、接收时间及剩余期限。
- 配对撤销同时删除互通授权；同一身份重新配对不恢复旧授权。Android Vault 替换/恢复切换授权绑定，后台只保留互通状态。
- 最终设备填充采用即时空字段检查；拒绝隐藏、替换、用途改变、非空和过期目标，不重定位，不等待隐藏字段重新出现，不自动提交。

## 自动化证据

本机执行于 2026-09-27 至 2026-09-28；测试只使用合成数据。

| 检查 | 结果 |
| --- | --- |
| `cargo test -p vaultmesh-lan-pairing --features desktop-sync` | 最新全量 43 通过、1 失败；新增互通 7 项通过。既有大批量首次同步测试报 persistent transport closed early，单独复测仍失败，不能声明同步回归全部通过 |
| `cargo test -p vaultmesh-android-runtime` | 46 通过；依赖设备/桌面 companion 的 ignored 测试单独执行 |
| `cargo test -p vaultmesh-tauri-desktop --lib` | 243 通过，1 ignored；包含新策略和原字段 assignment 回归 |
| `pnpm --filter @vaultmesh/tauri-desktop test` | 158 通过 |
| `pnpm extension:test` | 321 通过，53 个文件；含迟到响应、并发 finish、页面变化和最终字段检查 |
| `pnpm typecheck`、`pnpm verify:browser-parity` | 通过 |
| `pnpm android:contract:test` | 36 通过；固定 JNI、receive-only 权限和非黏性服务契约 |
| Android `testDebugUnitTest assembleDebug assembleDebugAndroidTest` | 通过；arm64-v8a、x86_64 JNI 与 APK 构建 |
| Chromium/Firefox WXT production build | 通过 |
| `pnpm tauri:build` | 本机 macOS x64 app/DMG 构建通过；不代表签名与安装态 Browser 验收 |
| `pnpm docs:trace`、`pnpm docs:check` | 通过；trace 第二次运行无变化 |

桌面旧开发身份测试原来引用已删除的 Bitwarden 目录。其公开身份夹具原样迁至 `apps/tauri-desktop/src-tauri/tests/fixtures/browser-development-identity.json`，保留原断言及既有目录删除；未恢复旧产品源码。

## 实机传输切片

执行：`ANDROID_HOME=/Users/atlan/Library/Android/sdk python3 apps/android/scripts/test-device-assist-device.py`。

已连接 Android API 36 与本机 Mac 经真实 Wi-Fi LAN 配对和 mDNS/TLS 完成以下验证：默认无互通授权、显式授权、关闭配对扫描后互通、Vault 锁定后号码交付、绑定电脑请求的手动验证码交付、一次消费，以及 Vault 文件未变。使用独立 cache 目录和合成号码/代码；未读取真实 SIM 或运营商短信。

该切片调用实际 JNI/网络服务，未覆盖 Compose 用户操作、Android 前台服务的系统存活、Browser 安装态 UI 或真实短信接收。实测发现并修复了 mDNS 服务名长度限制；增加固定回归测试。

## HTTP 页面支持补充验证

- HTTP/HTTPS 目标支持已贯通扩展入口、桌面最终 assignment、共享客户端和 Android 接收端；继续精确绑定页面、字段与独立 Browser 授权，LAN mutual TLS 不变。
- `pnpm extension:test`：54 个文件、335 项通过；桌面 `browser_fill::tests`：14 项通过；共享 `ct_device_assist`：9 项通过，包含 HTTP localhost/普通站点真实 TLS 号码与短信交付、一次消费及非网页来源拒绝。
- 扩展 typecheck、Browser parity（10 项）、测试页菜单（3 项）、`docs:trace` 幂等与 `docs:check` 通过；Chromium/Firefox、macOS x64 app/DMG、Android 双 ABI JNI/APK 构建通过。
- 已连接 Android 执行 `test-device-assist-device.py --serial 86cd9283 --origin http://synthetic.example` 通过：新版 APK 覆盖安装，使用独立合成数据验证 Vault 锁定时 HTTP 来源请求的号码与手动验证码交付、DTO 脱敏和一次消费。没有读取运营商短信或真实 SIM；不替代安装态浏览器最终填充验收。
- Mac 包已生成，未替换当前运行的安装态客户端；加载中的扩展仍需重载。测试页 HTTP 提示已在浏览器检查，未把页面事件或编译结果标为真实填充通过。

## 候选显示延迟修复

用户报告连接提示等待很久、候选间歇出现。已确认手机前台互通服务运行，Mac 安装二进制与上一轮构建一致；未读取真实号码、代码或 Vault 内容。

- 复现并修复客户端候选批量发布问题：真实 TLS 已返回的候选原来仍等待其他慢地址；同一手机成功响应后还会重复访问其其他地址。现在逐设备及时发布候选并跳过已成功服务实例的重复地址；失败地址保留回退，原授权、期限和一次消费不变。回归在修复前失败、修复后通过。
- 扩展增加分阶段反馈、每次响应 10 秒等待上限、总计 60 秒期限、无效响应明确失败及关闭/超时后迟到请求取消；手机号与短信空候选文案分别处理。新增 9 项组件回归，包括只在点击后选择和迟到候选不恢复。
- 共享互通 10 项、扩展全量 341 项、随后新增组件 3 项（组件共 9 项）、typecheck、Browser parity 和文档检查通过。构建包需安装并重载扩展后再验证用户当前页面；以上不宣称已在用户安装态消除全部延迟。

## 未通过的回归

`ct_lan_sync_v2_large_first_merge_is_chunked_and_committed_atomically` 在 1,650 条合成记录、超过 16 MiB 的首次同步中报 `persistent transport closed early`（`crates/vault-lan-pairing/src/lan_sync.rs` 第 790 行）。本轮全量 43/44 通过，单独运行该测试仍失败；更早一轮通过过此测试，因此不能推断为新互通功能引起，也不能推断为偶发后忽略。未改变该测试、fixture、断言或同步协议超时。需要继续定位关闭连接的具体阶段并修复后重跑。

## 待验收（AT-DEVICE-ASSIST-001）

- 无 Google 服务实机、真实系统新短信/分段短信广播与安装器 RECEIVE_SMS 限制。
- Android 17 三小时限制及手动回退的真实设备行为。
- 手机系统锁屏、任务移除、强制停止、通知停止、网络切换及多电脑竞争的系统级完整流程。
- macOS/Windows 上 Chromium/Firefox 安装态，从候选到真实页面最终填充；Windows 构建/安装与 macOS 签名验收。
- 既有密码、身份、银行卡、TOTP 的跨平台 UI 同步/填充人工回归。

上述项目没有用编译、mock 或本机传输测试替代；不标记 Done、不自动发布。
