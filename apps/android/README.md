# VaultMesh Android

Android 客户端使用 Jetpack Compose 与 Kotlin 平台 shell，通过固定 JNI operation 调用 `vaultmesh-android-runtime`；它不依赖 Tauri desktop runtime。解锁后以保险库、工具、设备、设置四个底部页面组织功能。保险库顶部按全部、登录、卡片、身份、SSH 和密钥分类，类型页保留适用回收站；条目操作在卡片展开后显示。实现范围与尚未完成的平台验收以 `specs/android-client.md` 和 `docs/07-test-release-plan.md` 为准。

## 本地构建

需要 Android SDK 37、NDK `28.2.13676358`、JDK 17+、Rust Android targets 和 `cargo-ndk 4.1.2`：

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk --version 4.1.2 --locked
pnpm android:build
```

`ANDROID_HOME` 必须指向 SDK；`ANDROID_NDK_HOME` 可以省略，构建脚本会选择固定 NDK。Debug APK 位于 `app/build/outputs/apk/debug/app-debug.apk`。

## Review 发布打包

Release 构建覆盖 `armeabi-v7a`、`arm64-v8a`、`x86_64`，并额外生成包含全部 ABI 的 universal APK（`ADR-0048`）。本地需要再安装 32 位 Rust target：

```sh
rustup target add armv7-linux-androideabi
```

签名密钥只通过环境变量提供，不得提交到仓库：

```sh
VAULTMESH_ANDROID_KEYSTORE_PATH=/path/to/release.jks \
VAULTMESH_ANDROID_KEYSTORE_PASSWORD=... VAULTMESH_ANDROID_KEY_ALIAS=... VAULTMESH_ANDROID_KEY_PASSWORD=... \
pnpm android:release:build
```

输出位于 `artifacts/android/VaultMesh_<version>_android-<universal|armeabi-v7a|arm64-v8a|x86_64>.apk`。versionName 取自根 `package.json`，versionCode 按版本单调派生，个位区分 ABI（universal 0、armeabi-v7a 1、arm64-v8a 2、x86_64 3）。设置 `VAULTMESH_ANDROID_CERT_SHA256` 时脚本还会校验证书指纹；仅做本地冒烟时可加 `-- --allow-unsigned` 生成未签名 APK。

CI 的 `Publish R2 review release` workflow 需要 Secrets `ANDROID_RELEASE_KEYSTORE_BASE64`、`ANDROID_RELEASE_KEYSTORE_PASSWORD`、`ANDROID_RELEASE_KEY_ALIAS`、`ANDROID_RELEASE_KEY_PASSWORD` 与仓库变量 `ANDROID_RELEASE_CERT_SHA256`。

## 新版本提示

Release APK 会在打开应用时（每天最多一次）检查 Review channel 的 `android.json`，发现新版本后提示下载；“设置 → 更新”可以手动检查或关闭自动检查。“下载”在系统浏览器中打开与设备 ABI 匹配的 APK，由系统完成覆盖安装并保留数据，应用本身不下载或安装 APK（`ADR-0049`）。Debug 构建不检查更新。签名发布需要提供 `VAULTMESH_ANDROID_UPDATE_MANIFEST_URL`，CI 由 `R2_PUBLIC_BASE_URL` 自动拼出。

## 应用图标

`app/src/main/res/mipmap-nodpi/ic_launcher_artwork.png` 是内置 imagegen 以桌面端 `apps/tauri-desktop/resources/icon.png` 为品牌参考生成的透明 RGBA 图标，保留锁盘、青色钥匙孔、六节点和紫蓝配色。完整生成提示词保存在 `resources/launcher-icon-prompt.txt`。替换图片时必须保留 alpha；白色背景由 Android 自适应图层提供，不烘焙进 PNG。

自适应图标使用纯白背景和透明 PNG 前景。前景占 72dp 可见区域的 84%，四周保留少量白色边距；由系统裁切圆形或圆角外形。不再使用 SVG 转换脚本或旧矢量图层。

## 当前门禁

```sh
pnpm android:rust:test
pnpm android:contract:test
pnpm android:build
./gradlew -p apps/android lintDebug
```

模拟器只用于开发冒烟。`FLAG_SECURE`、后台/锁屏、任务划除、进程终止和 backup exclusion 必须在 arm64 真机完成 `AT-ANDROID-001` 后才能视为通过；Login CRUD 使用 `AT-ANDROID-002`，搜索与回收站使用 `AT-ANDROID-003`。

## 局域网同步

配对后自动同步独立于扫描运行，可以关闭扫描并离开设备页。首次连接请解锁双方保险库；后台锁定时只收发密文，返回解锁后合并。设备页提供逐设备同步开关、重试、暂停/恢复与冲突历史；通知也可停止同步。需处于同一 Wi-Fi/以太网，并允许本地网络访问。系统休眠或任务移除可能停止连接，重新打开应用后补齐；不提供跨网络同步。

`CT-ANDROID-LAN-SYNC-001` 的主机真实网络回归：

```sh
cargo test -p vaultmesh-android-runtime android_desktop_sync_survives -- --ignored
```

真机测试 `LanSyncInstrumentedTest` 使用独立 cache 目录的合成保险库，并与 `desktop_companion_for_android_sync_instrumentation` 配合；不得用于产品数据目录。解锁测试手机并接入与主机相同的 LAN，运行以下命令。脚本安装 Debug 包、协调锁定后发送密文，并同时检查两端断言；测试临时保持亮屏，结束后释放。

```sh
apps/android/gradlew -p apps/android assembleDebug assembleDebugAndroidTest
python3 apps/android/scripts/test-lan-sync-device.py --serial <adb-device-serial>
```

该切片覆盖扫描关闭、双向新增、后台锁定密文接收、解锁合并、服务重启补齐与撤销；完整平台验收另需物理 Wi-Fi 切换、进程终止与 Android 37 权限拒绝/撤销。

## 系统自动填充与登录保存

在 VaultMesh 创建或恢复保险库后，进入“设置 → 自动填充与登录保存 → 启用自动填充”，在系统选择器选择 VaultMesh。受支持应用的登录字段会出现“使用 VaultMesh 填充”；输入主密码、选择账号后填入用户名/密码。首次把网站账号交给尚未关联的应用时，需要确认包名与应用声明的网站。浏览器必须提供 Android Autofill 结构，部分浏览器需要开启“使用其他服务”。

手动输入登录/注册/新密码并提交后，系统可弹出保存提示。确认后在 VaultMesh 输入主密码，选择新建或同账号更新，再确认保存。捕获与授权仅保留两分钟；取消或离开确认页会丢弃，必须重新触发。保存更新保留原登录项的 TOTP、恢复码及其他资料。不支持系统 Autofill 的自绘表单不会出现提示。

Android 9 及以上、Google Play 服务可用时，明确标记为短信验证码的输入框会显示“填充短信验证码”。点选后首次按系统提示授权，VaultMesh 等待最近或新收到的验证码并仅填入该字段；不会自动提交。目标应用已经自行监听验证码、系统授权被拒或字段没有明确短信验证码标记时不显示此候选。此功能不需要 Vault 解锁，也不申请读取短信权限。

验证使用独立合成 Vault 和测试 APK，不会读取产品保险库。连接并解锁真机后执行：

```sh
ANDROID_HOME=/path/to/sdk apps/android/gradlew -p apps/android assembleDebug assembleDebugAndroidTest
adb install -r apps/android/app/build/outputs/apk/debug/app-debug.apk
adb install -r apps/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w -r -e class com.vaultmesh.app.AutofillSystemTest com.vaultmesh.app.debug.test/androidx.test.runner.AndroidJUnitRunner
```

`CT-ANDROID-AUTOFILL-001/002/004` 与 `AT-ANDROID-023/025` 的系统测试临时选择 Debug 自动填充服务并在 finally 恢复之前的服务；测试 APK 的 AutofillFixtureActivity 提供合成登录和验证码表单。短信收到后的填入需用户在真机上触发测试短信，不得在测试日志输出短信或验证码。正式产品仍需签名发布与跨厂商/浏览器矩阵验收。
