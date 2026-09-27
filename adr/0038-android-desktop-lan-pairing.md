# ADR-0038：Android 与桌面共用局域网配对协议

- 状态：Accepted
- 日期：2026-09-18
- 关联 Work：`CHG-2026-064-android-lan-pairing`
- 关闭 OPEN：无

## 背景

现有 LAN protocol 2.0 配对实现在 Tauri Rust 模块中，Android 不能依赖桌面 shell。移动端独立重写 TLS/PAKE 与信任状态机会产生第二个安全协议所有者，也无法保证桌面与 Android 互通。Android 的网络权限、Keystore 和前台生命周期又必须由 Kotlin 管理。

## 决策

桌面与 Android 必须共用同一 Rust LAN protocol 2.0 配对状态机、mDNS TXT 验证、TLS/PAKE/key confirmation、碰撞仲裁、信任索引和帧限制；平台凭据存储作为受限适配器注入。Android 不得编译 Tauri shell、desktop runtime 或桌面同步服务。Android 凭据必须由 Android Keystore 密钥封存到应用私有存储，明文设备私钥、配对码和网络帧不得经 Compose 或 JNI DTO 返回。

Android 只在 Vault 已解锁、页面可见、用户显式启动且已获本地网络权限时启动十分钟发现窗口。Kotlin 必须在暂停、系统锁定、离页、权限撤销或进程退出时停止监听与 mDNS、释放 Wi-Fi 多播资源；重新进入不得自动重启。JNI 仅暴露固定 start/status/begin/stop/revoke/rename 操作，返回与桌面同形的安全状态。配对成功后必须为双方当前 Vault 持久化同步授权；Android 后台密文同步另设受控切片。

## 原因

- 单一协议所有者使 Android 和桌面使用相同线协议与拒绝路径。
- Android Keystore 与短时前台权限符合移动平台的凭据和电池边界。
- 配对可独立于尚未实现的 Android 后台同步验收，同时为后续同步保留明确授权。

## 后果

- 新增 Android `INTERNET`、Wi-Fi 多播和 Android 17 本地网络运行时权限；拒绝或撤销必须有明确错误状态。
- 共享 Rust crate 的桌面回归、Android arm64/x86_64 构建和桌面↔Android 真机双向配对成为完成门禁。
- 仅有配对不代表 Android 已能收发 Vault 更新；该能力仍由后续同步 Work 验收。

## 被拒方案

- Android 单独实现一套 PAKE/TLS 配对：会形成第二个安全协议所有者，拒绝。
- Android 复用 Tauri desktop runtime：会引入桌面 Agent、Browser 与后台网络权限，拒绝。
- 用明文六码或二维码中直接携带永久信任凭据：绕开现有 PAKE 与证书固定，拒绝。

## 验证

`CT-LAN-PAIRING-001`、`CT-ANDROID-LAN-PAIRING-001`、`AT-ANDROID-021` 与 Android GATE-3A。
