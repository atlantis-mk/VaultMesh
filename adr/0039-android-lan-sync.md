# ADR-0039：Android 独立服务与共享密文同步

- 状态：Accepted
- 日期：2026-09-26
- 关联 Work：`CHG-2026-065-android-lan-sync`

## 决策

用户明确要求完成 Android 同步。将现有密文缓存与窄 Rust 同步接口抽取到平台无关 crate；桌面与 Android 共用现有 mutual TLS protocol v2、分块、限额、收据和退避实现。Android 不依赖 desktop runtime。core 仍唯一拥有通道密钥、投影、验证及合并；平台 runtime 负责先原子提交 Vault，再发布可恢复密文缓存。

Kotlin 使用非导出的 connectedDevice 前台服务维持已授权 LAN 设备连接，持有独立多播资源并显示不含设备/条目名称的常驻通知。从可见 Activity 启动；不在开机或任务移除后自行复活。扫描停止、离页和 Activity 暂停不停止同步服务；暂停仍立即锁定 Vault，仅允许搬运已生成密文。用户可关闭逐设备授权或停止服务；权限撤销、网络切换、任务移除、服务销毁必须关闭连接并释放资源。系统休眠不持有永久唤醒锁，恢复后补齐。

共享缓存的路由证明通过现有 Android Keystore 封存凭据适配器验证。冷启动不得从普通 sidecar 恢复权限；首次通道建立或旧授权升级必须双方解锁。固定 JNI 仅暴露启动、停止、轮询、状态、逐设备授权、重试及冲突摘要/恢复/清空，不返回网络或秘密材料。恢复 Vault 清除旧路由。

替代 ADR-0038 中 Android 尚无同步服务的阶段限制；配对生命周期和信任协议不变。不改变 Vault 格式、KDF 或线上协议。拒绝锁定保留解密 session、常驻隐藏服务、复制桌面 runtime 与另写移动端协议。

## 验证

`CT-ANDROID-LAN-SYNC-001`、`CT-LAN-SYNC-001`、`AT-ANDROID-022`。Android 前台服务类型依据 [Android 官方说明](https://developer.android.com/develop/background-work/services/fgs/service-types#connected-device)。
