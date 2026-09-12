# VaultMesh Android

Android 客户端使用 Jetpack Compose 与 Kotlin 平台 shell，通过固定 JNI operation 调用 `vaultmesh-android-runtime`；它不依赖 Tauri desktop runtime。当前实现 Vault create/unlock/status/lock，基础 Login 列表、新增、编辑、搜索，以及回收站恢复、永久删除和清空。

## 本地构建

需要 Android SDK 37、NDK `28.2.13676358`、JDK 17+、Rust Android targets 和 `cargo-ndk 4.1.2`：

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk --version 4.1.2 --locked
pnpm android:build
```

`ANDROID_HOME` 必须指向 SDK；`ANDROID_NDK_HOME` 可以省略，构建脚本会选择固定 NDK。Debug APK 位于 `app/build/outputs/apk/debug/app-debug.apk`。

## 当前门禁

```sh
pnpm android:rust:test
pnpm android:contract:test
pnpm android:build
./gradlew -p apps/android lintDebug
```

模拟器只用于开发冒烟。`FLAG_SECURE`、后台/锁屏、任务划除、进程终止和 backup exclusion 必须在 arm64 真机完成 `AT-ANDROID-001` 后才能视为通过；Login CRUD 使用 `AT-ANDROID-002`，搜索与回收站使用 `AT-ANDROID-003`。
