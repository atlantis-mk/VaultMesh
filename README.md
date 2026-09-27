<h1 align="center">VaultMesh</h1>

<p align="center">
  <strong>本地优先的密码管理器</strong><br>
  没有账号，没有服务器，加密 Vault 只存放在你自己的设备上。
</p>

<p align="center">
  <a href="https://github.com/atlantis-mk/VaultMesh/releases/tag/v0.1.1-review"><img src="https://img.shields.io/github/v/release/atlantis-mk/VaultMesh?include_prereleases&amp;style=flat&amp;label=release&amp;color=4D6BFE" alt="Latest release"></a>
  <a href="https://github.com/atlantis-mk/VaultMesh/releases/tag/v0.1.1-review"><img src="https://img.shields.io/github/downloads/atlantis-mk/VaultMesh/total?style=flat&amp;label=downloads&amp;color=4D6BFE" alt="Total downloads"></a>
  <a href="https://github.com/atlantis-mk/VaultMesh/actions/workflows/document-governance.yml"><img src="https://github.com/atlantis-mk/VaultMesh/actions/workflows/document-governance.yml/badge.svg" alt="Document governance"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-E5534B?style=flat" alt="PolyForm Noncommercial License"></a>
  <img src="https://img.shields.io/badge/macOS%20%7C%20Windows%20%7C%20Android%20%7C%20Chrome%20%7C%20Firefox-4493F8?style=flat" alt="Supported platforms: macOS, Windows, Android, Chrome and Firefox">
</p>

<p align="center">
  <a href="https://blog.atlankj.com/products/vaultmesh"><strong>产品介绍与下载</strong></a>
  ·
  <a href="https://github.com/atlantis-mk/VaultMesh/releases/tag/v0.1.1-review">GitHub Releases</a>
  ·
  <a href="SECURITY.md">安全策略</a>
</p>

<p align="center">
  <a href="https://blog.atlankj.com/products/vaultmesh">
    <img src="https://blog.atlankj.com/api/media/file/vaultmesh-product-hero-20260811.png" alt="VaultMesh 界面预览" width="100%">
  </a>
</p>

VaultMesh 是一个源码可见的本地优先密码管理器，覆盖 macOS / Windows 桌面端（Tauri 2）、Android 客户端（Jetpack Compose）以及 Chrome / Firefox 浏览器扩展。Vault 的加密、格式、模型与解锁会话由共享的 Rust core 统一拥有，各客户端只通过受控接口调用它。

经过配对授权的设备可以在同一局域网内双向同步；Vault 锁定时只收发密文，解锁后再验证合并。没有云端账号、跨网络同步、分享或恢复后门。

> [!WARNING]
> 当前版本是 `0.1.1-review`（Review 预发布）。独立的密码学/内存审计、目标平台签名与安装验收等门禁尚未全部完成。请把源码和 review build 视为开发中软件，不要将其当作已经完成安全审计的生产密码管理器。

## 下载与安装

推荐前往[产品介绍页](https://blog.atlankj.com/products/vaultmesh)下载，也可以从 [GitHub Releases](https://github.com/atlantis-mk/VaultMesh/releases/tag/v0.1.1-review) 获取安装包。

| 平台 | 架构 | 安装包 |
| --- | --- | --- |
| macOS Apple Silicon | `aarch64` | DMG |
| macOS Intel | `x86_64` | DMG |
| Windows 10/11 | `x64` | NSIS 安装程序 / MSI |
| Android | `arm64-v8a` / `armeabi-v7a` / `x86_64` / universal | APK |
| Chrome / Chromium | MV3 | 扩展 ZIP（侧载） |
| Firefox | MV2 | 扩展 ZIP（侧载） |

浏览器扩展需要配合正在运行、并已完成配对的桌面端使用。桌面端会通过 Review 渠道检查新版本；Android 会在前台检查更新，并交由系统浏览器下载。

> 当前安装包尚未进行 Apple notarization 或 Windows Authenticode 签名，首次打开时系统可能显示“未知开发者”或类似提示。请确认下载来源后再放行。

### macOS 安装错误

**问题：“无法打开，因为无法验证开发者。”**

解决方案：将应用拖入“应用程序”文件夹，在 Finder 中按住 `Control` 键点按应用图标，选择“打开”，再在弹窗中确认“打开”。

**问题：“Apple 无法检查其是否包含恶意软件。”**

解决方案：打开“系统设置”→“隐私与安全性”，找到被拦截的应用，选择“仍要打开”，然后在弹窗中再次确认。

**问题：“应用已损坏，无法打开。您应该将它移到废纸篓。”**

解决方案：打开“终端”，执行以下命令移除此应用的隔离属性，然后重新打开应用：

```sh
xattr -dr com.apple.quarantine "/Applications/VaultMesh.app"
```

## 主要功能

| 功能 | 说明 |
| --- | --- |
| 本地加密 Vault | 离线创建、解锁、管理 Vault，支持可选 PIN 与平台快速解锁 |
| 多种凭据类型 | 登录、支付卡、SSH 凭据、身份信息、开发者/服务密钥，按网站聚合多个账号 |
| 浏览器自动填充 | Chrome / Firefox 扩展经配对后填充与保存凭据，从不自动提交表单 |
| Passkey | 通过 Chromium WebAuthn proxy 管理软件 Passkey |
| 局域网同步 | 已授权设备在同一局域网双向同步，锁定时只传输密文 |
| 设备填充互通 | 授权后 Android 可在锁屏时提供本机号码与短时验证码 |
| 邮件验证码 | 配置只读邮件来源，提取并短暂提供 email OTP |
| 备份与恢复 | 加密备份、回收站与历史记录恢复、主密码轮换 |
| 密码健康 | 检查密码健康，生成新凭据 |
| 安全剪贴板 | 敏感值只在有界操作中读取，复制到剪贴板后自动过期清除 |

## 安全设计

- **没有恢复后门**：忘记主密码即无法恢复，备份同样需要其主密码。
- **最小权限**：Tauri renderer 不直接拥有 filesystem、Node 或通用命令执行权限，所有特权操作由 Rust runtime 负责。
- **扩展只是代理**：浏览器扩展是瞬态远程 UI/自动填充代理，不打开也不持久化 Vault，页面已有字段值不会发送给桌面端。
- **独立授权**：桌面与扩展授权相互独立；撤销配对立即取消浏览器能力，最后一个授权锁定后清除解密核心。
- **原子写入**：Vault 修改先原子写盘成功再发布新状态，失败时保留旧文件和旧内存状态。
- **版本不匹配即拒绝**：Browser RPC、IPC、Vault 格式和 ABI 版本不一致时一律 fail closed。

正式范围、架构和安全约束以 [`AGENTS.md`](AGENTS.md) 与 [`docs/00-spec-index.md`](docs/00-spec-index.md) 为准。

## 架构

```text
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│ Tauri 2 桌面端    │  │ Android Compose  │  │ Chrome / Firefox 扩展 │
│ React renderer   │  │ Kotlin 平台服务   │  │ popup / content script│
└────────┬─────────┘  └────────┬─────────┘  └──────────┬───────────┘
         │ typed operation     │ 窄 JNI runtime        │ native messaging
         ▼                     ▼                       ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│ Rust desktop     │  │ Android runtime  │  │ native host（只转发）  │
│ runtime          │  │                  │  │ → 桌面 runtime        │
└────────┬─────────┘  └────────┬─────────┘  └──────────────────────┘
         └──────────┬──────────┘
                    ▼
          ┌──────────────────┐
          │ crates/vault-core│  加密 · 格式 · 模型 · 解锁会话 · 回滚
          └──────────────────┘
```

## 本地开发

需要 Rust stable、Node.js、pnpm 11.1.1，以及目标平台的 Tauri 2 系统依赖；Android 开发另需 Android SDK / NDK。

```sh
git clone https://github.com/atlantis-mk/VaultMesh.git
cd VaultMesh
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
```

常用命令：

| 命令 | 用途 |
| --- | --- |
| `pnpm tauri:dev` | 启动 Tauri 桌面开发环境 |
| `pnpm extension:dev` | 启动浏览器扩展开发环境 |
| `pnpm android:build` | 构建 Android Debug APK |
| `pnpm test` | 运行 Rust、桌面端与扩展测试 |
| `pnpm typecheck` | 桌面端与扩展类型检查 |
| `pnpm docs:check` | 校验规格、追踪矩阵与发布记录 |

开发和测试只能使用虚构凭据。不要提交真实 Vault、备份、恢复秘密、OAuth token、签名密钥或解密 fixture。

## 贡献与安全

提交改动前请阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)。安全问题不要创建公开 Issue；请按 [`SECURITY.md`](SECURITY.md) 使用 GitHub 私密漏洞报告。隐私说明见 [`PRIVACY.md`](PRIVACY.md)。

## 许可证

当前版本中由授权方拥有或有权许可的 VaultMesh 源代码按 [PolyForm Noncommercial License 1.0.0](LICENSE) 提供，SPDX 标识为 `PolyForm-Noncommercial-1.0.0`，仅允许该许可证定义的非商业用途。本项目是 source-available 软件，不是 OSI 认可的开源软件。

商业使用需要另行取得书面授权，联系 `atlantis-mk <atlanxg@gmail.com>`。完整边界、历史 AGPL 授权和第三方材料说明见 [`LICENSING.md`](LICENSING.md)，商业授权入口见 [`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md)。

Required Notice: Copyright 2026 atlantis-mk <atlanxg@gmail.com>
