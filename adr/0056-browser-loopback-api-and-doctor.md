# ADR-0056：浏览器本地回环动态端口 API 连接重构与 Doctor 诊断体系

- 状态：Accepted
- 日期：2026-11-10
- 关联 Work：`CHG-2026-081-browser-doctor-and-api-service`
- 关闭 OPEN：无

## 背景

在原有架构中，浏览器扩展与桌面端的 IPC 连接依赖本地配置文件与钥匙串直读：
1. **本地配置文件与严格权限脆弱性**：桌面端写入 `browser-host-config.json` 并强制要求 `0600` 权限；在 macOS 多用户、沙盒、权限继承或临时目录清理场景下，`vaultmesh-native-host` 常因无法读取配置文件或权限不符而直接退出。
2. **时序与钥匙串 ACL 竞态**：Native Host 曾试图在独立进程中打开 `DeviceCredentialStore` 或直接读取 macOS 系统钥匙串根秘密；当桌面端尚未完成主存储迁移、主程序未启动或钥匙串访问被拒时，Native Host 抛出 `RequireDesktopMigrate` 并输出 `unpaired` 导致假死。
3. **macOS 启动参数匹配缺陷**：Windows 端兼容 Chromium 传入的 `--parent-window` 参数，而 macOS 端只匹配单参数 `[origin]`，导致部分 Chromium 分支启动直接被判为非法调用。
4. **支持浏览器狭窄**：仅在 Chrome、Edge、Firefox 目录下注册 Manifest，缺少 Brave、Arc、Vivaldi、Chromium 等主流 Chromium 衍生浏览器支持。
5. **后台常驻失效**：主窗口关闭时触发 `RunEvent::ExitRequested { code: None, .. }`，原有逻辑直接执行清理并允许退出，导致后台监听器断开。
6. **macOS Doctor 诊断缺失**：设置页中的浏览器集成状态在 macOS 下硬编码返回 `supported: false`，用户遇到连接失败时无法获取任何诊断信息或修复手段。
7. **缺乏扩展安装引导**：检测到系统安装了浏览器但用户尚未安装扩展时，缺乏直接跳转官方扩展商店的一键安装通道。

## 决策

1. **保留 Native Messaging 强 Origin 边界，Native Host 彻底无状态化**：
   - 浏览器端继续使用官方 `chrome.runtime.connectNative("com.vaultmesh.browser")`，由浏览器内核强行保证发起端必须为指定固定 Extension ID（Chrome Web Store 公钥派生 ID `bdneegbnjbheblmamalplnddbodcghbg` 或 Firefox Gecko ID `vaultmesh@atlantis-mk.github.io`）。
   - 彻底废除 `browser-host-config.json` 与 Native Host 中的 `DeviceCredentialStore` / 钥匙串直读代码。Native Host 启动时不再读写任何磁盘配置文件或访问钥匙串。
   - 统一对齐 macOS 与 Windows 的命令行参数校验：Chromium 系列匹配 `[origin]` 或 `[origin, _]`（兼容 `--parent-window`）；Firefox 匹配 `[manifest_path, extension_id]`。

2. **桌面端本地回环动态端口 HTTP API 服务 (`browser_broker_http`)**：
   - 桌面主进程启动时，在 `127.0.0.1:42800..=42850` 动态端口池中自动绑定首个可用端口，提供内部回环 HTTP 服务。
   - 提供 `GET /discover` 端点：返回 `200 OK` 及 `{"service":"vaultmesh-desktop","version":2,"port":<u16>}`。
   - 提供 `POST /rpc` 端点：接收 JSON-RPC 请求，通过桌面主进程的 `BrowserBrokerCore` 处理后返回响应，完整支持即时响应与挂起授权（如临时解锁弹窗等待）。
   - **严格防御网页探测与跨站攻击**：
     - `POST /rpc` 强制校验请求头 `X-VaultMesh-Browser-Origin` 必须匹配白名单 Origin；
     - 严禁返回任何 `Access-Control-Allow-*` 跨域头；
     - 凡携带 `Origin`、`Sec-Fetch-*` 请求头或使用 `OPTIONS` 预检方法的请求，一律直接返回 `403 Forbidden`。普通网页无法通过 `fetch` 探测或调用该端口。

3. **桌面主窗口关闭后台常驻与 macOS 后台权限引导**：
   - 修复主窗口关闭逻辑：在 `RunEvent::ExitRequested { code: None, api }` 中调用 `api.prevent_exit()`，保持托盘图标与本地 API 服务常驻；仅在用户通过系统托盘菜单或原生应用菜单显式选择退出（`app.exit(0)`）时才执行 `cleanup_app_state` 并退出。
   - 在 `desktop_startup` 中增加 macOS 登录项与后台运行权限检测，提供 `desktop.startup.open-system-settings` 操作，在 macOS 下直接唤起 `x-apple.systempreferences:com.apple.LoginItems-Settings.extension`（Windows 下唤起 `ms-settings:startupapps`）。

4. **跨平台 Doctor 诊断、一键自动修复与插件市场跳转**：
   - 自动扫描并识别系统已安装浏览器：Chrome、Edge、Firefox、Brave、Arc、Vivaldi、Chromium。
   - 跨平台启用 Doctor 诊断：`desktop.browser-integration.get` 在 macOS 和 Windows 均返回 `supported: true`，提供各项体检结果（后台常驻、本地 API 监听、Native Host 二进制、Manifest 注册、各浏览器插件安装状态）。
   - 自动检测各浏览器 Profile 目录下是否已安装 VaultMesh 扩展（通过读取扩展目录只读元数据）；若浏览器已安装但未检测到插件，在 Doctor 界面提供安装跳转按钮（Chrome 跳转至 Chrome Web Store 官方市场，其他未上架商店的浏览器跳转至当前版本对应的 GitHub Release 发布页）。点击后通过 `desktop.browser-integration.open-store` 调起打开对应页面。
   - 提供一键自动修复 (`desktop.browser-integration.retry`)：自动重启本地 API 监听、重写所有已识别浏览器的 Manifest 并执行端到端往返校验。

5. **浏览器扩展 Popup 增加断开重试引导**：
   - 保持 Popup 简洁直观，在断开提示条增加“重试连接”按钮，并指引用户确认桌面端已在后台运行或前往桌面端运行 Doctor 一键体检。

## 原因

- **根治文件权限与钥匙串竞态**：消除 Native Host 的本地文件和钥匙串依赖，所有凭据与 Vault 状态完全由桌面主进程托管。
- **兼顾极高安全与可靠性**：保留浏览器 `connectNative` 作为安全沙箱护城河，同时通过回环端口解决跨进程通信，防跨域探测策略阻断网页恶意请求。
- **完善排障与用户引导**：桌面端提供可视化的分项体检与自动修复能力，对齐主流开发者工具体验；浏览器未装插件时可一键直达安装。

## 后果

- `vaultmesh-native-host` 代码量大幅缩减，转为轻量、无状态的中继器。
- 桌面端设置页在 macOS 与 Windows 上呈现统一且强大的 Doctor 诊断面板。
- 浏览器连接稳定性显著提升，不再因时序或文件权限问题导致连接假死。

## 被拒方案

- **浏览器插件直接通过 `fetch` 连接本地回环端口**：
  - 被拒原因：失去浏览器 Native Messaging 提供的官方固定 Origin 白名单内核校验，网页或恶意脚本可能利用各种本地网络扫描手段对本地端口进行探测或重放，且 MV3 对后台脚本直接访问任意本地未声明端口有潜在限制。
- **保留 Unix Socket 并由 Native Host 仅读 Socket 路径**：
  - 被拒原因：macOS 跨进程访问 Unix Socket 仍受文件权限、路径长度限制及沙盒环境干扰，且 Windows 下 Named Pipe 逻辑完全不同；而本地回环 TCP 端口跨平台一致性高、无文件系统权限依赖。
