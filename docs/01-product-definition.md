# 产品定义

## 产品一句话

VaultMesh 是无需账号或服务器、由本机桌面应用持有加密 Vault，并通过受控浏览器扩展提供管理和自动填充能力的本地优先密码管理器。经配对授权的桌面设备可以在同一局域网且双方解锁时自动双向同步。

## 产品承诺

1. 用户可以离线创建、解锁、管理、备份和恢复 Vault。
2. 忘记主密码时不存在恢复后门；备份也必须使用其主密码。
3. 桌面 renderer、浏览器扩展和网页不能直接读取 Vault 文件或 Vault Key。
4. 桌面与浏览器授权相互独立；撤销配对立即取消浏览器能力。
5. 受保护值只在有界操作中进入内存、页面或剪贴板，不进入日志和持久化 UI 状态。
6. Vault mutation 在原子提交失败时保留旧文件和旧内存状态。
7. 自动填充不会自动提交表单，也不会把页面已有值发送给桌面端。

## 当前用户界面

- Tauri 2 desktop：macOS/Windows 共享 React presentation，由 Rust runtime 拥有 Vault 和所有特权操作。
- Chromium MV3 extension：popup、background worker 和 content script；依赖正在运行且已配对的桌面端。
- Electron 与 SwiftUI/WinUI：源码已移除；旧 Electron 加密 user-data 只保留用于迁移和数据回退。

## 核心工作流

- 创建/解锁/锁定 Vault，使用可选 PIN 或平台 quick unlock。
- 管理 login、payment card、SSH credential、identity、developer/service secret。
- 按网站/服务聚合并导航多个账号、密钥、SSH 凭据与 Passkey，同时保留原 item 的独立安全边界。
- 恢复 trash/history、轮换主密码、创建/恢复加密备份。
- 检查密码健康、生成凭证、使用有过期时间的特权剪贴板。
- 配对浏览器，显式或按策略自动填充，捕获用户确认的新/更新数据。
- 使用 Chromium WebAuthn proxy 管理软件 Passkey。
- 配置只读邮件来源，提取并短暂提供 email OTP。

## 非目标

- 账号、云服务、跨网络或锁定期间同步、分享、团队 Vault 或服务端恢复。
- 自动表单提交或确认远端服务已经接受登录/修改。
- 从 SMS 捕获 OTP。
- 在扩展、native host 或 renderer 中实现 Vault 加密和持久化。
- 当前版本中的 SwiftUI/WinUI 完整客户端。
- WebAuthn conditional mediation、largeBlob 或 PRF。

## 成功不变量

- 复制的 Vault 在没有主密码时不可读且不可静默篡改。
- 任一秘密从创建到销毁都有明确所有者和清理路径。
- Browser RPC、IPC、格式和 ABI 的版本不匹配均 fail closed。
- 任一公开能力都能从 Requirement 追踪到 Spec/ADR、实现和测试证据。
