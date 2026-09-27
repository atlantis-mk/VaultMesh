# Android 设备页设计验收

日期：2026-09-26。最终结果：**passed**。

本次将已确认的 Material 3 设计实现为现有 Android Jetpack Compose 界面。适用需求为 REQ-ANDROID-021、REQ-ANDROID-001，回归覆盖 CT-ANDROID-LAN-PAIRING-001 与 CT-ANDROID-JNI-001 的适用部分。

## 设计与验收证据

设计源位于 [设计目录](output/design/android-devices-material3-20260926/)，包括 `01-device-list-discovery.png`、`02-pairing-flow.png`、`03-device-management.png`、`04-loading-errors.png`；交互解释以同目录的 [design-notes.md](output/design/android-devices-material3-20260926/design-notes.md) 为准。

真机为 2206122SC，Android 16，截图 1440 × 3200，密度 560 dpi。设计画板的单屏内容约为 390 × 844；真机内容按约 411 dp 宽度评估。对照时比较内容层级、间距和组件关系，系统栏与原生字体差异不按逐像素误差处理。

以下截图来自隔离的 Compose 测试宿主，使用实际页面、主题和导航组件及合成设备数据，不读取用户 Vault。截图目录为 [device-design-qa](output/design/android-devices-material3-20260926/qa/device-design-qa/)。

| 状态 | 真机截图 | 结果 |
| --- | --- | --- |
| 已配对列表 | `01-list.png` | 常驻页面，数量、分隔线、设备状态和操作入口完整 |
| 开启发现 | `02-discovery.png` | 配对码、倒计时、停止发现及附近设备列表完整 |
| 设备菜单 | `03-menu.png` | 重命名和撤销配对，锚定对应设备 |
| 重命名 | `04-rename.png` | 独立弹窗，输入与取消/保存操作完整 |
| 撤销配对 | `05-revoke.png` | 独立确认弹窗，明确目标设备 |
| 空列表 | `06-empty.png` | 空状态及开启发现入口完整 |
| 加载中 | `07-loading.png` | 明确加载反馈 |
| 加载失败 | `08-load-error.png` | 错误说明与重新加载入口完整 |
| 网络不可用 | `09-network-error.png` | 保留已配对设备，显示网络错误及重试 |
| 输入配对码 | `10-code.png` | 独立配对弹窗，六位数字校验 |
| 配对失败 | `11-code-error.png` | 弹窗内错误提示及重试路径 |
| 配对成功 | `12-success.png` | 实际受信任列表更新后关闭弹窗，更新列表并提示成功 |

## 视觉复核

- 布局：列表、发现卡片、附近设备和底部导航层级与设计一致；上述十二种状态未见文字截断或控件重叠。
- 字体：使用原生 Material 3 字体排版，标题、正文和辅助文字层级清晰。
- 色彩：统一蓝色主色、浅蓝发现卡片和近白色弹窗；选中导航和操作按钮不再出现默认紫色。
- 图标：采用官方 Material 图标，复用现有导航资源；撤销使用断开链接图标，避免暗示删除 Vault。
- 文案与交互：已配对列表常驻；菜单、输入配对码、重命名和撤销确认各自使用适当容器；提交配对请求不提前宣告成功。

复核中已修正选中导航的默认紫色、弹窗默认底色，以及“停止发现”按钮类似禁用态的描边和文字颜色。最终截图确认以上修正。

与生成图的有意差异：停止发现为蓝色描边次要按钮；不足六位的配对码不可提交；成功后不显示“配对第一台设备”的空状态文案；系统键盘、系统栏和安全限制遵循原生应用行为。现有导航图标笔画及原生字体与生成图存在轻微差异，属 P3 外观差异。没有未解决的 P0、P1 或 P2 问题。

## 验证

- 真机 Compose 界面回归：3 组通过，覆盖菜单与设备管理、空/加载/错误状态、配对输入/失败/成功/停止发现。见 [instrumentation-result.txt](output/design/android-devices-material3-20260926/qa/instrumentation-result.txt)。
- Android JVM 单元测试：7 项通过。
- Android 合同检查：28 项通过。
- Debug APK、测试 APK 构建及 Android Lint 通过。
- 文档 Traceability 生成与文档检查通过；适用文件 diff 空白检查通过。

这些界面测试使用合成状态验证实际 Compose 组件。本次没有重新执行桌面与 Android 之间的完整局域网配对端到端验收，也未更改配对协议、信任边界或 JNI 公共契约。
