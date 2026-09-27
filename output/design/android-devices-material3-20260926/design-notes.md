# VaultMesh Android 设备页 · Material 3 设计稿

2026-09-26。设计预览，未实施本轮 UI 变更。范围为 Android 设备页全部现有功能。

使用内置 image_gen 工具生成；四张图属于同一套设计，不是互斥备选。

## 最终设计图

- [设备列表、发现、空态](01-device-list-discovery.png)
- [输入配对码、失败重试、配对成功](02-pairing-flow.png)
- [设备操作菜单、重命名、撤销确认](03-device-management.png)
- [读取中、读取失败、本地网络未就绪](04-loading-errors.png)

## 交互分工

- 页面列表：已配对设备、附近设备、配对中和验证状态。
- 页面发现区：显式开启/停止、当前六码、剩余时间、扫描；默认关闭。
- 每行更多菜单：重命名、撤销配对。
- 弹窗：输入对方配对码、重命名、撤销确认。配对失败留在输入弹窗内显示原因，不叠加新弹窗。
- 页面状态：读取中、无已配对设备、无附近设备、读取失败可重试、本地网络/权限不足可重试。
- 成功反馈：新设备加入列表，Snackbar 明示同步授权；不显示未实现的后台同步进度。

## 状态补充

- 配对流程修订图右侧空态的辅助句由图像模型误用了“开启发现，配对你的第一台设备”；定稿应为“请在另一台设备开启发现”，因为本页已有已配对设备且发现已经开启。以这里的状态语义为准。
- 空配对码时图中的“重试”按钮应在实现时禁用；填满六位数字后才可提交。菜单省略号方向在定稿时统一为竖向，发现停止按钮使用outlined或tonal次要样式。

- 六位数字完整时才可提交；配对中禁用重复提交并清除提交过的输入。
- 配对尝试次数耗尽时禁用提交；本机码次数耗尽时隐藏数字并说明需重新开启发现。
- 身份变化：列表行显示需要撤销旧信任，再走现有撤销确认流程。
- 安全连接/保存信任失败：使用同一错误区域显示具体原因，不显示为配对成功。
- 保存名称/撤销进行时禁用重复提交，失败保留弹窗并显示错误，成功更新列表。
- 名称必须非空且不超过64字符；取消清理输入。
- 十分钟到期、离页、锁定、Activity暂停、权限或Wi-Fi失效停止发现并清理临时代码；重新进入不得自动开启。
- 图中设备名称和六码均为合成演示数据。没有服务器、账号、跨网连接、QR扫码或后台同步功能的新增承诺。
- 四张图中的十二个关键界面呈现全部主要操作；长列表在页面内滚动，底部导航固定。输入时使用系统键盘并按Insets调整弹窗。

## 提示词

### designPrompt1

```text
Use case: ui-mockup.
Create realistic production-quality native Android Material Design 3 UI for VaultMesh, a local-first password manager. This is one coherent design system, not competing design alternatives. Chinese interface.
Asset type: a high-fidelity design review board containing THREE related state screens in a single horizontal row. Each app viewport has natural logical dimensions 390 x 844, no stretching. Overall high-resolution landscape board approximately 2400 x 1800 with three equal app-content rectangles and modest neutral gutters. Screens large, text crisp and legible, concise Chinese captions OUTSIDE each screen. App content only: no phone hardware, bezel, notch, OS status icons, clock, battery, home indicator, perspective, decorative illustration, or watermark. Do not clip content.
Visual system grounded in current Kotlin Compose theme: primary #365BD8, primary container #DCE4FF, background/surface #F8FAFF, surface variant #E9EEF9; on-surface dark ink. Noto Sans SC / Roboto, restrained Material Symbols outlined icons, 24dp horizontal gutters, readable 14–16sp body, 28sp title. Material medium top app bar '设备' with a lock icon button at right; bottom navigation always visible with exactly '保险库' '工具' '设备' '设置', 设备 selected in blue tonal pill. Rounded filled primary buttons, 28dp corner dialogs, 48dp touch targets, spacious grouped list rows and fine separators, no card-per-row or nested cards, no gradients, no glass. One primary action per state.
Functional truth from apps/android/app/src/main/java/com/vaultmesh/app/LanPairingUi.kt and REQ-ANDROID-021: paired devices are ALWAYS a page list, never a modal. Discovery is explicitly started and lasts <=10 minutes; stopping/leaving/locking ends discovery. Local code can be shown; user inputs the OTHER device's six-digit code to pair; successful pairing grants current vault sync authorization. Do not claim active background sync, sync progress, account/cloud, internet remote access, QR scanning, clipboard copy of code, or device IP/fingerprint/last-seen values. Trusted labels are user labels; untrusted peers use opaque safe names e.g. 'VaultMesh A31F20'. '已配对' does not mean online. All sample data synthetic, pairing code 482 716 demo only. Current date 2026-09-26; omit dates.

Board theme: 设备列表与发现. THREE screens left-to-right:
LEFT caption '设备列表': top bar. Section '已配对设备' small count '2'. Two clean rows with generic desktop monitor icons, labels '我的 MacBook' and '办公电脑', secondary '已配对', trailing vertical-ellipsis menu icons. Below list, one tonal discovery area titled '配对新设备', text '与同一局域网中的设备安全配对', status '发现已关闭', primary button '开启发现'. Small supporting text '每次最多 10 分钟，离开页面即停止'. Generous whitespace.
MIDDLE caption '发现已开启': same two paired rows at top in compact group; lower tonal area titled '本机配对码' with prominent spaced '482 716', small timer '剩余 09:42', explanation '在另一台设备输入此码', action '停止发现'. Below, section '附近设备' and small refresh icon button labelled '扫描'. Two discovered rows: 'VaultMesh A31F20' secondary '尚未配对' action '配对'; 'VaultMesh D72B08' secondary '正在安全配对' with small progress spinner, disabled interaction. Small consent text '配对后将授权当前保险库同步'. Avoid overcrowding: use space between groups and readable typography.
RIGHT caption '暂无已配对设备': same navigation and top bar; section '已配对设备'; centered modest outlined devices icon, '还没有已配对设备', short '开启发现，配对你的第一台设备'. Lower tonal discovery block, '发现已关闭', '开启发现' primary and same 10-minute helper.
All three show natural consistent app screens, clean row hierarchy. Only screen captions outside UI, no marketing headline.

```

### designPrompt2

```text
Use case: ui-mockup.
Create realistic production-quality native Android Material Design 3 UI for VaultMesh, a local-first password manager. This is one coherent design system, not competing design alternatives. Chinese interface.
Asset type: a high-fidelity design review board containing THREE related state screens in a single horizontal row. Each app viewport has natural logical dimensions 390 x 844, no stretching. Overall high-resolution landscape board approximately 2400 x 1800 with three equal app-content rectangles and modest neutral gutters. Screens large, text crisp and legible, concise Chinese captions OUTSIDE each screen. App content only: no phone hardware, bezel, notch, OS status icons, clock, battery, home indicator, perspective, decorative illustration, or watermark. Do not clip content.
Visual system grounded in current Kotlin Compose theme: primary #365BD8, primary container #DCE4FF, background/surface #F8FAFF, surface variant #E9EEF9; on-surface dark ink. Noto Sans SC / Roboto, restrained Material Symbols outlined icons, 24dp horizontal gutters, readable 14–16sp body, 28sp title. Material medium top app bar '设备' with a lock icon button at right; bottom navigation always visible with exactly '保险库' '工具' '设备' '设置', 设备 selected in blue tonal pill. Rounded filled primary buttons, 28dp corner dialogs, 48dp touch targets, spacious grouped list rows and fine separators, no card-per-row or nested cards, no gradients, no glass. One primary action per state.
Functional truth from apps/android/app/src/main/java/com/vaultmesh/app/LanPairingUi.kt and REQ-ANDROID-021: paired devices are ALWAYS a page list, never a modal. Discovery is explicitly started and lasts <=10 minutes; stopping/leaving/locking ends discovery. Local code can be shown; user inputs the OTHER device's six-digit code to pair; successful pairing grants current vault sync authorization. Do not claim active background sync, sync progress, account/cloud, internet remote access, QR scanning, clipboard copy of code, or device IP/fingerprint/last-seen values. Trusted labels are user labels; untrusted peers use opaque safe names e.g. 'VaultMesh A31F20'. '已配对' does not mean online. All sample data synthetic, pairing code 482 716 demo only. Current date 2026-09-26; omit dates.

Board theme: 配对流程. THREE screens left-to-right, same underlying Devices page with paired list and discovery active, local code block '482 716'. No extra pages/features.
LEFT caption '输入配对码': scrim dims underlying device page. A centered Material 3 dialog width about 330dp, rounded 28dp, title '输入配对码', subtitle '输入 VaultMesh A31F20 上显示的六位数字'. One real outlined numeric field labelled '六位配对码', value '593 204', large spaced digits (single field, not six separate fields). Informational small text '配对成功后，将授权当前保险库同步'. Bottom right text button '取消' and filled button '开始配对'. No numeric keyboard required in this review state. Show dialog clearly and large enough.
MIDDLE caption '配对失败 · 可重试': same centered dialog over scrim, title '输入配对码', same peer instruction; same input in error state red outline and empty six digit placeholder; inline error '配对码错误，请核对后重试'. Actions '取消' and filled '重试'. Do not use separate error modal. Maintain exact same geometry.
RIGHT caption '配对成功': No modal. Device page with section '已配对设备' and THREE rows '我的 MacBook', '办公电脑', 'VaultMesh A31F20', each secondary '已配对' with trailing ellipsis. Below a compact discovery section shows code and '停止发现', discovery remains user-controlled. A Material snackbar above bottom navigation says '配对成功，已授权当前保险库同步', no invented secondary action. Newly paired device subtly highlighted with pale primary container as temporary success state. No sync progress, no cloud claim.
Use consistent typography and components; focused main task. Captions outside screens; readable Chinese.

```

### designPrompt3

```text
Use case: ui-mockup.
Create realistic production-quality native Android Material Design 3 UI for VaultMesh, a local-first password manager. This is one coherent design system, not competing design alternatives. Chinese interface.
Asset type: a high-fidelity design review board containing THREE related state screens in a single horizontal row. Each app viewport has natural logical dimensions 390 x 844, no stretching. Overall high-resolution landscape board approximately 2400 x 1800 with three equal app-content rectangles and modest neutral gutters. Screens large, text crisp and legible, concise Chinese captions OUTSIDE each screen. App content only: no phone hardware, bezel, notch, OS status icons, clock, battery, home indicator, perspective, decorative illustration, or watermark. Do not clip content.
Visual system grounded in current Kotlin Compose theme: primary #365BD8, primary container #DCE4FF, background/surface #F8FAFF, surface variant #E9EEF9; on-surface dark ink. Noto Sans SC / Roboto, restrained Material Symbols outlined icons, 24dp horizontal gutters, readable 14–16sp body, 28sp title. Material medium top app bar '设备' with a lock icon button at right; bottom navigation always visible with exactly '保险库' '工具' '设备' '设置', 设备 selected in blue tonal pill. Rounded filled primary buttons, 28dp corner dialogs, 48dp touch targets, spacious grouped list rows and fine separators, no card-per-row or nested cards, no gradients, no glass. One primary action per state.
Functional truth from apps/android/app/src/main/java/com/vaultmesh/app/LanPairingUi.kt and REQ-ANDROID-021: paired devices are ALWAYS a page list, never a modal. Discovery is explicitly started and lasts <=10 minutes; stopping/leaving/locking ends discovery. Local code can be shown; user inputs the OTHER device's six-digit code to pair; successful pairing grants current vault sync authorization. Do not claim active background sync, sync progress, account/cloud, internet remote access, QR scanning, clipboard copy of code, or device IP/fingerprint/last-seen values. Trusted labels are user labels; untrusted peers use opaque safe names e.g. 'VaultMesh A31F20'. '已配对' does not mean online. All sample data synthetic, pairing code 482 716 demo only. Current date 2026-09-26; omit dates.

Input image role: reference image of the chosen coherent design system and exact base Devices page layout. Continue this layout, typography, colors, row geometry, top app bar and bottom navigation. This is the DEVICE MANAGEMENT board, three states of the same device list, NOT alternate designs.
LEFT caption '设备操作菜单': base paired list with two rows, '我的 MacBook' and '办公电脑'; discovery disabled below. A small elevated Material dropdown anchored to the trailing vertical ellipsis of '我的 MacBook', with exactly two menu rows and real outline icons: '重命名' and red '撤销配对'. No full-screen scrim for menu. List remains clearly the page content.
MIDDLE caption '重命名': same background with dim scrim, centered Material 3 dialog, title '重命名设备', outlined single text field labelled '设备名称', value '我的 MacBook', helper character count '10/64', bottom actions '取消' text and '保存' filled blue. Cursor visible, no keyboard in this review state. Do not include pairing controls inside dialog.
RIGHT caption '撤销确认': same background with dim scrim, centered Material 3 confirmation dialog. Small neutral device-shield outline icon, title '撤销与此设备的配对？'; selected device name '我的 MacBook' in medium weight; body EXACT '将移除此设备的信任和当前保险库同步授权。再次连接需要重新配对。'; actions '取消' and red text button '撤销配对'. No password field, no pretend delete-vault warning, no switch.
All three dialogs/menus comfortably legible. Match attached reference precisely in surrounding app layout; no added feature. Chinese captions outside screens at TOP.

```

### designPrompt4

```text
Use case: ui-mockup.
Create realistic production-quality native Android Material Design 3 UI for VaultMesh, a local-first password manager. This is one coherent design system, not competing design alternatives. Chinese interface.
Asset type: a high-fidelity design review board containing THREE related state screens in a single horizontal row. Each app viewport has natural logical dimensions 390 x 844, no stretching. Overall high-resolution landscape board approximately 2400 x 1800 with three equal app-content rectangles and modest neutral gutters. Screens large, text crisp and legible, concise Chinese captions OUTSIDE each screen. App content only: no phone hardware, bezel, notch, OS status icons, clock, battery, home indicator, perspective, decorative illustration, or watermark. Do not clip content.
Visual system grounded in current Kotlin Compose theme: primary #365BD8, primary container #DCE4FF, background/surface #F8FAFF, surface variant #E9EEF9; on-surface dark ink. Noto Sans SC / Roboto, restrained Material Symbols outlined icons, 24dp horizontal gutters, readable 14–16sp body, 28sp title. Material medium top app bar '设备' with a lock icon button at right; bottom navigation always visible with exactly '保险库' '工具' '设备' '设置', 设备 selected in blue tonal pill. Rounded filled primary buttons, 28dp corner dialogs, 48dp touch targets, spacious grouped list rows and fine separators, no card-per-row or nested cards, no gradients, no glass. One primary action per state.
Functional truth from apps/android/app/src/main/java/com/vaultmesh/app/LanPairingUi.kt and REQ-ANDROID-021: paired devices are ALWAYS a page list, never a modal. Discovery is explicitly started and lasts <=10 minutes; stopping/leaving/locking ends discovery. Local code can be shown; user inputs the OTHER device's six-digit code to pair; successful pairing grants current vault sync authorization. Do not claim active background sync, sync progress, account/cloud, internet remote access, QR scanning, clipboard copy of code, or device IP/fingerprint/last-seen values. Trusted labels are user labels; untrusted peers use opaque safe names e.g. 'VaultMesh A31F20'. '已配对' does not mean online. All sample data synthetic, pairing code 482 716 demo only. Current date 2026-09-26; omit dates.

Input image role: visual reference for the exact chosen Devices page structure, colors, type and navigation. Continue it rather than redesigning.
Board theme: 加载与异常. THREE screens, top Chinese captions outside each viewport.
LEFT caption '读取设备列表': main page with top bar and navigation. '已配对设备' section, small Material circular progress indicator and '正在读取已配对设备…' with ample whitespace. No false empty-state text, no invented devices. Discovery area beneath shows '配对新设备', explanation '列表读取完成后可开启发现', disabled primary button '开启发现'. The loading indicator is modest and respects Material typography.
MIDDLE caption '读取失败': top bar and nav, '已配对设备', inline neutral error icon and text '暂时无法读取设备列表', helper '请重试加载', outlined '重新加载' action, no modal and no empty-state assertion. Discovery button disabled. Material error treatment uses muted red only for error icon and concise text, not a giant red card. Enough whitespace.
RIGHT caption '本地网络未就绪': real paired list showing '我的 MacBook' and '办公电脑' with secondary '已配对' and more menus still usable. Discovery block '配对新设备', state '发现已关闭', two-line inline warning '请连接同一局域网，并允许本地网络访问', action '重试开启'. Small note '系统权限会在开启时请求'. Below it a concise persistent-helper line '发现到期、离页或锁定后自动停止，可再次开启'. No system permission dialog invented. No network toggle or fake settings link. Keep safe paired metadata available even while discovery is unavailable.
Bottom nav same as reference: 保险库 工具 设备 设置, device icon is generic monitor not phone. Consistent exact visual theme, app content only.

```

### designPrompt2Revision

```text
undefined
```
