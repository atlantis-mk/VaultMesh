package com.vaultmesh.app

import android.graphics.Bitmap
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

// CT-ANDROID-LAN-PAIRING-001: real Compose components in an isolated test host.
// All device metadata and codes below are synthetic; no product Vault is opened.
@RunWith(AndroidJUnit4::class)
class LanDevicesPageTest {
    @get:Rule val compose = createComposeRule()
    private val peer = LanTrusted("lan-peer-0123456789abcdef0123456789abcdef", "我的 MacBook", 2)
    private val other = LanTrusted("lan-peer-1123456789abcdef0123456789abcdef", "办公电脑", 2)
    private val target = "lan-peer-00000000000000000000000000a31f20"
    private val idle = LanStatus(false, null, null, emptyList(), listOf(peer, other))
    private val panel = mutableStateOf(LanPanelState(status = idle))
    private var starts = 0
    private var renames = 0
    private var revokes = 0
    private var reloads = 0
    private var begins = 0

    private fun render() {
        compose.setContent {
            VaultMeshTheme {
                Scaffold(
                    containerColor = MaterialTheme.colorScheme.background,
                    topBar = { UnlockedHomeTopBar(HomeDestination.Devices) {} },
                    bottomBar = { HomeNavigationBar(HomeDestination.Devices) {} },
                ) { padding ->
                    LanDevicesPage(
                        panel = panel.value,
                        onStart = { starts++ }, onStop = { panel.value = panel.value.clearAction().withStatus(idle) },
                        onRefresh = {}, onReload = { reloads++ },
                        onSelectPair = { panel.value = panel.value.clearAction().copy(pairingRef = it) },
                        onCodeChange = { panel.value = panel.value.copy(codeInput = it) },
                        onBegin = { begins++; panel.value = panel.value.copy(pairingPending = true, codeInput = "") },
                        onSelectRevoke = { panel.value = panel.value.clearAction().copy(revokeRef = it) },
                        onRevoke = { revokes++; panel.value = panel.value.clearAction() },
                        onSelectRename = { ref, label -> panel.value = panel.value.clearAction().copy(renameRef = ref, labelInput = label) },
                        onLabelChange = { panel.value = panel.value.copy(labelInput = it) },
                        onRename = { renames++; panel.value = panel.value.clearAction() },
                        onCancelAction = { panel.value = panel.value.clearAction() },
                        modifier = Modifier.padding(padding),
                        deviceSettings = { selected ->
                            LanSyncPeerSettings(SyncUiState(listOf(SyncPeer(peer.pairingRef, true, "synced", null)), 0, 0),
                                selected, false, { _, _ -> }, null)
                        },
                    )
                }
            }
        }
    }

    @Test fun syncControlsRemainAvailableWithoutDiscovery() {
        var enabled: Boolean? = null
        var retried = 0
        val sync = SyncUiState(listOf(SyncPeer(peer.pairingRef, true, "delivered", null)), 0, 0)
        compose.setContent {
            VaultMeshTheme {
                Scaffold { padding ->
                    androidx.compose.foundation.layout.Box(Modifier.padding(padding)) {
                        androidx.compose.foundation.layout.Column {
                            LanSyncPanel(sync, "同步服务运行中", false, { retried++ }, {}, {}, null)
                            LanSyncPeerSettings(sync, peer, false, { _, value -> enabled = value }, null)
                        }
                    }
                }
            }
        }
        compose.waitUntil(15000) {
            compose.onAllNodesWithText("密文已送达，等待对端解锁合并")
                .fetchSemanticsNodes(atLeastOneRootRequired = false).isNotEmpty()
        }
        compose.onNodeWithText("密文已送达，等待对端解锁合并").assertIsDisplayed()
        compose.onNode(isToggleable()).performClick()
        assertEquals(false, enabled)
        compose.onNodeWithText("重试同步").performClick()
        assertEquals(1, retried)
    }

    @Test fun clearingSyncConflictsRequiresConfirmation() {
        var cleared = 0
        compose.setContent {
            VaultMeshTheme {
                Scaffold { padding ->
                    androidx.compose.foundation.layout.Box(Modifier.padding(padding)) {
                        SyncConflictDialog(listOf(SyncConflict("synthetic", "login", 1)), {}, { cleared++ }, {})
                    }
                }
            }
        }
        compose.waitUntil(15000) {
            compose.onAllNodesWithText("清空历史")
                .fetchSemanticsNodes(atLeastOneRootRequired = false).isNotEmpty()
        }
        compose.onNodeWithText("清空历史").performClick()
        assertEquals(0, cleared)
        compose.onNodeWithText("确认永久清空冲突历史？").assertIsDisplayed()
        compose.onNodeWithText("确认清空").performClick()
        assertEquals(1, cleared)
    }

    private fun capture(name: String) {
        compose.waitForIdle()
        // WindowManager dialog/menu enter animations are outside Compose's test clock.
        android.os.SystemClock.sleep(400)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val image = instrumentation.uiAutomation.takeScreenshot()
        val directory = File(instrumentation.targetContext.cacheDir, "device-design-qa").apply { mkdirs() }
        File(directory, "$name.png").outputStream().use { image.compress(Bitmap.CompressFormat.PNG, 100, it) }
        image.recycle()
    }

    @Test fun pairedListAndManagementUseSettingsThenSingleDialog() {
        render()
        compose.onNodeWithText("已配对设备").assertIsDisplayed()
        compose.onNodeWithText(peer.label).assertIsDisplayed()
        compose.onAllNodes(isDialog()).assertCountEquals(0)
        compose.onNodeWithText("重命名").assertDoesNotExist()
        compose.onNodeWithText("自动同步保险库").assertDoesNotExist()
        capture("01-list")
        compose.onNodeWithContentDescription("${peer.label}的更多操作").performClick()
        compose.onAllNodes(isDialog()).assertCountEquals(1)
        compose.onNodeWithText("设备设置").assertIsDisplayed()
        compose.onNodeWithText("自动同步保险库").assertIsDisplayed()
        compose.onNode(isToggleable()).assertIsOn()
        compose.onNodeWithText("重命名").performScrollTo().assertIsDisplayed()
        capture("03-settings")
        compose.onNodeWithText("重命名").performScrollTo().performClick()
        compose.onAllNodes(isDialog()).assertCountEquals(1)
        compose.onNodeWithText("重命名设备").assertIsDisplayed()
        compose.runOnIdle { assertEquals(peer.pairingRef, panel.value.renameRef) }
        capture("04-rename")
        compose.onNodeWithText("保存").performClick()
        compose.runOnIdle { assertEquals(1, renames) }
        compose.onNodeWithContentDescription("${peer.label}的更多操作").performClick()
        compose.onNodeWithText("撤销配对").performScrollTo().performClick()
        compose.onNodeWithText("撤销与此设备的配对？").assertIsDisplayed()
        compose.runOnIdle { assertEquals(0, revokes) }
        capture("05-revoke")
        compose.onNodeWithText("取消").performClick()
        compose.runOnIdle { assertEquals(0, revokes) }
        compose.onNodeWithContentDescription("${peer.label}的更多操作").performClick()
        compose.onNodeWithText("撤销配对").performScrollTo().performClick()
        compose.onNodeWithText("撤销配对").performClick()
        compose.runOnIdle { assertEquals(1, revokes); assertEquals(0, starts) }
    }

    @Test fun settingsFollowSelectedPeerAndCloseWhenPeerIsRemoved() {
        render()
        compose.onNodeWithContentDescription("${other.label}的更多操作").performClick()
        compose.onAllNodes(isDialog()).assertCountEquals(1)
        compose.onNode(isToggleable()).assertIsOff()
        compose.onNodeWithText("完成").performClick()
        compose.onNodeWithText("自动同步保险库").assertDoesNotExist()
        compose.onNodeWithContentDescription("${peer.label}的更多操作").performClick()
        compose.onNode(isToggleable()).assertIsOn()
        compose.runOnIdle { panel.value = panel.value.withStatus(idle.copy(trusted = listOf(other))) }
        compose.onAllNodes(isDialog()).assertCountEquals(0)
        compose.onNodeWithText("自动同步保险库").assertDoesNotExist()
    }

    @Test fun emptyLoadingFailureAndPermissionErrorAreDistinctAndRecoverable() {
        panel.value = LanPanelState(status = idle.copy(trusted = emptyList()))
        render()
        compose.onNodeWithText("还没有已配对设备").assertIsDisplayed()
        capture("06-empty")
        compose.runOnIdle { panel.value = LanPanelState() }
        compose.onNodeWithText("正在读取已配对设备…").assertIsDisplayed()
        compose.onNodeWithText("开启发现").assertIsNotEnabled()
        capture("07-loading")
        compose.runOnIdle { panel.value = LanPanelState(error = "读取失败") }
        compose.onNodeWithText("读取失败").assertIsDisplayed()
        compose.onNodeWithText("还没有已配对设备").assertDoesNotExist()
        compose.onNodeWithText("正在读取已配对设备…").assertDoesNotExist()
        capture("08-load-error")
        compose.onNodeWithText("重新加载").performClick()
        compose.runOnIdle { assertEquals(1, reloads); panel.value = LanPanelState(status = idle, error = "请连接同一局域网，并允许本地网络访问") }
        compose.onNodeWithText(peer.label).assertIsDisplayed()
        compose.onNodeWithText("重试开启").assertIsEnabled()
        capture("09-network-error")
        compose.onNodeWithText("重试开启").performClick()
        compose.runOnIdle { assertEquals(1, starts) }
    }

    @Test fun pairingDialogValidatesWaitsRetriesAndClosesOnRealTrust() {
        val active = idle.copy(discoverable = true, pairingCode = "482716", expiresAt = System.currentTimeMillis() + 582_000,
            nearby = listOf(LanNearby(target, "unverified")))
        panel.value = LanPanelState(status = active)
        render()
        compose.onNodeWithText("本机配对码").assertIsDisplayed()
        compose.onNodeWithText("停止发现").assertIsEnabled()
        capture("02-discovery")
        compose.onNodeWithText("配对").performScrollTo().performClick()
        compose.onNodeWithText("输入配对码").assertIsDisplayed()
        compose.onNodeWithText("开始配对").assertIsNotEnabled()
        compose.runOnIdle { panel.value = panel.value.copy(codeInput = "12345") }
        compose.onNodeWithText("开始配对").assertIsNotEnabled()
        compose.runOnIdle { panel.value = panel.value.copy(codeInput = "593204") }
        compose.onNodeWithText("开始配对").assertIsEnabled()
        capture("10-code")
        compose.onNodeWithText("开始配对").performClick()
        compose.onNodeWithText("正在安全配对…").assertIsDisplayed()
        compose.onNodeWithText("开始配对").assertIsNotEnabled()
        compose.runOnIdle {
            assertEquals(1, begins)
            assertEquals("", panel.value.codeInput)
            panel.value = panel.value.withStatus(active.copy(nearby = listOf(LanNearby(target, "code-rejected"))))
        }
        compose.onNode(hasText("配对码错误或认证失败") and hasAnyAncestor(isDialog())).assertIsDisplayed()
        compose.onNodeWithText("重试").assertIsNotEnabled()
        capture("11-code-error")
        compose.runOnIdle { panel.value = panel.value.copy(codeInput = "123456") }
        compose.onNodeWithText("重试").performClick()
        compose.runOnIdle { panel.value = panel.value.withStatus(active.copy(trusted = idle.trusted + LanTrusted(target, "VaultMesh A31F20", 2))) }
        compose.onAllNodes(isDialog()).assertCountEquals(0)
        compose.onNodeWithText("VaultMesh A31F20").assertIsDisplayed()
        compose.onNodeWithText("配对成功，已授权当前保险库同步").assertIsDisplayed()
        capture("12-success")
        compose.onNodeWithText("停止发现").performScrollTo().performClick()
        compose.onNodeWithText("本机配对码").assertDoesNotExist()
        compose.onNodeWithText("开启发现").assertIsEnabled()
    }
}
