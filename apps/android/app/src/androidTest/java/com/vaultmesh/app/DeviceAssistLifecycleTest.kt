package com.vaultmesh.app

import android.content.Context
import android.content.Intent
import androidx.activity.ComponentActivity
import androidx.compose.material3.Text
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.*
import org.junit.runner.RunWith

/** CT-DEVICE-ASSIST-002: isolated app sandbox; never loads a user's Vault or SIM. */
@RunWith(AndroidJUnit4::class)
class DeviceAssistLifecycleTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before fun isolate() {
        Assume.assumeTrue(context.packageName == "com.vaultmesh.app.lifecycle.debug")
    }
    private fun await(check: () -> Boolean) {
        val end = android.os.SystemClock.elapsedRealtime() + 10_000
        while (!check()) {
            Assert.assertTrue("Assist lifecycle timed out", android.os.SystemClock.elapsedRealtime() < end)
            Thread.sleep(50)
        }
    }
    @Test fun switchCanAlwaysTurnOffAndDoesNotAutoEnable() {
        val enabled = mutableStateOf(false)
        compose.setContent { VaultMeshTheme { DeviceAssistSwitch(enabled.value, false) { enabled.value = it } } }
        compose.waitUntil(15_000) {
            compose.onAllNodes(isToggleable()).fetchSemanticsNodes(atLeastOneRootRequired = false).isNotEmpty()
        }
        compose.onNode(isToggleable()).assertIsOff().assertIsNotEnabled()
        compose.runOnIdle { enabled.value = true }
        compose.onNode(isToggleable()).assertIsOn().assertIsEnabled().performClick()
        compose.onNode(isToggleable()).assertIsOff()
    }
    @Test fun missingNotificationPermissionKeepsSwitchButDoesNotClaimRunning() {
        Assume.assumeTrue(android.os.Build.VERSION.SDK_INT >= 33)
        Assume.assumeTrue(context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
        compose.setContent { Text("Synthetic notification permission check") }
        Assert.assertTrue(DeviceAssistService.setEnabled(context, true))
        DeviceAssistService.startIfEnabled(context)
        Assert.assertTrue(DeviceAssistService.enabled(context))
        Assert.assertFalse(DeviceAssistService.running)
        Assert.assertEquals("互通已开启，等待通知权限", DeviceAssistService.state)
        Assert.assertTrue(DeviceAssistService.setEnabled(context, false))
    }
    @Test fun prepareColdResume() {
        Assume.assumeTrue(InstrumentationRegistry.getArguments().getString("assistPhase") == "prepare")
        compose.setContent { Text("Synthetic assist preparation") }
        Assert.assertTrue(DeviceAssistService.setEnabled(context, false))
        Assert.assertEquals("ok", VaultNativeBridge.initialize(context.filesDir.absolutePath))
        Assert.assertEquals("missing", VaultNativeBridge.status())
        Assert.assertEquals("ok", VaultNativeBridge.create("synthetic-assist-lifecycle"))
        val key = LanPairingKeyService(context).readOrCreate()!!
        try { Assert.assertEquals("ok", VaultNativeBridge.assistOpen(key)) } finally { key.fill(0) }
        Assert.assertEquals("ok", VaultNativeBridge.lock())
        Assert.assertTrue(DeviceAssistService.setEnabled(context, true))
        Assert.assertTrue(DeviceAssistService.enabled(context))
        Assert.assertEquals("locked", VaultNativeBridge.status())
        Assert.assertTrue(context.getSharedPreferences("assist-lifecycle-test", Context.MODE_PRIVATE).edit()
            .putInt("preparedPid", android.os.Process.myPid()).commit())
        // The runner is terminated between phases; the next test has no runtime session.
    }
    @Test fun coldResumeStaysLockedAndNotificationStopPersists() {
        Assume.assumeTrue(InstrumentationRegistry.getArguments().getString("assistPhase") == "resume")
        compose.setContent { Text("Synthetic locked assist recovery") }
        val preparedPid = context.getSharedPreferences("assist-lifecycle-test", Context.MODE_PRIVATE).getInt("preparedPid", -1)
        Assert.assertTrue(preparedPid > 0)
        Assert.assertNotEquals(preparedPid, android.os.Process.myPid())
        // Android may already deliver the queued resume broadcast before the test Activity.
        Assert.assertTrue(VaultNativeBridge.status() in setOf("not_initialized", "locked"))
        Assert.assertTrue(DeviceAssistService.enabled(context))
        DeviceAssistResumeReceiver().onReceive(context, Intent(Intent.ACTION_BOOT_COMPLETED))
        await { DeviceAssistService.running && VaultNativeBridge.status() == "locked" &&
            (DeviceAssistService.state == "互通服务运行中" || DeviceAssistService.state.startsWith("等待局域网")) }
        Assert.assertEquals("locked", VaultNativeBridge.status())
        Assert.assertTrue(org.json.JSONObject(VaultNativeBridge.assistStatus()).has("grants"))
        // Task removal is not an opt-out; verify the installed service flag.
        val info = context.packageManager.getServiceInfo(android.content.ComponentName(context, DeviceAssistService::class.java), 0)
        Assert.assertEquals(0, info.flags and android.content.pm.ServiceInfo.FLAG_STOP_WITH_TASK)
        context.startService(Intent(context, DeviceAssistService::class.java).setAction("com.vaultmesh.app.STOP_DEVICE_ASSIST"))
        await { !DeviceAssistService.running && !DeviceAssistService.enabled(context) }
        DeviceAssistResumeReceiver().onReceive(context, Intent(Intent.ACTION_BOOT_COMPLETED))
        DeviceAssistService.startIfEnabled(context)
        Thread.sleep(500)
        Assert.assertFalse(DeviceAssistService.running)
        Assert.assertFalse(DeviceAssistService.enabled(context.createConfigurationContext(context.resources.configuration)))
        Assert.assertEquals("locked", VaultNativeBridge.status())
    }
}
