package com.vaultmesh.app

import android.content.Intent
import android.net.wifi.WifiManager
import androidx.compose.material3.Text
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.activity.ComponentActivity
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.*
import org.junit.runner.RunWith
import java.io.File

/** CT-ANDROID-LAN-SYNC-001 / AT-ANDROID-022. Only synthetic cache-dir Vaults. */
@RunWith(AndroidJUnit4::class)
class LanSyncInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    @Test fun pairedDeviceSyncsAfterScanningStopsAndWhileLocked() {
        val args = InstrumentationRegistry.getArguments()
        val peer = args.getString("syncPeer")
        val code = args.getString("syncCode")
        Assume.assumeTrue("Requires desktop companion", peer != null && code != null)
        compose.setContent { Text("VaultMesh synthetic LAN sync test") }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.adoptShellPermissionIdentity(android.Manifest.permission.WAKE_LOCK)
        @Suppress("DEPRECATION")
        val awake = context.getSystemService(android.os.PowerManager::class.java)
            .newWakeLock(android.os.PowerManager.SCREEN_BRIGHT_WAKE_LOCK, "vaultmesh:sync-test")
        awake.acquire(120000)
        val dir = File(context.cacheDir, "vaultmesh-sync-test-${System.nanoTime()}").apply { mkdirs() }
        val prefs = context.getSharedPreferences("lan-sync", 0)
        val wasPaused = prefs.getBoolean("paused", false)
        val multicast = context.getSystemService(WifiManager::class.java).createMulticastLock("vaultmesh-sync-test").apply { setReferenceCounted(false); acquire() }
        fun await(timeout: Long = 40000, condition: () -> Boolean) {
            val deadline = android.os.SystemClock.elapsedRealtime() + timeout
            while (!condition()) {
                Assert.assertTrue("Timed out: service=${LanSyncService.state}; network=${LanSyncService.networkAllowed(context)}; native=${VaultNativeBridge.syncStatus()}", android.os.SystemClock.elapsedRealtime() < deadline)
                Thread.sleep(100)
            }
        }
        fun titles() = VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.map { it.title }
        fun add(title: String) { Assert.assertEquals("ok", VaultNativeBridge.addLogin(title, "synthetic", "synthetic-secret", "")) }
        try {
            Assert.assertEquals("ok", VaultNativeBridge.initialize(dir.absolutePath))
            Assert.assertEquals("ok", VaultNativeBridge.create("synthetic-device-master"))
            val key = LanPairingKeyService(context).readOrCreate()!!
            try { Assert.assertEquals("ok", VaultNativeBridge.lanOpen(key)) } finally { key.fill(0) }
            Assert.assertNotNull(decodeLanStatus(VaultNativeBridge.lanStart()))
            await { decodeLanStatus(VaultNativeBridge.lanStatus())?.nearby?.any { it.pairingRef == peer } == true }
            Assert.assertEquals("ok", VaultNativeBridge.lanBegin(peer!!,code!!))
            await { decodeLanStatus(VaultNativeBridge.lanStatus())?.trusted?.size == 1 }
            Assert.assertEquals("ok", VaultNativeBridge.lanStop())
            Assert.assertFalse(decodeLanStatus(VaultNativeBridge.lanStatus())!!.discoverable)
            InstrumentationRegistry.getInstrumentation().runOnMainSync { LanSyncService.start(context, explicit = true) }
            await { LanSyncService.running }
            add("Android outbound")
            await { "Desktop seed" in titles() && "Desktop response" in titles() }
            // Exiting the device page closes only pairing; the real Service remains alive.
            Assert.assertEquals("ok", VaultNativeBridge.lanClose())
            add("Lock trigger")
            Assert.assertEquals("ok", VaultNativeBridge.lock())
            val vault = File(dir, "vaultmesh.vault")
            compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
            val before = vault.readBytes()
            val mailbox = File(dir, "vaultmesh.vault.lan-mailbox")
            val cacheBefore = mailbox.readBytes()
            // The companion waits for this stage before publishing its response,
            // so the assertion measures receipt while already locked/backgrounded.
            InstrumentationRegistry.getInstrumentation().sendStatus(2, android.os.Bundle().apply {
                putString("syncStage", "locked")
            })
            await { !mailbox.readBytes().contentEquals(cacheBefore) }
            Thread.sleep(1500)
            Assert.assertEquals("locked", VaultNativeBridge.status())
            Assert.assertTrue(before.contentEquals(vault.readBytes()))
            Assert.assertTrue(VaultNativeBridge.listLogins().contains("locked"))
            // Resume the isolated test host as a user launch; Android 16 blocks
            // ActivityScenario's background launch without an external gesture.
            val launched = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(
                "am start -W -n ${context.packageName}/androidx.activity.ComponentActivity -f 0x20000")
            val launchResult = android.os.ParcelFileDescriptor.AutoCloseInputStream(launched).use { it.reader().readText() }
            Assert.assertFalse("Unable to return synthetic test activity to foreground", launchResult.contains("Error"))
            Assert.assertEquals("ok", VaultNativeBridge.unlock("synthetic-device-master"))
            await { "Locked response" in titles() }
            context.stopService(Intent(context,LanSyncService::class.java))
            await { !LanSyncService.running }
            add("Android reconnect")
            InstrumentationRegistry.getInstrumentation().runOnMainSync { LanSyncService.start(context, explicit = true) }
            await { LanSyncService.running && decodeSyncStatus(VaultNativeBridge.syncStatus())?.peers?.any { it.state == "synced" } == true }
            // Cold cache must remain ciphertext-only.
            val cache = mailbox.readText()
            Assert.assertFalse(cache.contains("synthetic-secret"))
            Assert.assertFalse(cache.contains("Android outbound"))
            val reopenedKey = LanPairingKeyService(context).readOrCreate()!!
            try { Assert.assertEquals("ok", VaultNativeBridge.lanOpen(reopenedKey)) } finally { reopenedKey.fill(0) }
            val trusted = decodeLanStatus(VaultNativeBridge.lanStatus())!!.trusted.single().pairingRef
            Assert.assertEquals("ok", VaultNativeBridge.syncSetEnabled(trusted, false))
            Assert.assertFalse(decodeSyncStatus(VaultNativeBridge.syncStatus())!!.peers.single().enabled)
            add("Revoked change")
            Thread.sleep(1500)
            Assert.assertEquals("ok", VaultNativeBridge.lanRevoke(trusted))
            Assert.assertTrue(decodeLanStatus(VaultNativeBridge.lanStatus())!!.trusted.isEmpty())
        } finally {
            context.stopService(Intent(context,LanSyncService::class.java))
            await(10000) { !LanSyncService.running }
            VaultNativeBridge.syncClose()
            VaultNativeBridge.lanClose()
            VaultNativeBridge.lock()
            multicast.release()
            if (awake.isHeld) awake.release()
            automation.dropShellPermissionIdentity()
            prefs.edit().putBoolean("paused", wasPaused).commit()
            dir.deleteRecursively()
        }
    }
}
