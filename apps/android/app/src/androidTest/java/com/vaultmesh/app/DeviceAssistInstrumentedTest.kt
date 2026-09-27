package com.vaultmesh.app

import android.net.wifi.WifiManager
import androidx.activity.ComponentActivity
import androidx.compose.material3.Text
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.*
import org.junit.runner.RunWith
import org.json.JSONObject
import java.io.File

/** Real device + desktop TLS. Synthetic sources only; does not inspect carrier SMS or SIM. */
@RunWith(AndroidJUnit4::class)
class DeviceAssistInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    @Test fun lockedNativeDeliveryKeepsVaultLockedAndManualCodeRequestBound() {
        val args = InstrumentationRegistry.getArguments()
        val peer = args.getString("syncPeer")
        val code = args.getString("syncCode")
        Assume.assumeTrue("Requires desktop companion", peer != null && code != null)
        compose.setContent { Text("VaultMesh synthetic device assist test") }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File(context.cacheDir, "vaultmesh-assist-test-${System.nanoTime()}").apply { mkdirs() }
        val multicast = context.getSystemService(WifiManager::class.java).createMulticastLock("vaultmesh-assist-test").apply { setReferenceCounted(false); acquire() }
        fun await(condition: () -> Boolean) {
            val end = android.os.SystemClock.elapsedRealtime() + 45000
            while (!condition()) {
                Assert.assertTrue("Synthetic assist operation timed out", android.os.SystemClock.elapsedRealtime() < end)
                Thread.sleep(100)
            }
        }
        try {
            Assert.assertEquals("ok", VaultNativeBridge.initialize(dir.absolutePath))
            Assert.assertEquals("ok", VaultNativeBridge.create("synthetic-device-master"))
            val key = LanPairingKeyService(context).readOrCreate()!!
            try {
                Assert.assertEquals("ok", VaultNativeBridge.lanOpen(key))
            } finally { key.fill(0) }
            VaultNativeBridge.lanStart()
            await { decodeLanStatus(VaultNativeBridge.lanStatus())?.nearby?.any { it.pairingRef == peer } == true }
            Assert.assertEquals("ok", VaultNativeBridge.lanBegin(peer!!, code!!))
            await { decodeLanStatus(VaultNativeBridge.lanStatus())?.trusted?.size == 1 }
            val assistKey = LanPairingKeyService(context).readOrCreate()!!
            try { Assert.assertEquals("ok", VaultNativeBridge.assistOpen(assistKey)) } finally { assistKey.fill(0) }
            val trusted = decodeLanStatus(VaultNativeBridge.lanStatus())!!.trusted.single().pairingRef
            Assert.assertEquals(0, JSONObject(VaultNativeBridge.assistStatus()).getJSONArray("grants").length())
            Assert.assertEquals("ok", VaultNativeBridge.assistGrant(trusted, true, true))
            Assert.assertEquals("ok", VaultNativeBridge.lanStop())
            Assert.assertEquals("ok", VaultNativeBridge.assistTick(true, "+12025550123", false))
            Assert.assertEquals("ok", VaultNativeBridge.lock())
            Assert.assertEquals("locked", VaultNativeBridge.assistGrant(trusted, false, false))
            val before = File(dir, "vaultmesh.vault").readBytes()
            InstrumentationRegistry.getInstrumentation().sendStatus(2, android.os.Bundle().apply { putString("syncStage", "locked") })
            if (args.getString("assistPush") == "true") {
                Assert.assertEquals("ok", VaultNativeBridge.assistCode("123456", "合成推送来源", 0, "synthetic-push", ""))
                // Give the already-subscribed desktop time to receive the synthetic snapshot.
                Thread.sleep(10000)
                Assert.assertEquals("ok", VaultNativeBridge.assistStop())
                InstrumentationRegistry.getInstrumentation().sendStatus(2, android.os.Bundle().apply { putString("syncStage", "offline") })
            } else {
            var request: String? = null
            await {
                val requests = JSONObject(VaultNativeBridge.assistStatus()).getJSONArray("requests")
                if (requests.length() > 0) request = requests.getJSONObject(0).getString("id")
                request != null
            }
            Assert.assertEquals("ok", VaultNativeBridge.assistCode("123456", "合成手动来源", 0, "synthetic-manual", request!!))
            await { JSONObject(VaultNativeBridge.assistStatus()).getJSONArray("requests").length() == 0 }
            }
            Assert.assertEquals("locked", VaultNativeBridge.status())
            Assert.assertTrue(before.contentEquals(File(dir, "vaultmesh.vault").readBytes()))
            Assert.assertEquals("ok", VaultNativeBridge.assistStop())
        } finally {
            VaultNativeBridge.assistStop()
            VaultNativeBridge.lanClose()
            VaultNativeBridge.lock()
            multicast.release()
            dir.deleteRecursively()
        }
    }
}
