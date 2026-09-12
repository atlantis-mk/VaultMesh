package com.vaultmesh.app

import android.view.WindowManager
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class VaultInstrumentedTest {
    @Test
    fun jniRoundTripUsesPrivateTestStorageAndFailsClosed() {
        withTestDirectory("round-trip") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("missing", VaultNativeBridge.status())
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            assertEquals("unlocked", VaultNativeBridge.status())
            assertEquals("already_exists", VaultNativeBridge.create("replacement"))

            assertEquals("ok", VaultNativeBridge.lock())
            assertEquals("locked", VaultNativeBridge.status())
            assertEquals("unlock_failed", VaultNativeBridge.unlock("wrong-password"))
            assertEquals("locked", VaultNativeBridge.status())
            assertEquals("ok", VaultNativeBridge.unlock(TEST_PASSWORD))
            assertEquals("unlocked", VaultNativeBridge.status())
            assertEquals(
                "ok",
                VaultNativeBridge.addLogin(
                    "Device login",
                    "person@example.test",
                    "item-password",
                    "https://example.test",
                ),
            )
            val added = VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins())
            assertEquals(null, added.error)
            assertEquals(1, added.items.size)
            assertTrue(added.items.single().hasPassword)
            assertEquals(
                "ok",
                VaultNativeBridge.updateLogin(
                    added.items.single().id,
                    "Updated login",
                    "updated@example.test",
                    "",
                    false,
                    "",
                ),
            )
            assertEquals(
                "Updated login",
                VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().title,
            )
            assertEquals("ok", VaultNativeBridge.deleteLogin(added.items.single().id))
            assertTrue(VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.isEmpty())
            val deleted = VaultNativeBridge.decodeTrash(VaultNativeBridge.listTrash())
            assertEquals(null, deleted.error)
            assertEquals(1, deleted.items.size)
            assertEquals("ok", VaultNativeBridge.restoreLogin(deleted.items.single().trashId))
            assertEquals(1, VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.size)
            assertEquals("ok", VaultNativeBridge.deleteLogin(added.items.single().id))
            val restoredThenDeleted = VaultNativeBridge.decodeTrash(VaultNativeBridge.listTrash())
            assertEquals(
                "ok",
                VaultNativeBridge.purgeLogin(restoredThenDeleted.items.single().trashId),
            )
            assertTrue(VaultNativeBridge.decodeTrash(VaultNativeBridge.listTrash()).items.isEmpty())
            assertEquals("ok", VaultNativeBridge.emptyTrash())
            assertEquals("ok", VaultNativeBridge.lock())

            val vault = File(directory, "vaultmesh.vault")
            assertTrue(vault.isFile)
            assertNotEquals(0L, vault.length())
        }
    }

    @Test
    fun activityProtectsWindowAndOnStopLocksNativeSession() {
        withTestDirectory("lifecycle") { directory ->
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    val flags = activity.window.attributes.flags
                    assertTrue(flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
                    assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
                    assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
                    assertEquals("unlocked", VaultNativeBridge.status())
                }

                scenario.moveToState(Lifecycle.State.CREATED)
                InstrumentationRegistry.getInstrumentation().waitForIdleSync()
                scenario.moveToState(Lifecycle.State.RESUMED)
                scenario.onActivity {
                    assertEquals("locked", awaitStatus("locked"))
                }
            }
        }
    }

    private fun awaitStatus(expected: String): String {
        repeat(100) {
            val current = VaultNativeBridge.status()
            if (current == expected) return current
            Thread.sleep(10)
        }
        return VaultNativeBridge.status()
    }

    private fun withTestDirectory(name: String, block: (File) -> Unit) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.cacheDir, "vaultmesh-$name-${System.nanoTime()}")
        check(directory.mkdirs())
        try {
            block(directory)
        } finally {
            VaultNativeBridge.lock()
            directory.deleteRecursively()
        }
    }

    private companion object {
        const val TEST_PASSWORD = "android-instrumentation-only"
    }
}
