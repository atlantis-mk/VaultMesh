package com.vaultmesh.app

import android.view.WindowManager
import android.app.Application
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class VaultInstrumentedTest {
    @Test
    fun localNetworkListenerCanBindInDebugAppSandbox() {
        ServerSocket().use { listener ->
            listener.bind(InetSocketAddress(InetAddress.getByName("0.0.0.0"), 0))
            assertTrue(listener.isBound)
        }
    }

    @Test
    fun jniRoundTripUsesPrivateTestStorageAndFailsClosed() {
        withTestDirectory("round-trip") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("missing", VaultNativeBridge.status())
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            assertEquals("unlocked", VaultNativeBridge.status())
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
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
            assertTrue(!added.items.single().hasTotpSecret)
            assertEquals("unlock_failed", VaultNativeBridge.copyLoginPassword(added.items.single().id, "wrong"))
            assertEquals("value:item-password", VaultNativeBridge.copyLoginPassword(added.items.single().id, TEST_PASSWORD))
            assertEquals("invalid_input", VaultNativeBridge.setLoginTotp(added.items.single().id, "invalid!", false))
            assertEquals("ok", VaultNativeBridge.setLoginTotp(added.items.single().id, "JBSWY3DPEHPK3PXP", false))
            assertTrue(VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().hasTotpSecret)
            assertEquals("unlock_failed", VaultNativeBridge.copyLoginTotpCode(added.items.single().id, "wrong"))
            assertTrue(VaultNativeBridge.copyLoginTotpCode(added.items.single().id, TEST_PASSWORD)
                .matches(Regex("value:[0-9]{6}")))
            assertEquals("invalid_input", VaultNativeBridge.setLoginRecoveryCodes(added.items.single().id, " \n", false))
            assertEquals("ok", VaultNativeBridge.setLoginRecoveryCodes(
                added.items.single().id, "first-code\nsecond-code", false,
            ))
            assertTrue(VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().hasRecoveryCodes)
            assertEquals("unlock_failed", VaultNativeBridge.viewLoginRecoveryCodes(added.items.single().id, "wrong"))
            assertEquals("value:[\"first-code\",\"second-code\"]",
                VaultNativeBridge.viewLoginRecoveryCodes(added.items.single().id, TEST_PASSWORD))
            assertEquals("value:second-code", VaultNativeBridge.copyLoginRecoveryCode(
                added.items.single().id, 1, TEST_PASSWORD))
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
            assertTrue(VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().hasTotpSecret)
            assertTrue(VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().hasRecoveryCodes)
            assertEquals("ok", VaultNativeBridge.setLoginTotp(added.items.single().id, "", true))
            assertTrue(!VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().hasTotpSecret)
            assertEquals("ok", VaultNativeBridge.setLoginRecoveryCodes(added.items.single().id, "", true))
            assertTrue(!VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().hasRecoveryCodes)
            val healthRaw = VaultNativeBridge.passwordHealth()
            assertTrue(!healthRaw.contains("item-password"))
            val health = AndroidItemDtos.passwordHealth(healthRaw)
            assertEquals(null, health.error)
            assertTrue(health.report!!.score in 0..100)
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

    /** CT-ANDROID-HOME-001: selected rows use the existing fixed delete operations. */
    @Test
    fun batchDeleteMovesSyntheticLoginsToTrash() {
        withTestDirectory("batch-delete") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.addLogin("First", "first@example.test", "one-password", ""))
            assertEquals("ok", VaultNativeBridge.addLogin("Second", "second@example.test", "two-password", ""))
            val ids = VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.map {
                VaultSelection(VaultSection.Logins, it.id)
            }
            assertEquals(2, ids.size)
            val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as Application
            val viewModel = VaultViewModel(app)
            viewModel.refresh()
            for (attempt in 0 until 200) {
                if (viewModel.state.value.status == "unlocked" && !viewModel.state.value.busy) break
                Thread.sleep(10)
            }
            assertEquals("unlocked", viewModel.state.value.status)
            viewModel.deleteSelectedItems(ids)
            for (attempt in 0 until 200) {
                if (viewModel.state.value.batchDeleteNotice != null && !viewModel.state.value.busy) break
                Thread.sleep(10)
            }
            assertEquals("已删除 2 项", viewModel.state.value.batchDeleteNotice)
            assertEquals(0, VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.size)
            assertEquals(2, VaultNativeBridge.decodeTrash(VaultNativeBridge.listTrash()).items.size)
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

    @Test
    fun pausedActivityLocksNativeSessionBeforeStop() {
        withTestDirectory("pause-lock") { directory ->
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
                    assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
                    ViewModelProvider(activity)[VaultViewModel::class.java].refresh()
                }
                awaitUiIdle(scenario)
                assertEquals("unlocked", VaultNativeBridge.status())
                scenario.moveToState(Lifecycle.State.STARTED)
                assertEquals("locked", VaultNativeBridge.status())
                scenario.moveToState(Lifecycle.State.RESUMED)
                scenario.onActivity { activity ->
                    val state = ViewModelProvider(activity)[VaultViewModel::class.java].state.value
                    assertEquals("locked", state.status)
                    assertTrue(state.logins.isEmpty())
                }
            }
        }
    }

    @Test
    fun permissionOverlayResumeRestoresUnlockPageWithoutStop() {
        // CT-ANDROID-JNI-001/017: a permission sheet may pause without stopping us.
        withTestDirectory("permission-resume") { directory ->
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                awaitUiIdle(scenario)
                scenario.onActivity { activity ->
                    assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
                    assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
                    ViewModelProvider(activity)[VaultViewModel::class.java].refresh()
                }
                awaitUiIdle(scenario)
                val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
                repeat(3) {
                    scenario.moveToState(Lifecycle.State.STARTED)
                    assertEquals("locked", VaultNativeBridge.status())
                    scenario.moveToState(Lifecycle.State.RESUMED)
                    assertTrue("Permission dismissal must restore the password fallback",
                        device.wait(Until.hasObject(By.text("解锁保险库")), 5_000))
                    scenario.onActivity { activity ->
                        val state = ViewModelProvider(activity)[VaultViewModel::class.java].state.value
                        assertEquals("locked", state.status)
                        assertTrue(state.logins.isEmpty())
                        assertTrue(state.password.isEmpty())
                        assertEquals(null, state.loadingPhase)
                    }
                }
            }
        }
    }

    @Test
    fun notificationPermissionDismissalRestoresUnlockPage() {
        org.junit.Assume.assumeTrue(android.os.Build.VERSION.SDK_INT >= 33)
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        // Run this OS dialog check only in a separate acceptance application sandbox.
        org.junit.Assume.assumeTrue(context.packageName == "com.vaultmesh.app.lifecycle.debug")
        assertNotEquals(android.content.pm.PackageManager.PERMISSION_GRANTED,
            context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS))
        withTestDirectory("notification-dialog") { directory ->
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                awaitUiIdle(scenario)
                scenario.onActivity { activity ->
                    assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
                    assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
                    ViewModelProvider(activity)[VaultViewModel::class.java].refresh()
                }
                awaitUiIdle(scenario)
                val paused = CountDownLatch(1)
                scenario.onActivity { activity ->
                    activity.lifecycle.addObserver(LifecycleEventObserver { _, event ->
                        if (event == Lifecycle.Event.ON_PAUSE) paused.countDown()
                    })
                    androidx.core.app.ActivityCompat.requestPermissions(activity,
                        arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 7301)
                }
                assertTrue("System permission sheet must pause the Activity", paused.await(5, TimeUnit.SECONDS))
                val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
                device.waitForIdle()
                device.pressBack()
                assertTrue("Hiding the system permission sheet must restore the unlock page",
                    device.wait(Until.hasObject(By.text("解锁保险库")), 5_000))
                assertEquals("locked", VaultNativeBridge.status())
            }
        }
    }

    @Test
    fun backgroundedMutationCannotUnlockOrPublishAStaleResult() {
        withTestDirectory("pending-mutation") { directory ->
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                awaitUiIdle(scenario)
                scenario.onActivity { activity ->
                    assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
                    assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
                    val viewModel = ViewModelProvider(activity)[VaultViewModel::class.java]
                    viewModel.beginCreateLogin()
                    viewModel.updateLoginDraft { it.copy(title = "Pending login", password = "synthetic-pending-password") }
                    viewModel.saveLogin()
                    viewModel.lock()
                    assertTrue(viewModel.state.value.busy)
                    viewModel.refresh()
                }
                awaitUiIdle(scenario)
                scenario.onActivity { activity ->
                    val state = ViewModelProvider(activity)[VaultViewModel::class.java].state.value
                    assertEquals("locked", state.status)
                    assertTrue(state.logins.isEmpty())
                    assertEquals("locked", VaultNativeBridge.status())
                }
            }
        }
    }

    @Test
    fun protectedRevealRequiresFreshPasswordAndClearsOnLock() {
        withTestDirectory("reveal") { directory ->
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                awaitUiIdle(scenario)
                scenario.onActivity { activity ->
                    assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
                    assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
                    assertEquals("ok", VaultNativeBridge.addLogin(
                        "Reveal login", "person", "synthetic-reveal-value", "",
                    ))
                    ViewModelProvider(activity)[VaultViewModel::class.java].refresh()
                }
                awaitUiIdle(scenario)
                scenario.onActivity { activity ->
                    val viewModel = ViewModelProvider(activity)[VaultViewModel::class.java]
                    val item = viewModel.state.value.logins.single()
                    viewModel.requestProtectedReveal(ProtectedCopyTarget(
                        item.id, item.title, ProtectedCopyField.LoginPassword,
                    ))
                    viewModel.updateProtectedRevealPassword(TEST_PASSWORD)
                    viewModel.submitProtectedReveal()
                }
                awaitUiIdle(scenario)
                scenario.onActivity { activity ->
                    val viewModel = ViewModelProvider(activity)[VaultViewModel::class.java]
                    assertEquals("synthetic-reveal-value", viewModel.state.value.protectedReveal?.value)
                    assertEquals("", viewModel.state.value.protectedReveal?.masterPassword)
                    viewModel.lock()
                    assertEquals(null, viewModel.state.value.protectedReveal)
                }
            }
        }
    }

    @Test
    fun otherItemOperationsUseFixedJniAndPrivateStorage() {
        withTestDirectory("other-items") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))

            assertEquals("ok", VaultNativeBridge.addCardComplete(
                "Test card", "Example Holder", "4111111111111111", 12, 2030, "123", "",
                AndroidItemDtos.cardExtrasJson(OtherDraft.Card(
                    issuer = "Test issuer", billingAddress = "Synthetic Street", notes = "Test note",
                    folder = "Personal", favorite = true, masterPasswordReprompt = true,
                )),
            ))
            val card = AndroidItemDtos.cards(VaultNativeBridge.listCards()).items.single()
            assertEquals("Test card", card.title)
            val cardExtras = AndroidItemDtos.cardExtras(VaultNativeBridge.cardEditorDetail(card.id)).item!!
            assertEquals("Synthetic Street", cardExtras.billingAddress)
            assertTrue(cardExtras.favorite)
            assertEquals("value:4111111111111111", VaultNativeBridge.copyCardNumber(card.id, TEST_PASSWORD))
            assertEquals("value:123", VaultNativeBridge.copyCardSecurityCode(card.id, TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.updateCardComplete(
                card.id, "Updated card", "Example Holder", "", 12, 2030, "", false, "", false,
                AndroidItemDtos.cardExtrasJson(OtherDraft.Card(issuer = "Updated issuer")),
            ))
            assertEquals("Updated issuer", AndroidItemDtos.cardExtras(
                VaultNativeBridge.cardEditorDetail(card.id)).item!!.issuer)
            assertEquals("value:4111111111111111", VaultNativeBridge.copyCardNumber(card.id, TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.deleteCard(card.id))
            val cardTrash = AndroidItemDtos.trash(VaultNativeBridge.listCardTrash()).items.single()
            assertEquals("ok", VaultNativeBridge.restoreCard(cardTrash.trashId))

            assertEquals("ok", VaultNativeBridge.addSshComplete(
                "Test SSH", "ssh.example.test", 22, "test-user", "synthetic-password", "", "", "",
                AndroidItemDtos.sshExtrasJson(OtherDraft.Ssh(notes = "Synthetic note", folder = "Infrastructure", favorite = true)),
            ))
            val ssh = AndroidItemDtos.ssh(VaultNativeBridge.listSsh()).items.single()
            assertTrue(ssh.hasPassword)
            val sshDetail = AndroidItemDtos.sshExtras(VaultNativeBridge.sshEditorDetail(ssh.id)).item!!
            assertEquals("Synthetic note", sshDetail.notes)
            assertTrue(sshDetail.favorite)
            assertTrue(!VaultNativeBridge.sshEditorDetail(ssh.id).contains("synthetic-password"))
            assertEquals("value:synthetic-password", VaultNativeBridge.copySshPassword(ssh.id, TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.updateSshComplete(
                ssh.id, "Updated SSH", "ssh.example.test", 22, "test-user",
                "", false, "", false, "", false, "", false,
                AndroidItemDtos.sshExtrasJson(OtherDraft.Ssh(notes = "Updated note")),
            ))
            assertEquals("Updated note", AndroidItemDtos.sshExtras(
                VaultNativeBridge.sshEditorDetail(ssh.id)).item!!.notes)
            assertEquals("value:synthetic-password", VaultNativeBridge.copySshPassword(ssh.id, TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.deleteSsh(ssh.id))
            val sshTrash = AndroidItemDtos.trash(VaultNativeBridge.listSshTrash()).items.single()
            assertEquals("ok", VaultNativeBridge.restoreSsh(sshTrash.trashId))

            val identityInput = OtherDraft.Identity(
                title = "Test identity", firstName = "A", lastName = "B", organization = "Org",
                emails = listOf(IdentityContactDraft(label = "work", value = "a@example.test", preferred = true)),
                addresses = listOf(IdentityAddressDraft(label = "home", addressLine1 = "1 Test Street", countryCode = "US", preferred = true)),
                notes = "Synthetic note", favorite = true,
            )
            assertEquals("ok", VaultNativeBridge.addIdentityComplete(AndroidItemDtos.identityCompleteJson(identityInput)))
            val identity = AndroidItemDtos.identities(VaultNativeBridge.listIdentities()).items.single()
            assertEquals("A", AndroidItemDtos.identityBasic(VaultNativeBridge.identityBasic(identity.id)).item?.firstName)
            val complete = AndroidItemDtos.identityComplete(VaultNativeBridge.identityEditorDetail(identity.id), identity.id).item!!
            assertEquals("Synthetic note", complete.notes)
            assertEquals(identityInput.emails[0].id, complete.emails[0].id)
            assertEquals("ok", VaultNativeBridge.updateIdentityComplete(identity.id,
                AndroidItemDtos.identityCompleteJson(complete.copy(title = "Updated identity", organization = "New Org"))))
            assertEquals(identityInput.addresses[0].id,
                AndroidItemDtos.identityComplete(VaultNativeBridge.identityEditorDetail(identity.id), identity.id).item!!.addresses[0].id)
            assertEquals("ok", VaultNativeBridge.deleteIdentity(identity.id))
            val identityTrash = AndroidItemDtos.trash(VaultNativeBridge.listIdentityTrash()).items.single()
            assertEquals("ok", VaultNativeBridge.restoreIdentity(identityTrash.trashId))

            assertEquals("ok", VaultNativeBridge.addSecretComplete(
                "Test key", "api-key", "Provider", "Account", "synthetic-secret",
                AndroidItemDtos.secretExtrasJson(OtherDraft.Secret(
                    environment = "test", scopes = "read\nwrite", website = "https://example.test",
                    notes = "Synthetic note", favorite = true,
                )),
            ))
            val secret = AndroidItemDtos.secrets(VaultNativeBridge.listSecrets()).items.single()
            val secretExtras = AndroidItemDtos.secretExtras(VaultNativeBridge.secretEditorDetail(secret.id)).item!!
            assertEquals(listOf("read", "write"), secretExtras.scopes)
            assertTrue(secretExtras.favorite)
            assertEquals("value:synthetic-secret", VaultNativeBridge.copySecretValue(secret.id, TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.updateSecretComplete(
                secret.id, "Updated key", "Provider", "Account", "",
                AndroidItemDtos.secretExtrasJson(OtherDraft.Secret(scopes = "read")),
            ))
            assertEquals(listOf("read"), AndroidItemDtos.secretExtras(
                VaultNativeBridge.secretEditorDetail(secret.id)).item!!.scopes)
            assertEquals("value:synthetic-secret", VaultNativeBridge.copySecretValue(secret.id, TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.deleteSecret(secret.id))
            assertTrue(AndroidItemDtos.secrets(VaultNativeBridge.listSecrets()).items.isEmpty())
            assertEquals("ok", VaultNativeBridge.lock())
        }
    }

    @Test
    fun loginCompleteFieldsPreserveProtectedData() {
        withTestDirectory("login-complete") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            val draft = LoginDraft(
                title = "Complete login", username = "person", password = "synthetic-password",
                url = "https://example.test", notes = "Synthetic note", folder = "Personal",
                favorite = true, additionalUrls = listOf("https://alt.example.test"),
                autofillOnPageLoad = false, masterPasswordReprompt = true,
                customFields = listOf(LoginCustomFieldDraft("account", "synthetic-field")),
            )
            assertEquals("ok", VaultNativeBridge.addLoginComplete(
                draft.title, draft.username, draft.password, draft.url, AndroidItemDtos.loginExtrasJson(draft)))
            val item = VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single()
            val raw = VaultNativeBridge.loginEditorDetail(item.id)
            assertTrue(!raw.contains("synthetic-password"))
            val extras = AndroidItemDtos.loginExtras(raw).item!!
            assertEquals("Synthetic note", extras.notes)
            assertEquals("synthetic-field", extras.customFields.single().value)
            assertEquals("ok", VaultNativeBridge.updateLoginComplete(item.id, "Renamed", "person", "",
                draft.url, AndroidItemDtos.loginExtrasJson(draft.copy(notes = "Updated note"))))
            assertEquals("value:synthetic-password", VaultNativeBridge.copyLoginPassword(item.id, TEST_PASSWORD))
            assertEquals("Updated note", AndroidItemDtos.loginExtras(
                VaultNativeBridge.loginEditorDetail(item.id)).item!!.notes)
        }
    }

    @Test
    fun biometricWrapperUsesOpaqueSecretAndLockStillClearsSession() {
        withTestDirectory("biometric-wrapper") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            val prepared = VaultNativeBridge.prepareBiometricUnlock()
            assertTrue(prepared.startsWith("value:"))
            val secret = prepared.removePrefix("value:")
            assertEquals("ok", VaultNativeBridge.lock())
            assertEquals("locked", VaultNativeBridge.status())
            assertEquals("unlock_failed", VaultNativeBridge.unlockWithBiometricSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
            assertEquals("locked", VaultNativeBridge.status())
            assertEquals("ok", VaultNativeBridge.unlockWithBiometricSecret(secret))
            assertEquals("unlocked", VaultNativeBridge.status())
            assertEquals("ok", VaultNativeBridge.disableBiometricUnlock())
            assertEquals("ok", VaultNativeBridge.lock())
            assertEquals("value_unavailable", VaultNativeBridge.unlockWithBiometricSecret(secret))
        }
    }

    @Test
    fun pinWrapperLimitsFailuresAndMasterUnlockResetsThem() {
        withTestDirectory("pin-wrapper") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            val deviceSecret = android.util.Base64.encodeToString(ByteArray(32) { 42 },
                android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
            assertEquals("ok", VaultNativeBridge.enablePinUnlock("123456", deviceSecret))
            assertEquals("ok", VaultNativeBridge.lock())
            assertEquals("pin_failed", VaultNativeBridge.unlockWithPin("000000", deviceSecret))
            assertEquals(4, org.json.JSONObject(VaultNativeBridge.pinStatus()).getInt("remainingAttempts"))
            assertEquals("ok", VaultNativeBridge.unlock(TEST_PASSWORD))
            assertEquals(5, org.json.JSONObject(VaultNativeBridge.pinStatus()).getInt("remainingAttempts"))
            assertEquals("ok", VaultNativeBridge.lock())
            assertEquals("ok", VaultNativeBridge.unlockWithPin("123456", deviceSecret))
            assertEquals("ok", VaultNativeBridge.disablePinUnlock())
        }
    }

    @Test
    fun pinDeviceSecretStaysInKeystoreSealedPrivateFile() {
        val service = PinUnlockService(InstrumentationRegistry.getInstrumentation().targetContext)
        service.disableLocal()
        try {
            val secret = service.enroll()
            assertTrue(secret != null)
            assertTrue(service.enabled())
            assertEquals(secret, service.readDeviceSecret())
        } finally {
            service.disableLocal()
        }
        assertTrue(!service.enabled())
    }

    @Test
    fun masterPasswordRotationKeepsItemsAndRejectsOldPassword() {
        withTestDirectory("password-rotation") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.addLogin(
                "Preserved login", "person@example.test", "synthetic-item-password", "",
            ))
            assertEquals(
                "unlock_failed",
                VaultNativeBridge.changeMasterPassword("wrong-password", "new-vault-password"),
            )
            assertEquals("unlocked", VaultNativeBridge.status())
            assertEquals("ok", VaultNativeBridge.changeMasterPassword(TEST_PASSWORD, "new-vault-password"))
            assertEquals("Preserved login", VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().title)
            assertEquals("ok", VaultNativeBridge.lock())
            assertEquals("unlock_failed", VaultNativeBridge.unlock(TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.unlock("new-vault-password"))
            assertEquals("Preserved login", VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().title)
        }
    }

    @Test
    fun itemHistoryUsesRedactedFixedJniAndPersistsAfterLock() {
        withTestDirectory("history") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.addLogin("Login", "person", "synthetic-password", ""))
            val loginId = VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().id
            assertEquals("ok", VaultNativeBridge.updateLogin(loginId, "Login new", "person", "", false, ""))
            val loginRaw = VaultNativeBridge.listLoginHistory(loginId)
            assertTrue(!loginRaw.contains("synthetic-password"))
            val loginRevision = AndroidItemDtos.history(loginRaw).items.single()
            assertEquals("revision_not_found", VaultNativeBridge.restoreLoginRevision(
                loginId, "00000000-0000-4000-8000-000000000000",
            ))
            assertEquals("ok", VaultNativeBridge.restoreLoginRevision(loginId, loginRevision.revisionId))
            assertEquals("Login", VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().title)

            assertEquals("ok", VaultNativeBridge.addCard("Card", "Holder", "4111111111111111", 12, 2030, "123", ""))
            val cardId = AndroidItemDtos.cards(VaultNativeBridge.listCards()).items.single().id
            assertEquals("ok", VaultNativeBridge.updateCard(cardId, "Card new", "Holder", "", 12, 2030, "", false, "", false))
            val cardRaw = VaultNativeBridge.listCardHistory(cardId)
            assertTrue(!cardRaw.contains("4111111111111111"))
            val cardRevision = AndroidItemDtos.history(cardRaw).items.single()
            assertEquals("ok", VaultNativeBridge.restoreCardRevision(cardId, cardRevision.revisionId))

            assertEquals("ok", VaultNativeBridge.addSsh("SSH", "host.test", 22, "person", "ssh-password", "", "", ""))
            val sshId = AndroidItemDtos.ssh(VaultNativeBridge.listSsh()).items.single().id
            assertEquals("ok", VaultNativeBridge.updateSsh(sshId, "SSH new", "host.test", 22, "person", "", false, "", false, "", false, "", false))
            val sshRaw = VaultNativeBridge.listSshHistory(sshId)
            assertTrue(!sshRaw.contains("ssh-password"))
            val sshRevision = AndroidItemDtos.history(sshRaw).items.single()
            assertEquals("ok", VaultNativeBridge.restoreSshRevision(sshId, sshRevision.revisionId))

            assertEquals("ok", VaultNativeBridge.addIdentity("Identity", "A", "B", ""))
            val identityId = AndroidItemDtos.identities(VaultNativeBridge.listIdentities()).items.single().id
            assertEquals("ok", VaultNativeBridge.updateIdentity(identityId, "Identity new", "A", "B", ""))
            val identityRevision = AndroidItemDtos.history(VaultNativeBridge.listIdentityHistory(identityId)).items.single()
            assertEquals("ok", VaultNativeBridge.restoreIdentityRevision(identityId, identityRevision.revisionId))

            assertEquals("ok", VaultNativeBridge.clearLoginHistory(loginId))
            assertEquals("ok", VaultNativeBridge.clearCardHistory(cardId))
            assertEquals("ok", VaultNativeBridge.clearSshHistory(sshId))
            assertEquals("ok", VaultNativeBridge.clearIdentityHistory(identityId))
            assertEquals("ok", VaultNativeBridge.lock())
            assertTrue(VaultNativeBridge.listLoginHistory(loginId).contains("locked"))
            assertEquals("ok", VaultNativeBridge.unlock(TEST_PASSWORD))
            assertTrue(AndroidItemDtos.history(VaultNativeBridge.listLoginHistory(loginId)).items.isEmpty())
        }
    }

    @Test
    fun encryptedBackupRestoreUsesPrivateStagingAndRejectsWrongPassword() {
        var encrypted = byteArrayOf()
        withTestDirectory("backup-source") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            assertEquals("ok", VaultNativeBridge.addLogin("From backup", "person", "synthetic-secret", ""))
            assertEquals("ok", VaultNativeBridge.prepareEncryptedBackup())
            encrypted = File(directory, "vaultmesh-backup-export.vault").readBytes()
            assertTrue(!String(encrypted).contains("synthetic-secret"))
        }
        withTestDirectory("backup-target") { directory ->
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create("different-password"))
            assertEquals("ok", VaultNativeBridge.addLogin("Current", "person", "current-secret", ""))
            File(directory, "vaultmesh-backup-import.vault").writeBytes(encrypted)
            assertEquals("unlock_failed", VaultNativeBridge.restoreStagedBackup("wrong"))
            assertEquals("Current", VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().title)
            assertEquals("ok", VaultNativeBridge.restoreStagedBackup(TEST_PASSWORD))
            assertEquals("From backup", VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.single().title)
            assertEquals("ok", VaultNativeBridge.lock())
            assertEquals("unlock_failed", VaultNativeBridge.unlock("different-password"))
            assertEquals("ok", VaultNativeBridge.unlock(TEST_PASSWORD))
        }
        encrypted.fill(0)
    }

    private fun awaitUiIdle(scenario: ActivityScenario<MainActivity>) {
        repeat(100) {
            var busy = true
            scenario.onActivity { activity ->
                busy = ViewModelProvider(activity)[VaultViewModel::class.java].state.value.busy
            }
            if (!busy) return
            Thread.sleep(10)
        }
        error("Android UI did not become idle")
    }

    private fun awaitStatus(expected: String): String {
        repeat(100) {
            val current = VaultNativeBridge.status()
            if (current == expected) return current
            Thread.sleep(10)
        }
        return VaultNativeBridge.status()
    }

    @Test
    fun lanIdentityKeyAndFixedStatusStayPrivateUntilExplicitDiscovery() {
        withTestDirectory("lan-identity") { directory ->
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(TEST_PASSWORD))
            val key = LanPairingKeyService(context).readOrCreate()
            assertTrue(key != null && key.size == 32)
            try {
                assertEquals("ok", VaultNativeBridge.lanOpen(key!!))
            } finally { key?.fill(0) }
            val status = VaultNativeBridge.lanStatus()
            assertTrue(status.contains("\"discoverable\":false"))
            assertTrue(!status.contains("certificate"))
            assertTrue(!status.contains("privateKey"))
            assertTrue(!status.contains("fingerprint"))
            assertEquals("ok", VaultNativeBridge.lanClose())
            assertTrue(VaultNativeBridge.lanStatus().contains("not_initialized"))
            assertEquals("ok", VaultNativeBridge.lock())
            assertEquals("locked", VaultNativeBridge.lanOpen(ByteArray(32)))
        }
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
