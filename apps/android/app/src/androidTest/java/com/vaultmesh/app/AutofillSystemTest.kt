package com.vaultmesh.app

import android.content.ComponentName
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import org.json.JSONArray

@RunWith(AndroidJUnit4::class)
class AutofillSystemTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val device = UiDevice.getInstance(instrumentation)
    private fun text(value: String): androidx.test.uiautomator.UiObject2 {
        return device.wait(Until.findObject(By.text(value)), 15_000) ?: run {
            val markers = device.findObjects(By.textStartsWith("TEST_")).map { it.text }
            val auth = device.hasObject(By.text("解锁本次请求"))
            error("Missing UI: $value; package=${device.currentPackageName}; markers=$markers; auth=$auth")
        }
    }
    private fun fixture(mode: String = "") {
        val nonce = java.util.UUID.randomUUID().toString()
        context.startActivity(Intent().setComponent(ComponentName(instrumentation.context.packageName, AutofillFixtureActivity::class.java.name)).putExtra("mode", mode).putExtra("nonce", nonce).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        text("VaultMesh Autofill Test $nonce")
        text("TEST_REQUEST_FILL").click()
    }
    private fun authenticate() {
        if (!device.wait(Until.hasObject(By.text("解锁本次请求")), 2_000)) {
            if (device.currentPackageName == "com.android.systemui") device.pressBack()
            if (!device.wait(Until.hasObject(By.text("解锁本次请求")), 2_000)) {
                text("其他解锁方式").click()
                text("主密码").click()
            }
        }
        text("解锁本次请求")
        device.findObject(By.clazz("android.widget.EditText")).text = MASTER
        text("解锁本次请求").click()
    }

    @Test fun smsOtpSuggestionIsBoundToExplicitFieldAndCanCancel() {
        val prior = device.executeShellCommand("settings get secure autofill_service").trim()
        try {
            device.executeShellCommand("settings put secure autofill_service ${context.packageName}/com.vaultmesh.app.VaultAutofillService")
            val nonce = java.util.UUID.randomUUID().toString()
            context.startActivity(Intent().setComponent(ComponentName(instrumentation.context.packageName, AutofillFixtureActivity::class.java.name))
                .putExtra("mode", "otp-sms").putExtra("nonce", nonce).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
            text("VaultMesh Autofill Test $nonce")
            text("TEST_REQUEST_OTP").click()
            text("填充短信验证码").click()
            if (device.wait(Until.hasObject(By.text("等待短信验证码")), 3_000)) {
                val waitingTitle = text("等待短信验证码")
                val cancelButton = text("取消")
                val cardCenter = (waitingTitle.visibleBounds.top + cancelButton.visibleBounds.bottom) / 2
                assertTrue("Waiting card should be vertically centered", kotlin.math.abs(cardCenter - device.displayHeight / 2) < device.displayHeight / 7)
                cancelButton.click()
                assertTrue(device.wait(Until.gone(By.text("等待短信验证码")), 5_000))
                text("TEST_OTP_EMPTY")
                if (!device.wait(Until.hasObject(By.text("填充短信验证码")), 2_000)) text("TEST_REQUEST_OTP").click()
                text("填充短信验证码").click()
                if (device.wait(Until.hasObject(By.text("等待短信验证码")), 3_000)) {
                    device.click(device.displayWidth / 2, device.displayHeight / 8)
                    assertTrue(device.wait(Until.gone(By.text("等待短信验证码")), 5_000))
                    text("TEST_OTP_EMPTY")
                } else text("TEST_OTP_FILLED")
            } else {
                // The API can immediately retrieve a recent SMS from the last minute.
                text("TEST_OTP_FILLED")
            }
            val split = java.util.UUID.randomUUID().toString()
            context.startActivity(Intent().setComponent(ComponentName(instrumentation.context.packageName, AutofillFixtureActivity::class.java.name))
                .putExtra("mode", "otp-split").putExtra("nonce", split).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
            text("VaultMesh Autofill Test $split")
            text("TEST_REQUEST_OTP").click()
            text("填充短信验证码")
            for (mode in listOf("otp-numeric", "otp-app", "otp-email")) {
                val next = java.util.UUID.randomUUID().toString()
                context.startActivity(Intent().setComponent(ComponentName(instrumentation.context.packageName, AutofillFixtureActivity::class.java.name))
                    .putExtra("mode", mode).putExtra("nonce", next).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
                text("VaultMesh Autofill Test $next")
                text("TEST_REQUEST_OTP").click()
                assertFalse(device.wait(Until.hasObject(By.text("填充短信验证码")), 2_000))
            }
        } finally {
            device.pressBack()
            if (prior.isEmpty() || prior == "null") device.executeShellCommand("settings delete secure autofill_service")
            else device.executeShellCommand("settings put secure autofill_service $prior")
        }
    }

    @Test fun smsOtpRequestsAreSingleUseAndBoundToTheirFieldSet() {
        val target = AutofillTarget("com.example.synthetic", "ab".repeat(32), null)
        val first = SmsOtpRequests.create(SmsOtpForm(target, "com.example.synthetic/.Otp", listOf(android.widget.EditText(context).autofillId)))
        assertFalse(target.stillInstalled(context))
        assertFalse(first.valid(first.createdAt + 315_000L))
        assertSame(first, SmsOtpRequests.claim(first.id))
        assertNull(SmsOtpRequests.claim(first.id))
        val second = SmsOtpRequests.create(first.form)
        SmsOtpRequests.remove(second.id)
        assertNull(SmsOtpRequests.claim(second.id))
    }

    @Test fun systemSaveThenLockedFillAndCancel() {
        val directory = File(context.cacheDir, "autofill-system-${System.nanoTime()}").apply { mkdirs() }
        val prior = device.executeShellCommand("settings get secure autofill_service").trim()
        try {
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(MASTER))
            assertEquals("ok", VaultNativeBridge.lock())
            device.executeShellCommand("settings put secure autofill_service ${context.packageName}/com.vaultmesh.app.VaultAutofillService")
            device.wakeUp()
            fixture()
            text("使用 VaultMesh 填充")
            text("TEST_ENTER_SYNTHETIC").click()
            text("TEST_SUBMIT").click()
            // Android's localized system save button uses its stable resource ID.
            val save = device.wait(Until.findObject(By.res("android", "autofill_save_yes")), 15_000)
                ?: error("Missing system save confirmation")
            save.click()
            authenticate()
            assertTrue(device.wait(Until.hasObject(By.textStartsWith("VaultMesh · ")), 15_000))
            text(instrumentation.context.packageName)
            text("继续保存").click()
            text("确认").click()
            assertTrue(device.wait(Until.hasObject(By.text("TEST_SUBMIT")), 15_000))
            assertEquals("locked", VaultNativeBridge.status())
            assertEquals("ok", VaultNativeBridge.unlock(MASTER))
            val saved = VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items
            assertEquals(1, saved.size)
            assertEquals("synthetic-user", saved.single().username)
            assertEquals("value:synthetic-login-password", VaultNativeBridge.copyLoginPassword(saved.single().id, MASTER))
            VaultNativeBridge.lock()
            fixture()
            text("使用 VaultMesh 填充").click()
            authenticate()
            assertTrue(device.wait(Until.hasObject(By.textStartsWith("VaultMesh · ")), 15_000))
            text(instrumentation.context.packageName)
            text("其他账号")
            text("synthetic-user").click()
            text("TEST_FILL_OK")
            assertEquals("locked", VaultNativeBridge.status())
            fixture()
            text("使用 VaultMesh 填充").click()
            text("取消").click()
            // A system biometric prompt may consume the first cancel before the Activity does.
            if (!device.wait(Until.hasObject(By.text("TEST_EMPTY")), 2_000)) text("取消").click()
            assertEquals("locked", VaultNativeBridge.status())
            text("TEST_EMPTY")
            fixture("change")
            text("使用 VaultMesh 填充")
            text("TEST_ENTER_SYNTHETIC").click()
            text("TEST_SUBMIT").click()
            val updateSave = device.wait(Until.findObject(By.res("android", "autofill_save_yes")), 15_000) ?: error("Missing password-change save")
            updateSave.click()
            authenticate()
            val update = device.wait(Until.findObject(By.textStartsWith("更新 ")), 15_000) ?: error("Missing update account")
            update.click()
            text("继续保存").click()
            text("确认").click()
            text("TEST_SUBMIT")
            assertEquals("ok", VaultNativeBridge.unlock(MASTER))
            assertEquals(1, VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.size)
            assertEquals("value:synthetic-updated-password", VaultNativeBridge.copyLoginPassword(saved.single().id, MASTER))
            VaultNativeBridge.lock()
            fixture("multi")
            text("使用 VaultMesh 填充")
            text("TEST_ENTER_SYNTHETIC").click()
            text("TEST_NEXT").click()
            text("使用 VaultMesh 填充")
            text("TEST_ENTER_SYNTHETIC").click()
            text("TEST_SUBMIT").click()
            val multiSave = device.wait(Until.findObject(By.res("android", "autofill_save_yes")), 15_000) ?: error("Missing multistep save")
            multiSave.click()
            authenticate()
            text("synthetic-user") // username must have survived the first screen
            val multiUpdate = device.wait(Until.findObject(By.textStartsWith("更新 ")), 15_000) ?: error("Missing multistep update")
            multiUpdate.click()
            text("继续保存").click()
            text("确认").click()
            text("TEST_SUBMIT")
            assertEquals("ok", VaultNativeBridge.unlock(MASTER))
            assertEquals(1, VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items.size)
            assertEquals("value:synthetic-login-password", VaultNativeBridge.copyLoginPassword(saved.single().id, MASTER))
            VaultNativeBridge.lock()
        } finally {
            device.pressBack()
            VaultNativeBridge.lock()
            if (prior.isEmpty() || prior == "null") device.executeShellCommand("settings delete secure autofill_service")
            else device.executeShellCommand("settings put secure autofill_service $prior")
            directory.deleteRecursively()
        }
    }

    @Test fun unnamedUsernameBesidePasswordOffersAndFillsBothFields() {
        val directory = File(context.cacheDir, "autofill-unnamed-${System.nanoTime()}").apply { mkdirs() }
        val prior = device.executeShellCommand("settings get secure autofill_service").trim()
        try {
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(MASTER))
            assertEquals("ok", VaultNativeBridge.addLogin("Synthetic", "synthetic-user", "synthetic-login-password", "https://example.test"))
            VaultNativeBridge.lock()
            device.executeShellCommand("settings put secure autofill_service ${context.packageName}/com.vaultmesh.app.VaultAutofillService")
            fixture("unlabeled")
            text("使用 VaultMesh 填充").click()
            authenticate()
            text("synthetic-user").click()
            text("仅本次填充").click()
            text("TEST_FILL_OK")
            assertEquals("locked", VaultNativeBridge.status())
        } finally {
            device.pressBack()
            VaultNativeBridge.lock()
            if (prior.isEmpty() || prior == "null") device.executeShellCommand("settings delete secure autofill_service")
            else device.executeShellCommand("settings put secure autofill_service $prior")
            directory.deleteRecursively()
        }
    }

    @Test fun tappingAboveSheetCancelsWithoutFilling() {
        val directory = File(context.cacheDir, "autofill-outside-${System.nanoTime()}").apply { mkdirs() }
        val prior = device.executeShellCommand("settings get secure autofill_service").trim()
        try {
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(MASTER))
            assertEquals("ok", VaultNativeBridge.addLogin("Synthetic", "synthetic-user", "synthetic-login-password", "https://example.test"))
            VaultNativeBridge.lock()
            device.executeShellCommand("settings put secure autofill_service ${context.packageName}/com.vaultmesh.app.VaultAutofillService")
            fixture()
            text("使用 VaultMesh 填充").click()
            authenticate()
            text("synthetic-user")
            device.click(5, device.displayHeight / 2)
            assertTrue(device.hasObject(By.textStartsWith("VaultMesh · ")))
            device.click(device.displayWidth / 2, device.displayHeight / 8)
            assertTrue(device.wait(Until.gone(By.textStartsWith("VaultMesh · ")), 15_000))
            text("TEST_EMPTY")
            assertEquals("locked", VaultNativeBridge.status())
        } finally {
            device.pressBack()
            VaultNativeBridge.lock()
            if (prior.isEmpty() || prior == "null") device.executeShellCommand("settings delete secure autofill_service")
            else device.executeShellCommand("settings put secure autofill_service $prior")
            directory.deleteRecursively()
        }
    }

    @Test fun searchFiltersAfterTypingAndRestoresOnClear() {
        val directory = File(context.cacheDir, "autofill-search-${System.nanoTime()}").apply { mkdirs() }
        val prior = device.executeShellCommand("settings get secure autofill_service").trim()
        try {
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(MASTER))
            assertEquals("ok", VaultNativeBridge.addLogin("Synthetic", "synthetic-user", "synthetic-login-password", "https://example.test"))
            VaultNativeBridge.lock()
            device.executeShellCommand("settings put secure autofill_service ${context.packageName}/com.vaultmesh.app.VaultAutofillService")
            fixture()
            text("使用 VaultMesh 填充").click()
            authenticate()
            text("synthetic-user")
            val field = device.findObject(By.pkg(context.packageName).clazz("android.widget.EditText"))
            field.text = "no-matching-login"
            text("没有找到登录项。可先登录，再按系统提示保存。")
            device.findObject(By.pkg(context.packageName).clazz("android.widget.EditText")).text = ""
            text("其他账号")
            assertFalse(device.hasObject(By.text("搜索")))
        } finally {
            device.pressBack()
            VaultNativeBridge.lock()
            if (prior.isEmpty() || prior == "null") device.executeShellCommand("settings delete secure autofill_service")
            else device.executeShellCommand("settings put secure autofill_service $prior")
            directory.deleteRecursively()
        }
    }

    @Test fun pendingCapturesAreSingleClaimBoundedAndCleared() {
        val target = AutofillTarget("com.example.synthetic", "ab".repeat(32), null)
        val form = AutofillForm(target, "com.example.synthetic/.Login", null, null, null, null)
        val firstSecret = CapturedLogin("user".toCharArray(), "synthetic".toCharArray())
        val first = AutofillRequests.create(form, firstSecret)
        assertSame(first, AutofillRequests.claim(first.id))
        assertNull(AutofillRequests.claim(first.id))
        repeat(16) { AutofillRequests.create(form, CapturedLogin(charArrayOf(), charArrayOf('s'))) }
        assertNull(AutofillRequests.get(first.id))
        assertTrue(firstSecret.password.all { it == '\u0000' })
        val captured = CapturedLogin("user".toCharArray(), "synthetic".toCharArray())
        val last = AutofillRequests.create(form, captured)
        AutofillRequests.clear()
        assertNull(AutofillRequests.capturedPassword(last.id))
        assertTrue(captured.password.all { it == '\u0000' })
        assertTrue(captured.username.all { it == '\u0000' })
    }

    @Test fun selectionHistoryKeepsMostRecentFirstInEncryptedPrivateRecord() {
        val directory = File(context.cacheDir, "autofill-history-${System.nanoTime()}").apply { mkdirs() }
        try {
            val isolated = object : android.content.ContextWrapper(context) {
                override fun getNoBackupFilesDir(): File = directory
            }
            val target = AutofillTarget("com.tencent.mobileqq", "ab".repeat(32), null)
            val first = java.util.UUID.randomUUID().toString()
            val second = java.util.UUID.randomUUID().toString()
            val history = AutofillSelectionHistory(isolated)
            history.record(target, first)
            history.record(target, second)
            history.record(target, first)
            assertEquals(listOf(first, second), AutofillSelectionHistory(isolated).recentIds(target))
            val bytes = File(directory, "autofill-selection-history.bin").readBytes()
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains(first))
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains(target.packageName))
        } finally { directory.deleteRecursively() }
    }

    @Test fun lockedPreviewShowsSeveralRelevantAccountsAndInvalidatesOnVaultChange() {
        val directory = File(context.cacheDir, "autofill-preview-${System.nanoTime()}").apply { mkdirs() }
        try {
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(MASTER))
            assertEquals("ok", VaultNativeBridge.addLogin("QQ first", "synthetic-first", "synthetic-secret-1", "https://qq.com/login"))
            assertEquals("ok", VaultNativeBridge.addLogin("QQ second", "synthetic-second", "synthetic-secret-2", "https://qq.com/other"))
            assertEquals("ok", VaultNativeBridge.addLogin("Unrelated", "synthetic-third", "synthetic-secret-3", "https://unrelated.test"))
            val isolated = object : android.content.ContextWrapper(context) {
                override fun getNoBackupFilesDir(): File = directory
                override fun getFilesDir(): File = directory
            }
            val cache = AutofillPreviewCache(isolated)
            val before = cache.vaultDigest()
            val logins = VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins()).items
            cache.refreshLogins(logins, before)
            val target = AutofillTarget("com.tencent.mobileqq", "ab".repeat(32), null)
            val recent = logins.first { it.username == "synthetic-second" }.id
            AutofillSelectionHistory(isolated).record(target, recent)
            VaultNativeBridge.lock()
            val recommended = cache.recommend(target, "QQ", AutofillSelectionHistory(isolated).recentIds(target))
            assertEquals(listOf("synthetic-second", "synthetic-first"), recommended.map { it.username })
            val bytes = File(directory, "autofill-preview-v1.bin").readBytes()
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains("synthetic-first"))
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains("synthetic-secret-1"))
            assertEquals("ok", VaultNativeBridge.unlock(MASTER))
            assertEquals("ok", VaultNativeBridge.addLogin("Changed", "synthetic-new", "synthetic-secret-4", "https://example.test"))
            VaultNativeBridge.lock()
            assertTrue(cache.recommend(target, "QQ", listOf(recent)).isEmpty())
        } finally {
            VaultNativeBridge.lock()
            directory.deleteRecursively()
        }
    }

    @Test fun localPhoneNumberIsValidatedEncryptedAndRemovable() {
        assertEquals("+8615500001234", LocalPhoneNumber.normalize(" +86 (155) 0000-1234 "))
        assertEquals("15500001234", LocalPhoneNumber.forAutofill("+86 155 0000 1234", "CN"))
        assertEquals("2025550123", LocalPhoneNumber.forAutofill("+1 202 555 0123", "US"))
        assertEquals("15500001234", LocalPhoneNumber.forAutofill("15500001234", "CN"))
        assertNull(LocalPhoneNumber.normalize("+86abc15500001234"))
        assertNull(LocalPhoneNumber.normalize("12345"))
        val directory = File(context.cacheDir, "autofill-phone-${System.nanoTime()}").apply { mkdirs() }
        try {
            val isolated = object : android.content.ContextWrapper(context) {
                override fun getNoBackupFilesDir(): File = directory
            }
            val source = LocalPhoneNumber(isolated)
            assertTrue(source.saveManualNumber("155 0000 1234"))
            assertEquals("15500001234", LocalPhoneNumber(isolated).manualNumber())
            val bytes = File(directory, "autofill-local-phone.bin").readBytes()
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains("15500001234"))
            assertFalse(source.saveManualNumber("bad-number"))
            assertEquals("15500001234", source.manualNumber())
            assertTrue(source.clearManualNumber())
            assertNull(source.manualNumber())
        } finally { directory.deleteRecursively() }
    }

    @Test fun passwordSuggestionPreservesPreviouslyChosenUsernameAndCancelCanRetry() {
        val directory = File(context.cacheDir, "autofill-password-only-${System.nanoTime()}").apply { mkdirs() }
        val prior = device.executeShellCommand("settings get secure autofill_service").trim()
        try {
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(MASTER))
            assertEquals("ok", VaultNativeBridge.addLogin("https://first.example.test", "synthetic-user", "synthetic-login-password", "https://example.test"))
            assertEquals("ok", VaultNativeBridge.addLogin("https://second.example.test", "other-user", "other-login-password", "https://example.test"))
            VaultNativeBridge.lock()
            device.executeShellCommand("settings put secure autofill_service ${context.packageName}/com.vaultmesh.app.VaultAutofillService")
            fixture()
            text("使用 VaultMesh 填充").click()
            authenticate()
            text("其他账号")
            text("synthetic-user")
            assertTrue(text("synthetic-user").visibleBounds.top < text("https://first.example.test").visibleBounds.top)
            text("synthetic-user").click()
            text("仅本次填充").click()
            text("TEST_FILL_OK")
            text("TEST_CLEAR_PASSWORD").click()
            text("TEST_REQUEST_PASSWORD_FILL").click()
            text("使用 VaultMesh 填充").click()
            text("取消").click()
            if (!device.wait(Until.hasObject(By.text("使用 VaultMesh 填充")), 2_000)) text("取消").click()
            if (!device.hasObject(By.text("使用 VaultMesh 填充"))) {
                device.findObject(By.desc("TEST_USERNAME")).click()
                device.findObject(By.desc("TEST_PASSWORD")).click()
            }
            if (!device.hasObject(By.text("使用 VaultMesh 填充"))) text("TEST_REQUEST_PASSWORD_FILL").click()
            text("使用 VaultMesh 填充").click()
            authenticate()
            text("最近使用")
            assertTrue(text("other-user").visibleBounds.top < text("https://second.example.test").visibleBounds.top)
            text("other-user").click()
            text("仅本次填充").click()
            text("TEST_USERNAME_PRESERVED")
            assertEquals("synthetic-user", device.findObject(By.desc("TEST_USERNAME")).text)
            assertEquals("locked", VaultNativeBridge.status())
        } finally {
            device.pressBack()
            VaultNativeBridge.lock()
            if (prior.isEmpty() || prior == "null") device.executeShellCommand("settings delete secure autofill_service")
            else device.executeShellCommand("settings put secure autofill_service $prior")
            directory.deleteRecursively()
        }
    }

    @Test fun credentialSuggestionPresentsUsernameBeforeUrlTitle() {
        val label = VaultAutofillService.credentialPresentation(context, "synthetic-user", "https://example.test")
            .apply(context, null)
        assertEquals("synthetic-user", label.findViewById<android.widget.TextView>(android.R.id.text1).text.toString())
        assertEquals("https://example.test", label.findViewById<android.widget.TextView>(android.R.id.text2).text.toString())
        assertEquals("QQ", VaultAutofillService.credentialSubtitle("com.tencent.mobileqq", "com.tencent.mobileqq", "QQ"))
        val action = VaultAutofillService.presentation(context, "使用 VaultMesh 填充").apply(context, null)
        assertEquals("使用 VaultMesh 填充", action.findViewById<android.widget.TextView>(android.R.id.text1).text.toString())
        val passwordAction = VaultAutofillService.passwordActionPresentation(context, "使用 VaultMesh 填充").apply(context, null)
        assertEquals("使用 VaultMesh 填充", passwordAction.findViewById<android.widget.TextView>(android.R.id.text1).text.toString())
        val phone = VaultAutofillService.phonePresentation(context, "15500001234").apply(context, null)
        assertEquals("本机号码", phone.findViewById<android.widget.TextView>(android.R.id.text1).text.toString())
        assertEquals("•••• 1234", phone.findViewById<android.widget.TextView>(android.R.id.text2).text.toString())
    }

    @Test fun defaultSuggestionsFollowAssociatedAccountsBeforeOtherRecommendations() {
        val recent = AutofillPreview("recent-id", "recent", "Recent", null)
        val associated = AutofillPreview("associated-id", "associated", "Associated", null, matched = true)
        val related = AutofillPreview("related-id", "related", "Related", null, relatedHint = true)
        fun labels(items: List<AutofillSuggestion>) = items.map { item ->
            when (item) {
                is AutofillSuggestion.Login -> item.preview.username
                is AutofillSuggestion.RandomAccount -> "随机账号"
                is AutofillSuggestion.Phone -> "本机号码"
                AutofillSuggestion.OpenVault -> "使用 VaultMesh 填充"
            }
        }
        val previews = listOf(recent, associated, related)
        assertEquals(listOf("recent", "associated", "本机号码", "使用 VaultMesh 填充", "related"),
            labels(VaultAutofillService.suggestionOrder(previews, listOf(recent.id), null, "15500001234")))
        assertEquals(listOf("recent", "associated", "使用 VaultMesh 填充", "related"),
            labels(VaultAutofillService.suggestionOrder(previews, listOf(recent.id), null, null)))
        assertEquals(listOf("本机号码", "使用 VaultMesh 填充", "related"),
            labels(VaultAutofillService.suggestionOrder(listOf(related), emptyList(), null, "15500001234")))
        assertEquals(listOf("recent", "associated", "随机账号", "本机号码", "使用 VaultMesh 填充", "related"),
            labels(VaultAutofillService.suggestionOrder(previews, listOf(recent.id), "vm1234567890", "15500001234")))
    }

    @Test fun registrationOffersRandomAccountWithoutUnlockingVault() {
        val prior = device.executeShellCommand("settings get secure autofill_service").trim()
        try {
            device.executeShellCommand("settings put secure autofill_service ${context.packageName}/com.vaultmesh.app.VaultAutofillService")
            fixture("register")
            text("随机账号").click()
            assertTrue(device.findObject(By.desc("TEST_USERNAME")).text.matches(Regex("vm[a-z0-9]{10}")))
            assertEquals("TEST_PASSWORD", device.findObject(By.desc("TEST_PASSWORD")).text)
            text("TEST_PARTIAL_FILL")
        } finally {
            device.pressBack()
            if (prior.isEmpty() || prior == "null") device.executeShellCommand("settings delete secure autofill_service")
            else device.executeShellCommand("settings put secure autofill_service $prior")
        }
    }

    @Test fun qqPhoneRegistrationExceptionRejectsOtherNumericFields() {
        val pkg = "com.tencent.mobileqq"
        val activity = "com.tencent.mobileqq.activity.RegisterPhoneNumActivity"
        assertTrue(AutofillStructure.knownPhoneRegistration(pkg, activity, 1, 15))
        assertFalse(AutofillStructure.knownPhoneRegistration("example.app", activity, 1, 15))
        assertFalse(AutofillStructure.knownPhoneRegistration(pkg, "com.tencent.mobileqq.activity.LoginActivity", 1, 15))
        assertFalse(AutofillStructure.knownPhoneRegistration(pkg, activity, 2, 15))
        assertFalse(AutofillStructure.knownPhoneRegistration(pkg, activity, 1, 6))
    }

    @Test fun localPhoneSuggestionFillsUsernameOnly() {
        val record = File(context.noBackupFilesDir, "autofill-local-phone.bin")
        org.junit.Assume.assumeFalse(record.exists())
        org.junit.Assume.assumeTrue(context.checkSelfPermission(android.Manifest.permission.READ_PHONE_NUMBERS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
        val prior = device.executeShellCommand("settings get secure autofill_service").trim()
        val source = LocalPhoneNumber(context)
        try {
            assertTrue(source.saveManualNumber("15500001234"))
            device.executeShellCommand("settings put secure autofill_service ${context.packageName}/com.vaultmesh.app.VaultAutofillService")
            fixture()
            val vault = text("使用 VaultMesh 填充")
            val phone = text("本机号码")
            text("•••• 1234")
            assertTrue(phone.visibleBounds.top <= vault.visibleBounds.top)
            phone.click()
            text("TEST_PARTIAL_FILL")
            assertEquals("15500001234", device.findObject(By.desc("TEST_USERNAME")).text)
            // UIAutomator reports the hint as text for an empty password field.
            assertEquals("TEST_PASSWORD", device.findObject(By.desc("TEST_PASSWORD")).text)
        } finally {
            device.pressBack()
            if (prior.isEmpty() || prior == "null") device.executeShellCommand("settings delete secure autofill_service")
            else device.executeShellCommand("settings put secure autofill_service $prior")
            source.clearManualNumber()
        }
    }

    @Test fun jniAutofillRejectsReplayAndWrongPassword() {
        val directory = File(context.cacheDir, "autofill-jni-${System.nanoTime()}").apply { mkdirs() }
        try {
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(MASTER))
            assertEquals("ok", VaultNativeBridge.addLogin("Synthetic", "synthetic-user", "synthetic-login-password", "https://example.test"))
            val deviceSecret = android.util.Base64.encodeToString(ByteArray(32) { 17 }, android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
            assertEquals("ok", VaultNativeBridge.enablePinUnlock("123456", deviceSecret))
            VaultNativeBridge.lock()
            val id = java.util.UUID.randomUUID().toString()
            val target = AutofillTarget("com.example.synthetic", "ab".repeat(32), "https://example.test").json()
            assertEquals("unlock_failed", VaultNativeBridge.autofillBegin(id, target, "wrong"))
            val token = VaultNativeBridge.autofillBegin(id, target, MASTER).removePrefix("token:")
            assertEquals("locked", VaultNativeBridge.status())
            val candidates = JSONArray(VaultNativeBridge.autofillCandidates(token, "", "", "[]"))
            val item = candidates.getJSONObject(0).getString("id")
            assertTrue(VaultNativeBridge.autofillFill(token, id, item, true, false, true).startsWith("value:"))
            assertEquals("locked", VaultNativeBridge.autofillFill(token, id, item, true, false, true))
            assertEquals("invalid_input", VaultNativeBridge.autofillBeginBiometric(id, target, "bad"))
            val pinToken = VaultNativeBridge.autofillBeginPin(id, target, "123456", deviceSecret).removePrefix("token:")
            assertEquals("locked", VaultNativeBridge.status())
            assertTrue(VaultNativeBridge.autofillFill(pinToken, id, item, true, false, true).startsWith("value:"))
            val saveToken = VaultNativeBridge.autofillBeginPin(id, target, "123456", deviceSecret).removePrefix("token:")
            assertEquals("ok", VaultNativeBridge.autofillSave(saveToken, id, "", "New", "new-user", "new-secret"))
            assertEquals("locked", VaultNativeBridge.status())
            assertEquals("pin_failed", VaultNativeBridge.autofillBeginPin(id, target, "000000", deviceSecret))
            assertEquals(4, org.json.JSONObject(VaultNativeBridge.pinStatus()).getInt("remainingAttempts"))
        } finally { VaultNativeBridge.lock(); directory.deleteRecursively() }
    }
    @Test fun jniPackageHintAndRememberedAssociation() {
        val directory = File(context.cacheDir, "autofill-qq-${System.nanoTime()}").apply { mkdirs() }
        try {
            assertEquals("ok", VaultNativeBridge.initialize(directory.absolutePath))
            assertEquals("ok", VaultNativeBridge.create(MASTER))
            assertEquals("ok", VaultNativeBridge.addLogin("Other", "other-user", "other-secret", "https://example.test"))
            assertEquals("ok", VaultNativeBridge.addLogin("QQ", "qq-user", "qq-secret", "https://qq.com/login"))
            VaultNativeBridge.lock()
            val target = AutofillTarget("com.tencent.mobileqq", "ab".repeat(32), null).json()
            val request = java.util.UUID.randomUUID().toString()
            val token = VaultNativeBridge.autofillBegin(request, target, MASTER).removePrefix("token:")
            val candidates = JSONArray(VaultNativeBridge.autofillCandidates(token, "", "", "[]"))
            assertEquals("QQ", candidates.getJSONObject(0).getString("title"))
            assertTrue(candidates.getJSONObject(0).getBoolean("relatedHint"))
            val qqId = candidates.getJSONObject(0).getString("id")
            val otherId = candidates.getJSONObject(1).getString("id")
            val recent = JSONArray(VaultNativeBridge.autofillCandidates(token, "", "", JSONArray(listOf(otherId)).toString()))
            assertEquals(otherId, recent.getJSONObject(0).getString("id"))
            assertEquals("invalid_input", VaultNativeBridge.autofillFill(token, request, qqId, false, false, true))
            val approved = VaultNativeBridge.autofillBegin(request, target, MASTER).removePrefix("token:")
            assertTrue(VaultNativeBridge.autofillFill(approved, request, qqId, true, true, true).startsWith("value:"))
            assertEquals("locked", VaultNativeBridge.status())
            val next = VaultNativeBridge.autofillBegin(java.util.UUID.randomUUID().toString(), target, MASTER).removePrefix("token:")
            assertTrue(JSONArray(VaultNativeBridge.autofillCandidates(next, "", "", "[]")).getJSONObject(0).getBoolean("matched"))
        } finally { VaultNativeBridge.lock(); directory.deleteRecursively() }
    }
    companion object { const val MASTER = "synthetic-autofill-master" }
}
