package com.vaultmesh.app

import android.app.assist.AssistStructure
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.service.autofill.Dataset
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.google.android.gms.auth.api.phone.SmsCodeRetriever
import com.google.android.gms.auth.api.phone.SmsRetriever
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.common.api.ResolvableApiException
import com.google.android.gms.common.api.Status
import java.security.SecureRandom

internal data class SmsOtpForm(val target: AutofillTarget, val activity: String, val fields: List<AutofillId>)

internal object SmsOtpEligibility {
    // Google Play PermissionState: NONE=0, GRANTED=1, DENIED=2.
    fun allowed(ongoingTargetRequest: Boolean?, permissionState: Int?): Boolean =
        ongoingTargetRequest == false && permissionState in 0..1
}

internal object SmsOtpRequests {
    const val EXTRA_REQUEST = "com.vaultmesh.app.sms_otp_request"
    private const val LIFETIME_MS = 315_000L
    private val random = SecureRandom()
    private val pending = LinkedHashMap<String, Entry>()

    data class Entry(val id: String, val form: SmsOtpForm, val createdAt: Long) {
        fun valid(now: Long = SystemClock.elapsedRealtime()): Boolean = now - createdAt in 0 until LIFETIME_MS
    }

    @Synchronized fun create(form: SmsOtpForm): Entry {
        prune()
        while (pending.size >= 8) pending.remove(pending.keys.first())
        val bytes = ByteArray(16).also(random::nextBytes)
        val id = bytes.joinToString("") { "%02x".format(it) }
        return Entry(id, form, SystemClock.elapsedRealtime()).also { pending[id] = it }
    }

    @Synchronized fun claim(id: String?): Entry? {
        prune()
        return id?.let(pending::remove)?.takeIf { it.valid() }
    }

    @Synchronized fun remove(id: String?) { if (id != null) pending.remove(id) }

    @Synchronized private fun prune() {
        pending.entries.removeAll { !it.value.valid() }
    }

    fun validCode(code: String?, splitFields: Int): Boolean =
        code != null && code.length in 4..10 && code.all { it in '0'..'9' || it in 'A'..'Z' || it in 'a'..'z' } &&
            (splitFields == 1 || code.length == splitFields)
}

@Composable
internal fun SmsOtpWaitingContent(onCancel: () -> Unit) {
    VaultMeshTheme {
        Box(Modifier.fillMaxSize().clickable(onClick = onCancel), contentAlignment = Alignment.Center) {
            Surface(
                modifier = Modifier.fillMaxWidth(0.88f).widthIn(max = 420.dp).testTag("smsOtpWaitingCard")
                    .pointerInput(Unit) { detectTapGestures(onTap = {}) },
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surface,
                shadowElevation = 14.dp,
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(42.dp),
                        color = MaterialTheme.colorScheme.primary,
                        strokeWidth = 3.dp,
                        trackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.14f),
                    )
                    Spacer(Modifier.height(20.dp))
                    Text("等待短信验证码", style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onSurface)
                    Spacer(Modifier.height(8.dp))
                    Text("收到后将填入当前输入框", style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(24.dp))
                    OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth().height(48.dp)) {
                        Text("取消")
                    }
                }
            }
        }
    }
}

/** Runs only after the user chooses the system Autofill SMS-code suggestion. */
class SmsOtpAutofillActivity : ComponentActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private var request: SmsOtpRequests.Entry? = null
    private var receiver: BroadcastReceiver? = null
    private var awaitingConsent = false
    private var consentResolvedOnce = false
    private var completed = false
    private val timeout = Runnable { cancel() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        setResult(RESULT_CANCELED)
        // A recreated Activity cannot inherit a claimed request or a prior receiver.
        if (savedInstanceState != null) { cancel(); return }
        val id = intent.getStringExtra(SmsOtpRequests.EXTRA_REQUEST)
        if (intent.data?.lastPathSegment != id) { cancel(); return }
        request = SmsOtpRequests.claim(id)
        val entry = request
        if (entry == null || !entry.form.target.stillInstalled(this) || Build.VERSION.SDK_INT < 28) { cancel(); return }
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() { cancel(reoffer = true) }
        })
        @Suppress("DEPRECATION")
        val structure = intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        if (structure?.let { AutofillStructure.parseSmsOtp(this, it) } != entry.form) { cancel(); return }
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_DIM_BEHIND)
        window.attributes = window.attributes.apply { dimAmount = 0.45f }
        setContent { SmsOtpWaitingContent { cancel(reoffer = true) } }
        receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, result: Intent) {
                if (result.action != SmsCodeRetriever.SMS_CODE_RETRIEVED_ACTION || completed) return
                @Suppress("DEPRECATION")
                val status = result.getParcelableExtra<Status>(SmsCodeRetriever.EXTRA_STATUS)
                if (status?.statusCode != CommonStatusCodes.SUCCESS) { cancel(); return }
                deliver(result.getStringExtra(SmsCodeRetriever.EXTRA_SMS_CODE))
            }
        }
        val filter = IntentFilter(SmsCodeRetriever.SMS_CODE_RETRIEVED_ACTION)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(receiver, filter, SmsRetriever.SEND_PERMISSION, null, Context.RECEIVER_EXPORTED)
        else registerReceiver(receiver, filter, SmsRetriever.SEND_PERMISSION, null)
        handler.postDelayed(timeout, 315_000L)
        checkAndStart()
    }

    private fun checkAndStart() {
        val entry = request ?: return cancel()
        val client = SmsCodeRetriever.getAutofillClient(this)
        client.hasOngoingSmsRequest(entry.form.target.packageName).addOnCompleteListener { ongoing ->
            if (completed) return@addOnCompleteListener
            if (!ongoing.isSuccessful || ongoing.result != false) return@addOnCompleteListener cancel()
            client.checkPermissionState().addOnCompleteListener { permission ->
                if (completed) return@addOnCompleteListener
                if (!permission.isSuccessful || !SmsOtpEligibility.allowed(false, permission.result)) return@addOnCompleteListener cancel()
                startRetriever()
            }
        }
    }

    private fun startRetriever() {
        SmsCodeRetriever.getAutofillClient(this).startSmsCodeRetriever()
            .addOnFailureListener { error ->
                if (completed) return@addOnFailureListener
                if (error is ResolvableApiException && !consentResolvedOnce) {
                    awaitingConsent = true
                    consentResolvedOnce = true
                    try { error.startResolutionForResult(this, CONSENT_REQUEST) }
                    catch (_: Exception) { cancel() }
                } else cancel()
            }
    }

    @Deprecated("Google Play services uses startResolutionForResult")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != CONSENT_REQUEST) return
        awaitingConsent = false
        if (resultCode == RESULT_OK && !completed) startRetriever() else cancel()
    }

    private fun deliver(code: String?) {
        val entry = request ?: return cancel()
        if (!entry.valid() || !entry.form.target.stillInstalled(this) ||
            !SmsOtpRequests.validCode(code, entry.form.fields.size)) return cancel()
        val value = code ?: return cancel()
        val dataset = Dataset.Builder(VaultAutofillService.presentation(this, "短信验证码"))
        if (entry.form.fields.size == 1) dataset.setValue(entry.form.fields.single(), AutofillValue.forText(value))
        else entry.form.fields.forEachIndexed { index, field -> dataset.setValue(field, AutofillValue.forText(value[index].toString())) }
        completed = true
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build()))
        finish()
    }

    private fun cancel(reoffer: Boolean = false) {
        if (completed) return
        completed = true
        val entry = request
        if (!reoffer || entry == null || !entry.valid() || !entry.form.target.stillInstalled(this)) {
            finish()
            return
        }
        // Android keeps a selected authenticated Dataset in its current session.
        // Return a fresh one-time suggestion so a later tap can start a new request.
        handler.postDelayed({ if (!isFinishing) finish() }, 2_000L)
        val client = SmsCodeRetriever.getAutofillClient(this)
        client.hasOngoingSmsRequest(entry.form.target.packageName).addOnCompleteListener { ongoing ->
            if (isFinishing || !ongoing.isSuccessful || ongoing.result != false) {
                if (!isFinishing) finish()
                return@addOnCompleteListener
            }
            client.checkPermissionState().addOnCompleteListener { permission ->
                if (isFinishing) return@addOnCompleteListener
                if (permission.isSuccessful && SmsOtpEligibility.allowed(false, permission.result) &&
                    entry.valid() && entry.form.target.stillInstalled(this)) {
                    runCatching { VaultAutofillService.createSmsOtpResponse(this, entry.form).first }
                        .getOrNull()?.let { response ->
                            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
                        }
                }
                finish()
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (!awaitingConsent && !completed && !isChangingConfigurations) cancel()
    }

    override fun onDestroy() {
        handler.removeCallbacks(timeout)
        receiver?.let { runCatching { unregisterReceiver(it) } }
        request = null
        super.onDestroy()
    }

    companion object { private const val CONSENT_REQUEST = 4217 }
}
