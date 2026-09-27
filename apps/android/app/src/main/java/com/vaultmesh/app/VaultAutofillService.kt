package com.vaultmesh.app

import android.app.PendingIntent
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillValue
import android.view.View
import android.widget.RemoteViews
import com.google.android.gms.auth.api.phone.SmsCodeRetriever
import com.google.android.gms.tasks.Tasks
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

internal sealed interface AutofillSuggestion {
    data class Login(val preview: AutofillPreview) : AutofillSuggestion
    data class RandomAccount(val username: String) : AutofillSuggestion
    data class Phone(val number: String) : AutofillSuggestion
    data object OpenVault : AutofillSuggestion
}

internal object AutofillRandomAccount {
    private const val ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
    private val random = SecureRandom()
    fun generate(): String = buildString(12) {
        append("vm")
        repeat(10) { append(ALPHABET[random.nextInt(ALPHABET.length)]) }
    }
}

class VaultAutofillService : AutofillService() {
    private val worker = Executors.newSingleThreadExecutor()

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        worker.execute {
            var pendingIds: List<String> = emptyList()
            try {
                if (Build.VERSION.SDK_INT >= 28) {
                    val otp = request.fillContexts.lastOrNull()?.structure?.let { AutofillStructure.parseSmsOtp(this, it) }
                    if (otp != null) {
                        if (cancellationSignal.isCanceled) return@execute
                        val response = if (smsOtpEligible(this, otp.target.packageName)) createSmsOtpResponse(this, otp) else null
                        if (cancellationSignal.isCanceled) {
                            response?.second?.let(SmsOtpRequests::remove)
                            return@execute
                        }
                        callback.onSuccess(response?.first)
                        return@execute
                    }
                }
                val form = AutofillStructure.parseContexts(this, request.fillContexts)
                if (form == null || (form.fillIds.isEmpty() && form.savePassword == null)) {
                    if (!cancellationSignal.isCanceled) callback.onSuccess(null)
                    return@execute
                }
                val (response, ids) = createFillResponse(this, form)
                pendingIds = ids
                val delivered = AtomicBoolean(false)
                cancellationSignal.setOnCancelListener {
                    if (!delivered.get()) ids.forEach(AutofillRequests::remove)
                }
                if (cancellationSignal.isCanceled) { ids.forEach(AutofillRequests::remove); return@execute }
                delivered.set(true)
                callback.onSuccess(response)
            } catch (_: Exception) {
                pendingIds.forEach(AutofillRequests::remove)
                if (!cancellationSignal.isCanceled) callback.onFailure("无法识别当前登录表单")
            }
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        worker.execute {
            val originalId = request.clientState?.getString(AutofillRequests.EXTRA_REQUEST)
            var pendingId: String? = null
            try {
                val original = AutofillRequests.get(originalId) ?: error("expired")
                val capture = AutofillStructure.capture(this, request.fillContexts, original.form) ?: error("invalid")
                val pending = AutofillRequests.create(original.form, capture)
                pendingId = pending.id
                AutofillRequests.remove(originalId)
                val intent = authenticationIntent(pending.id)
                if (Build.VERSION.SDK_INT >= 28) callback.onSuccess(intent.intentSender)
                else { intent.send(); callback.onSuccess() }
            } catch (_: Exception) {
                AutofillRequests.remove(originalId)
                AutofillRequests.remove(pendingId)
                callback.onFailure("无法保存，请重新触发登录保存")
            }
        }
    }

    private fun authenticationIntent(id: String): PendingIntent = authenticationIntent(this, id)

    override fun onDestroy() { worker.shutdown(); super.onDestroy() }

    companion object {
        private fun smsOtpEligible(context: android.content.Context, targetPackage: String): Boolean = runCatching {
            val client = SmsCodeRetriever.getAutofillClient(context)
            val ongoing = Tasks.await(client.hasOngoingSmsRequest(targetPackage), 2, TimeUnit.SECONDS)
            val permission = Tasks.await(client.checkPermissionState(), 2, TimeUnit.SECONDS)
            SmsOtpEligibility.allowed(ongoing, permission)
        }.getOrDefault(false)

        internal fun createSmsOtpResponse(context: android.content.Context, form: SmsOtpForm): Pair<FillResponse, String> {
            val entry = SmsOtpRequests.create(form)
            try {
                val intent = PendingIntent.getActivity(context, 0,
                    Intent(context, SmsOtpAutofillActivity::class.java).apply {
                        data = Uri.parse("vaultmesh-sms-otp://request/${entry.id}")
                        putExtra(SmsOtpRequests.EXTRA_REQUEST, entry.id)
                    }, PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_MUTABLE)
                val dataset = Dataset.Builder(presentation(context, "填充短信验证码"))
                form.fields.forEach { dataset.setValue(it, null) }
                dataset.setAuthentication(intent.intentSender)
                return FillResponse.Builder().addDataset(dataset.build()).build() to entry.id
            } catch (error: Exception) {
                SmsOtpRequests.remove(entry.id)
                throw error
            }
        }

        internal fun createFillResponse(context: android.content.Context, form: AutofillForm): Pair<FillResponse, List<String>> {
            val ids = ArrayList<String>(14)
            try {
                val primary = AutofillRequests.create(form, fillScope =
                    if (form.username == null) AutofillRequests.FillScope.PasswordOnly else AutofillRequests.FillScope.Pair)
                ids.add(primary.id)
                val response = FillResponse.Builder().setClientState(Bundle().apply {
                    putString(AutofillRequests.EXTRA_REQUEST, primary.id)
                })
                val appLabel = runCatching { context.packageManager.getApplicationLabel(
                    context.packageManager.getApplicationInfo(form.target.packageName, 0)).toString().take(64)
                }.getOrDefault(form.target.packageName.take(64))
                val (previews, previewDigest, recentIds) = runCatching {
                    if (VaultNativeBridge.status() == "not_initialized") VaultNativeBridge.initialize(context.filesDir.absolutePath)
                    val history = AutofillSelectionHistory(context).recentIds(form.target)
                    val cache = AutofillPreviewCache(context)
                    val before = cache.vaultDigest()
                    val candidates = cache.recommend(form.target, appLabel, history)
                    if (before != null && before == cache.vaultDigest()) Triple(candidates, before, history)
                    else Triple(emptyList<AutofillPreview>(), null, emptyList<String>())
                }.getOrDefault(Triple(emptyList<AutofillPreview>(), null, emptyList<String>()))
                val phone = if (form.username != null) {
                    runCatching { LocalPhoneNumber(context).suggestedNumber() }.getOrNull()
                } else null
                val randomAccount = if (form.username != null && form.password == null && !form.phoneOnlyUsername)
                    AutofillRandomAccount.generate() else null
                suggestionOrder(if (form.phoneOnlyUsername) emptyList() else previews, recentIds, randomAccount, phone).forEach { suggestion ->
                    when (suggestion) {
                        is AutofillSuggestion.Login -> {
                            val preview = suggestion.preview
                            form.username?.let { usernameId ->
                                val selected = AutofillRequests.create(form, fillScope = AutofillRequests.FillScope.Pair,
                                    clientStateId = primary.id, selectedId = preview.id, selectedDigest = previewDigest)
                                ids.add(selected.id)
                                response.addDataset(Dataset.Builder(credentialPresentation(context, preview.username,
                                    credentialSubtitle(preview.title, form.target.packageName, appLabel)))
                                    .setValue(usernameId, null)
                                    .setAuthentication(authenticationIntent(context, selected.id).intentSender).build())
                            }
                            form.password?.let { passwordId ->
                                val selected = AutofillRequests.create(form, fillScope = AutofillRequests.FillScope.PasswordOnly,
                                    clientStateId = primary.id, selectedId = preview.id, selectedDigest = previewDigest)
                                ids.add(selected.id)
                                response.addDataset(Dataset.Builder(credentialPresentation(context, preview.username,
                                    credentialSubtitle(preview.title, form.target.packageName, appLabel)))
                                    .setValue(passwordId, null)
                                    .setAuthentication(authenticationIntent(context, selected.id).intentSender).build())
                            }
                        }
                        is AutofillSuggestion.Phone -> form.username?.let { usernameId ->
                            response.addDataset(phoneDataset(context, usernameId, suggestion.number))
                        }
                        is AutofillSuggestion.RandomAccount -> form.username?.let { usernameId ->
                            response.addDataset(Dataset.Builder(credentialPresentation(context, suggestion.username, "随机账号"))
                                .setValue(usernameId, AutofillValue.forText(suggestion.username)).build())
                        }
                        AutofillSuggestion.OpenVault -> {
                            val entry = form.username ?: form.password
                            if (entry != null) {
                                response.addDataset(Dataset.Builder(presentation(context, "使用 VaultMesh 填充"))
                                    .setValue(entry, null)
                                    .setAuthentication(authenticationIntent(context, primary.id).intentSender).build())
                            }
                            if (form.username != null && form.password != null) {
                                val password = AutofillRequests.create(form, fillScope = AutofillRequests.FillScope.PasswordOnly,
                                    clientStateId = primary.id)
                                ids.add(password.id)
                                response.addDataset(Dataset.Builder(passwordActionPresentation(context, "使用 VaultMesh 填充"))
                                    .setValue(form.password, null)
                                    .setAuthentication(authenticationIntent(context, password.id).intentSender).build())
                            }
                        }
                    }
                }
                saveInfo(form)?.let(response::setSaveInfo)
                return response.build() to ids
            } catch (cause: Exception) {
                ids.forEach(AutofillRequests::remove)
                throw cause
            }
        }

        internal fun suggestionOrder(previews: List<AutofillPreview>, recentIds: List<String>, randomAccount: String?, phone: String?): List<AutofillSuggestion> {
            val recent = recentIds.toSet()
            val (preferred, other) = previews.partition { it.matched || it.id in recent }
            return buildList {
                preferred.forEach { add(AutofillSuggestion.Login(it)) }
                if (randomAccount != null) add(AutofillSuggestion.RandomAccount(randomAccount))
                if (phone != null) add(AutofillSuggestion.Phone(phone))
                add(AutofillSuggestion.OpenVault)
                other.forEach { add(AutofillSuggestion.Login(it)) }
            }
        }

        private fun authenticationIntent(context: android.content.Context, id: String): PendingIntent = PendingIntent.getActivity(
            context, 0, Intent(context, AutofillAuthActivity::class.java).apply {
                data = Uri.parse("vaultmesh-autofill://request/$id")
                putExtra(AutofillRequests.EXTRA_REQUEST, id)
            }, PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_MUTABLE,
        )

        internal fun presentation(context: android.content.Context, label: String) =
            RemoteViews(context.packageName, R.layout.autofill_action_suggestion).apply {
                setTextViewText(android.R.id.text1, label)
            }

        internal fun passwordActionPresentation(context: android.content.Context, label: String) =
            RemoteViews(context.packageName, R.layout.autofill_password_action_suggestion).apply {
                setTextViewText(android.R.id.text1, label)
            }

        internal fun credentialSubtitle(title: String, targetPackage: String, appLabel: String): String =
            if (title == targetPackage) appLabel else title

        internal fun credentialPresentation(context: android.content.Context, username: String, title: String) =
            RemoteViews(context.packageName, R.layout.autofill_credential_suggestion).apply {
                setTextViewText(android.R.id.text1, username.ifBlank { title })
                setTextViewText(android.R.id.text2, title.takeIf { username.isNotBlank() && it != username }.orEmpty())
                setViewVisibility(android.R.id.text2, if (username.isNotBlank() && title != username) View.VISIBLE else View.GONE)
            }

        internal fun phonePresentation(context: android.content.Context, number: String) =
            RemoteViews(context.packageName, R.layout.autofill_phone_suggestion).apply {
                setTextViewText(android.R.id.text1, "本机号码")
                setTextViewText(android.R.id.text2, maskedPhone(number))
            }

        internal fun phoneDataset(context: android.content.Context, usernameId: android.view.autofill.AutofillId, number: String): Dataset =
            Dataset.Builder(phonePresentation(context, number))
                .setValue(usernameId, AutofillValue.forText(number)).build()

        internal fun maskedPhone(number: String): String = "•••• ${number.takeLast(4)}"

        internal fun saveInfo(form: AutofillForm): SaveInfo? {
            if (form.savePassword == null) {
                if (Build.VERSION.SDK_INT < 29 || form.saveUsername == null) return null
                return SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_USERNAME, arrayOf(form.saveUsername))
                    .setFlags(SaveInfo.FLAG_DELAY_SAVE).build()
            }
            val required = listOfNotNull(form.savePassword).toTypedArray()
            val builder = SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD or SaveInfo.SAVE_DATA_TYPE_USERNAME, required)
                .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            form.saveUsername?.let { builder.setOptionalIds(arrayOf(it)) }
            return builder.build()
        }
    }
}
