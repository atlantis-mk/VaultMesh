package com.vaultmesh.app

import android.app.assist.AssistStructure
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.service.autofill.FillContext
import android.view.View
import android.view.autofill.AutofillId
import org.json.JSONObject
import java.security.MessageDigest

internal data class AutofillTarget(val packageName: String, val signerDigest: String, val webOrigin: String?) {
    fun json(): String = JSONObject().put("packageName", packageName).put("signerDigest", signerDigest)
        .put("webOrigin", webOrigin ?: JSONObject.NULL).toString()
    fun stillInstalled(context: Context): Boolean = signer(context, packageName) == signerDigest
    companion object {
        @Suppress("DEPRECATION")
        fun signer(context: Context, packageName: String): String? = runCatching {
            val signatures = if (Build.VERSION.SDK_INT >= 28) {
                context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners
            } else context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures
            if (signatures.isNullOrEmpty()) return null
            val certs = signatures.map { signature ->
                MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }
            }.sorted().joinToString(":")
            MessageDigest.getInstance("SHA-256").digest(certs.toByteArray(Charsets.US_ASCII)).joinToString("") { "%02x".format(it) }
        }.getOrNull()
    }
}

internal data class AutofillForm(
    val target: AutofillTarget, val activity: String,
    val username: AutofillId?, val password: AutofillId?, val savePassword: AutofillId?,
    val confirmation: AutofillId?, val saveUsername: AutofillId? = username,
    val phoneOnlyUsername: Boolean = false,
) {
    val fillIds: List<AutofillId> get() = listOfNotNull(username, password).distinct()
    val saveIds: List<AutofillId> get() = listOfNotNull(saveUsername, savePassword).distinct()
}

internal object AutofillStructure {
    private data class Field(val id: AutofillId, val role: LoginFieldRole, val origin: String?, val focused: Boolean, val ancestors: List<Int>, val order: Int)

    internal fun knownPhoneRegistration(packageName: String, activity: String, editableCount: Int, maxLength: Int): Boolean =
        packageName == "com.tencent.mobileqq" &&
            activity == "com.tencent.mobileqq.activity.RegisterPhoneNumActivity" &&
            editableCount == 1 && maxLength == 15

    fun parseSmsOtp(context: Context, structure: AssistStructure): SmsOtpForm? = runCatching {
        val component = structure.activityComponent ?: return null
        if (component.packageName == context.packageName || structure.windowNodeCount !in 1..8) return null
        val digest = AutofillTarget.signer(context, component.packageName) ?: return null
        data class OtpField(val id: AutofillId, val position: Int, val origin: String?, val focused: Boolean)
        val fields = ArrayList<OtpField>()
        var count = 0
        var inputs = 0
        var invalid = false
        fun walk(node: AssistStructure.ViewNode, inheritedOrigin: String?, depth: Int) {
            if (invalid) return
            if (++count > 2048 || depth > 64) { invalid = true; return }
            var origin = inheritedOrigin
            node.webDomain?.let { domain ->
                val scheme = if (Build.VERSION.SDK_INT >= 28) node.webScheme else null
                val normalized = AutofillFields.origin(domain, scheme)
                if (normalized == null || (origin != null && origin != normalized)) { invalid = true; return }
                origin = normalized
            }
            if (node.visibility == View.VISIBLE && node.isEnabled && node.autofillType == View.AUTOFILL_TYPE_TEXT) {
                if (++inputs > 64) { invalid = true; return }
                val id = node.autofillId
                val attrs = node.htmlInfo?.attributes?.associate { it.first to it.second } ?: emptyMap()
                val position = AutofillFields.smsOtpPosition(node.autofillHints?.toList() ?: emptyList(),
                    listOfNotNull(node.idEntry, attrs["name"], attrs["id"]).joinToString(" "), node.hint)
                if (id != null && position != null) fields.add(OtpField(id, position, origin, node.isFocused))
            }
            for (i in 0 until node.childCount) walk(node.getChildAt(i), origin, depth + 1)
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode, null, 0)
        if (invalid || fields.isEmpty() || fields.none { it.focused } || fields.map { it.origin }.distinct().size != 1) return null
        val selected = if (fields.size == 1 && fields.single().position == 0) listOf(fields.single()) else {
            if (fields.any { it.position == 0 } || fields.size !in 4..8 || fields.count { it.focused } != 1) return null
            val sorted = fields.sortedBy { it.position }
            if (sorted.map { it.position } != (1..sorted.size).toList()) return null
            sorted
        }
        SmsOtpForm(AutofillTarget(component.packageName, digest, selected.first().origin),
            component.flattenToString(), selected.map { it.id })
    }.getOrNull()

    fun parse(context: Context, structure: AssistStructure): AutofillForm? = runCatching {
        val component = structure.activityComponent ?: return null
        if (component.packageName == context.packageName) return null
        val digest = AutofillTarget.signer(context, component.packageName) ?: return null
        val fields = ArrayList<Field>()
        val unnamedText = ArrayList<Field>()
        val qqPhoneNumber = ArrayList<Pair<Field, Int>>()
        var count = 0
        var editableCount = 0
        var invalid = false
        fun walk(node: AssistStructure.ViewNode, inheritedOrigin: String?, ancestors: List<Int>, depth: Int) {
            if (invalid) return
            if (++count > 2048 || depth > 64 || fields.size > 64) { invalid = true; return }
            var origin = inheritedOrigin
            node.webDomain?.let { domain ->
                val scheme = if (Build.VERSION.SDK_INT >= 28) node.webScheme else null
                val normalized = AutofillFields.origin(domain, scheme)
                if (normalized == null || (origin != null && normalized != origin)) { invalid = true; return }
                origin = normalized
            }
            val path = ancestors + count
            if (node.visibility == View.VISIBLE && node.isEnabled && node.autofillType == View.AUTOFILL_TYPE_TEXT) {
                editableCount++
                val attrs = node.htmlInfo?.attributes?.associate { it.first to it.second } ?: emptyMap()
                val role = AutofillFields.classify(node.autofillHints?.toList() ?: emptyList(), attrs["autocomplete"],
                    listOfNotNull(node.idEntry, attrs["name"], attrs["id"]).joinToString(" "), node.hint, attrs["type"], node.inputType)
                val id = node.autofillId
                if (role != null && id != null) fields.add(Field(id, role, origin, node.isFocused, ancestors, count))
                else if (id != null && node.className == "android.widget.AutoCompleteTextView" &&
                    node.idEntry.isNullOrBlank() && node.hint.isNullOrBlank() &&
                    node.autofillHints.isNullOrEmpty() && node.inputType and 0xfff == 1) {
                    unnamedText.add(Field(id, LoginFieldRole.Username, origin, node.isFocused, ancestors, count))
                } else if (id != null && component.packageName == "com.tencent.mobileqq" &&
                    component.className == "com.tencent.mobileqq.activity.RegisterPhoneNumActivity" &&
                    node.className == "android.widget.EditText" &&
                    node.inputType == 2 && node.autofillHints.isNullOrEmpty() && node.hint.isNullOrBlank() &&
                    node.contentDescription == null && node.htmlInfo == null && origin == null && node.isFocused) {
                    qqPhoneNumber.add(Field(id, LoginFieldRole.Username, null, true, ancestors, count) to node.maxTextLength)
                }
            }
            for (i in 0 until node.childCount) walk(node.getChildAt(i), origin, path, depth + 1)
        }
        if (structure.windowNodeCount > 8) return null
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode, null, emptyList(), 0)
        // Some native login screens expose an unnamed AutoCompleteTextView next to one
        // explicit password field. Infer it only when these are the sole editable fields.
        if (editableCount == 2 && fields.size == 1 && fields[0].role == LoginFieldRole.Password &&
            unnamedText.size == 1 && unnamedText[0].order < fields[0].order &&
            unnamedText[0].origin == fields[0].origin) fields.add(0, unnamedText[0])
        val phoneOnlyUsername = fields.isEmpty() && qqPhoneNumber.size == 1 &&
            knownPhoneRegistration(component.packageName, component.className, editableCount, qqPhoneNumber[0].second)
        if (phoneOnlyUsername) fields.add(qqPhoneNumber[0].first)
        if (invalid || fields.isEmpty() || fields.map { it.origin }.distinct().size != 1) return null
        // If several forms exist, only the nearest ancestor of the focused field
        // containing a password and username can define the selected form.
        var selected = fields.toList()
        if (fields.count { it.role == LoginFieldRole.Username } > 1 || fields.count { it.role == LoginFieldRole.Password } > 1) {
            val focused = fields.singleOrNull { it.focused } ?: return null
            selected = focused.ancestors.asReversed().map { ancestor -> fields.filter { ancestor in it.ancestors } }
                .firstOrNull { group -> group.any { it.role == LoginFieldRole.Username } && group.any { it.role != LoginFieldRole.Username } } ?: return null
        }
        fun one(role: LoginFieldRole) = selected.filter { it.role == role }
        if (LoginFieldRole.entries.any { one(it).size > 1 }) return null
        val username = one(LoginFieldRole.Username).singleOrNull()?.id
        val current = one(LoginFieldRole.Password).singleOrNull()?.id
        val fresh = one(LoginFieldRole.NewPassword).singleOrNull()?.id
        val confirmation = one(LoginFieldRole.Confirmation).singleOrNull()?.id
        if (username == null && current == null && fresh == null) return null
        AutofillForm(AutofillTarget(component.packageName, digest, selected.first().origin),
            component.flattenToString(), username, if (fresh != null || confirmation == null) current else null, fresh ?: current, confirmation,
            saveUsername = if (phoneOnlyUsername) null else username, phoneOnlyUsername = phoneOnlyUsername)
    }.getOrNull()

    fun parseContexts(context: Context, contexts: List<FillContext>): AutofillForm? {
        if (contexts.isEmpty() || contexts.size > 8) return null
        val last = parse(context, contexts.last().structure) ?: return null
        if (last.saveUsername != null) return last
        val prior = contexts.dropLast(1).asReversed().mapNotNull { parse(context, it.structure) }
            .firstOrNull { it.target == last.target && it.activity == last.activity && it.saveUsername != null }
        return last.copy(saveUsername = prior?.saveUsername)
    }

    /** Called only for SaveRequest, never during discovery. */
    fun capture(context: Context, contexts: List<FillContext>, form: AutofillForm): CapturedLogin? {
        if (contexts.size !in 1..8 || !form.target.stillInstalled(context) || form.savePassword == null) return null
        val found = HashMap<AutofillId, CharArray>()
        val expected = (form.saveIds + listOfNotNull(form.confirmation)).toSet()
        try {
            for (fillContext in contexts) {
                val structure = fillContext.structure
                val parsed = parse(context, structure) ?: continue
                if (parsed.target != form.target || parsed.activity != form.activity) return null
                var count = 0
                fun walk(node: AssistStructure.ViewNode, depth: Int) {
                    check(++count <= 2048 && depth <= 64)
                    val id = node.autofillId
                    if (id in expected) {
                        val value = node.autofillValue
                        if (value != null && value.isText) {
                            val text = value.textValue
                            check(text.length <= 4096)
                            found.put(id!!, CharArray(text.length) { text[it] })?.fill('\u0000')
                        }
                    }
                    for (i in 0 until node.childCount) walk(node.getChildAt(i), depth + 1)
                }
                for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode, 0)
            }
            val password = found[form.savePassword] ?: return null
            val username = form.saveUsername?.let { found[it] } ?: charArrayOf()
            if (password.isEmpty() || username.size > 256) return null
            if (form.confirmation != null && !password.contentEquals(found[form.confirmation] ?: return null)) return null
            return CapturedLogin(username.copyOf(), password.copyOf())
        } catch (_: Exception) { return null }
        finally { found.values.forEach { it.fill('\u0000') } }
    }
}

internal class CapturedLogin(val username: CharArray, val password: CharArray) {
    fun clear() { username.fill('\u0000'); password.fill('\u0000') }
}
