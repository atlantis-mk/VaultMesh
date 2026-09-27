package com.vaultmesh.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject

/** Encrypted display-only metadata. Every selected item is rechecked by Rust after authorization. */
internal data class AutofillPreview(val id: String, val username: String, val title: String,
    val host: String?, val matched: Boolean = false, val suggested: Boolean = false,
    val relatedHint: Boolean = false)

internal class AutofillPreviewCache(private val context: Context) {
    private companion object { val gate = Any() }
    private val record = File(context.noBackupFilesDir, "autofill-preview-v1.bin")
    private val alias = "vaultmesh-autofill-preview-v1"
    private val aad = alias.toByteArray(Charsets.US_ASCII)

    fun vaultDigest(): String? = runCatching {
        VaultNativeBridge.autofillPreviewFingerprint(context.filesDir.absolutePath).takeIf { value ->
            value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
        }
    }.getOrNull()

    fun refreshLogins(logins: List<LoginSummary>, expectedDigest: String?) {
        synchronized(gate) {
        if (expectedDigest == null || expectedDigest != vaultDigest()) return
        val entries = JSONArray()
        logins.asSequence().filter { it.hasPassword }.take(500).forEach { item ->
            if (valid(item.id, item.username, item.title)) entries.put(JSONObject()
                .put("id", item.id).put("u", item.username).put("t", item.title)
                .put("h", httpsHost(item.url)))
        }
        val previous = read(expectedDigest)
        previous.put("g", entries)
        write(previous, expectedDigest)
        }
    }

    fun refreshTarget(target: AutofillTarget, items: List<FillCandidate>, expectedDigest: String?) {
        synchronized(gate) {
        if (expectedDigest == null || expectedDigest != vaultDigest()) return
        val previous = read(expectedDigest)
        val targets = previous.optJSONObject("targets") ?: JSONObject()
        val entries = JSONArray()
        items.take(100).forEach { item ->
            if (valid(item.id, item.username, item.title)) entries.put(JSONObject()
                .put("id", item.id).put("u", item.username).put("t", item.title)
                .put("m", item.matched).put("s", item.suggested).put("r", item.relatedHint))
        }
        val targetKey = target.json()
        targets.put(targetKey, entries)
        while (targets.length() > 8) {
            val old = targets.keys().asSequence().firstOrNull { it != targetKey } ?: break
            targets.remove(old)
        }
        previous.put("targets", targets)
        write(previous, expectedDigest)
        }
    }

    fun recommend(target: AutofillTarget, appLabel: String, recentIds: List<String>): List<AutofillPreview> {
        val digest = vaultDigest() ?: return emptyList()
        val cache = read(digest)
        val specific = cache.optJSONObject("targets")?.optJSONArray(target.json())
        val global = cache.optJSONArray("g")
        if (specific == null && global == null) return emptyList()
        val entries = sequenceOf(specific, global).filterNotNull().flatMap { array ->
            (0 until minOf(array.length(), 500)).asSequence().mapNotNull { index ->
            val row = array.optJSONObject(index) ?: return@mapNotNull null
            val id = row.optString("id")
            val username = row.optString("u")
            val title = row.optString("t")
            if (!valid(id, username, title)) return@mapNotNull null
            AutofillPreview(id, username, title, row.optString("h").takeIf(String::isNotEmpty),
                row.optBoolean("m"), row.optBoolean("s"), row.optBoolean("r"))
            }
        }.toList()
        val originHost = httpsHost(target.webOrigin)
        val hints = (target.packageName.split('.') + appLabel).map { it.lowercase() }
            .filter { it.length >= 2 && it !in setOf("com", "org", "net", "app", "android", "mobile", "client") }
        fun score(item: AutofillPreview): Int {
            val recent = recentIds.indexOf(item.id)
            if (recent >= 0) return recent
            if (item.matched) return 20
            if (item.suggested || (originHost != null && item.host == originHost)) return 21
            if (item.relatedHint || hints.any { hint ->
                item.title.contains(hint, ignoreCase = true) ||
                    item.host?.split('.')?.any { label -> label.equals(hint, ignoreCase = true) } == true
            }) return 22
            return Int.MAX_VALUE
        }
        return entries.distinctBy { it.id }.filter { score(it) != Int.MAX_VALUE }
            .sortedWith(compareBy<AutofillPreview> { score(it) }.thenBy { it.title }.thenBy { it.id })
            .take(5)
    }

    private fun valid(id: String, username: String, title: String): Boolean =
        runCatching { UUID.fromString(id) }.isSuccess && username.length <= 256 && title.length in 1..256

    private fun httpsHost(value: String?): String? = runCatching {
        val uri = java.net.URI(value ?: return null)
        uri.host?.lowercase()?.takeIf { uri.scheme.equals("https", ignoreCase = true) && it.length <= 253 }
    }.getOrNull()

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return generator.generateKey()
    }

    private fun read(digest: String): JSONObject = runCatching {
        if (!record.isFile || record.length() !in 29..262_144) return JSONObject().put("digest", digest)
        val sealed = record.readBytes()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
        cipher.updateAAD(aad)
        val plain = cipher.doFinal(sealed, 12, sealed.size - 12)
        try {
            val data = JSONObject(String(plain, Charsets.UTF_8))
            if (data.optString("digest") == digest) data else JSONObject().put("digest", digest)
        } finally { plain.fill(0); sealed.fill(0) }
    }.getOrDefault(JSONObject().put("digest", digest))

    private fun write(data: JSONObject, expectedDigest: String) {
        if (expectedDigest != vaultDigest()) return
        val plain = data.toString().toByteArray(Charsets.UTF_8)
        try {
            if (plain.size > 240_000) return
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(aad)
            val sealed = cipher.iv + cipher.doFinal(plain)
            val partial = File(record.parentFile, "autofill-preview-v1.partial")
            try {
                Files.write(partial.toPath(), sealed)
                Files.move(partial.toPath(), record.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } finally { Files.deleteIfExists(partial.toPath()); sealed.fill(0) }
        } finally { plain.fill(0) }
    }
}
