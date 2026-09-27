package com.vaultmesh.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject

/** Local encrypted ranking metadata. It never contains usernames or passwords. */
internal class AutofillSelectionHistory(context: Context) {
    private val record = context.noBackupFilesDir.toPath().resolve("autofill-selection-history.bin")
    private val alias = "vaultmesh-autofill-selection-v1"
    private val aad = "vaultmesh-autofill-selection-v1".toByteArray(Charsets.US_ASCII)
    private fun targetKey(target: AutofillTarget): String = JSONArray()
        .put(target.packageName).put(target.signerDigest).put(target.webOrigin).toString()

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

    private fun read(): JSONObject = runCatching {
        if (!Files.isRegularFile(record) || Files.size(record) !in 29..16384) return JSONObject()
        val sealed = Files.readAllBytes(record)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
        cipher.updateAAD(aad)
        val plain = cipher.doFinal(sealed, 12, sealed.size - 12)
        try { JSONObject(String(plain, Charsets.UTF_8)) } finally { plain.fill(0); sealed.fill(0) }
    }.getOrDefault(JSONObject())

    fun recentIds(target: AutofillTarget): List<String> {
        val array = read().optJSONArray(targetKey(target)) ?: return emptyList()
        return (0 until minOf(array.length(), 20)).mapNotNull { array.optString(it).takeIf(String::isNotEmpty) }
    }

    fun record(target: AutofillTarget, id: String) {
        if (id.length != 36) return
        val history = read()
        val key = targetKey(target)
        val ids = (listOf(id) + recentIds(target)).distinct().take(20)
        history.put(key, JSONArray(ids))
        // Bound the encrypted local cache; a full cache resets rather than retaining stale targets.
        if (history.length() > 30) {
            val current = history.getJSONArray(key)
            history.keys().asSequence().filter { it != key }.take(history.length() - 30).toList().forEach(history::remove)
            history.put(key, current)
        }
        val plain = history.toString().toByteArray(Charsets.UTF_8)
        try {
            if (plain.size > 12000) return
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(aad)
            val sealed = cipher.iv + cipher.doFinal(plain)
            val partial = record.resolveSibling("autofill-selection-history.partial")
            try {
                Files.write(partial, sealed)
                Files.move(partial, record, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } finally { Files.deleteIfExists(partial); sealed.fill(0) }
        } finally { plain.fill(0) }
    }
}
