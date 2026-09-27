package com.vaultmesh.app

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import android.telephony.PhoneNumberUtils
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** A user-selected system Autofill value, independent of the encrypted Vault. */
internal class LocalPhoneNumber(private val context: Context) {
    private val record = context.noBackupFilesDir.toPath().resolve("autofill-local-phone.bin")
    private val alias = "vaultmesh-autofill-local-phone-v1"
    private val aad = "vaultmesh-autofill-local-phone-v1".toByteArray(Charsets.US_ASCII)

    fun simNumber(): String? = runCatching {
        if (context.checkSelfPermission(Manifest.permission.READ_PHONE_NUMBERS) != PackageManager.PERMISSION_GRANTED ||
            !context.packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION)) return null
        val raw = if (Build.VERSION.SDK_INT >= 33) {
            val service = context.getSystemService(SubscriptionManager::class.java) ?: return null
            service.getPhoneNumber(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID)
        } else {
            @Suppress("DEPRECATION")
            val number = context.getSystemService(TelephonyManager::class.java)?.line1Number
            number
        }
        normalize(raw)
    }.getOrNull()

    fun suggestedNumber(): String? {
        val countryIso = runCatching { context.getSystemService(TelephonyManager::class.java)?.simCountryIso }
            .getOrNull()?.takeIf { it.length == 2 } ?: Locale.getDefault().country
        return forAutofill(simNumber(), countryIso) ?: forAutofill(manualNumber(), countryIso)
    }

    fun manualNumber(): String? = runCatching {
        if (!Files.isRegularFile(record) || Files.size(record) !in 29..128) return null
        val sealed = Files.readAllBytes(record)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
            cipher.updateAAD(aad)
            val plain = cipher.doFinal(sealed, 12, sealed.size - 12)
            try { normalize(String(plain, Charsets.UTF_8)) } finally { plain.fill(0) }
        } finally { sealed.fill(0) }
    }.getOrNull()

    fun saveManualNumber(input: String): Boolean = runCatching {
        val number = normalize(input) ?: return false
        val plain = number.toByteArray(Charsets.UTF_8)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(aad)
            val sealed = cipher.iv + cipher.doFinal(plain)
            val partial = record.resolveSibling("autofill-local-phone.partial")
            try {
                Files.write(partial, sealed)
                Files.move(partial, record, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } finally { Files.deleteIfExists(partial); sealed.fill(0) }
        } finally { plain.fill(0) }
        true
    }.getOrDefault(false)

    fun clearManualNumber(): Boolean = runCatching { Files.deleteIfExists(record); true }.getOrDefault(false)

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

    companion object {
        /** Keep the national digits shown by the platform's phone formatter. */
        fun forAutofill(raw: String?, countryIso: String): String? {
            val normalized = normalize(raw) ?: return null
            if (!normalized.startsWith('+') && !normalized.startsWith("00")) return normalized
            val international = if (normalized.startsWith("00")) "+${normalized.drop(2)}" else normalized
            val formatted = PhoneNumberUtils.formatNumber(international, countryIso.uppercase(Locale.ROOT)) ?: return null
            val countryCode = Regex("^\\+(\\d{1,3})\\D").find(formatted)?.groupValues?.get(1)
                ?: return null
            if (!international.startsWith("+$countryCode")) return null
            return international.drop(countryCode.length + 1).takeIf { it.length in 6..20 }
        }

        /** Keep only dialable digits and one leading plus; reject letters and service codes. */
        fun normalize(raw: String?): String? {
            val value = raw?.trim() ?: return null
            if (value.length !in 6..64 || value.any { it !in '0'..'9' && it !in "+ -()." }) return null
            if (value.count { it == '+' } > 1 || ('+' in value && !value.startsWith('+'))) return null
            val digits = value.filter { it in '0'..'9' }
            if (digits.length !in 6..20) return null
            return (if (value.startsWith('+')) "+" else "") + digits
        }
    }
}
