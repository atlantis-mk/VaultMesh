package com.vaultmesh.app

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

/** Seals only the random Rust wrapper secret. The Vault Key stays inside Rust. */
internal class BiometricUnlockService(private val context: Context) {
    private val alias = "vaultmesh-biometric-wrapper-v1"
    private val record = context.filesDir.toPath().resolve("vaultmesh-biometric-seal.json")

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun available(): Boolean = BiometricManager.from(context).canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG,
    ) == BiometricManager.BIOMETRIC_SUCCESS

    fun enabled(): Boolean = runCatching {
        readRecord() != null && keyStore().containsAlias(alias)
    }.getOrDefault(false)

    fun enrollmentCipher(): Cipher? = runCatching {
        if (!available()) return null
        disableLocal()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 30) {
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            spec.setUserAuthenticationValidityDurationSeconds(-1)
        }
        generator.init(spec.build())
        val key = generator.generateKey()
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
    }.getOrNull()

    fun storeSealedSecret(cipher: Cipher, encodedSecret: String): Boolean = runCatching {
        val secret = Base64.decode(encodedSecret, Base64.NO_WRAP)
        try {
            require(secret.size == 32)
            val ciphertext = cipher.doFinal(secret)
            require(cipher.iv.size == 12 && ciphertext.size == 48)
            val json = JSONObject().apply {
                put("version", 1)
                put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            }.toString().toByteArray(Charsets.UTF_8)
            val partial = record.resolveSibling("vaultmesh-biometric-seal.partial")
            try {
                Files.write(partial, json)
                Files.move(partial, record, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } finally {
                Files.deleteIfExists(partial)
                json.fill(0)
                ciphertext.fill(0)
            }
        } finally {
            secret.fill(0)
        }
    }.isSuccess

    fun unlockCipher(): Pair<Cipher, ByteArray>? = runCatching {
        val (iv, ciphertext) = readRecord() ?: return null
        val key = keyStore().getKey(alias, null) as? SecretKey ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        iv.fill(0)
        cipher to ciphertext
    }.getOrNull()

    fun releaseSecret(cipher: Cipher, ciphertext: ByteArray): String? = runCatching {
        try {
            val secret = cipher.doFinal(ciphertext)
            try {
                require(secret.size == 32)
                Base64.encodeToString(secret, Base64.NO_WRAP or Base64.NO_PADDING)
            } finally {
                secret.fill(0)
            }
        } finally {
            ciphertext.fill(0)
        }
    }.getOrNull()

    fun disableLocal() {
        Files.deleteIfExists(record)
        Files.deleteIfExists(record.resolveSibling("vaultmesh-biometric-seal.partial"))
        val store = keyStore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }

    private fun readRecord(): Pair<ByteArray, ByteArray>? {
        if (!Files.isRegularFile(record) || Files.size(record) > 4096) return null
        val bytes = ByteArray(4097)
        val length = Files.newInputStream(record).use { input ->
            var count = 0
            while (count < bytes.size) {
                val read = input.read(bytes, count, bytes.size - count)
                if (read <= 0) break
                count += read
            }
            count
        }
        val json = try {
            if (length > 4096) return null
            JSONObject(String(bytes, 0, length, Charsets.UTF_8))
        } finally {
            bytes.fill(0)
        }
        if (json.length() != 3 || json.getInt("version") != 1) return null
        val iv = Base64.decode(json.getString("iv"), Base64.NO_WRAP)
        val ciphertext = Base64.decode(json.getString("ciphertext"), Base64.NO_WRAP)
        if (iv.size != 12 || ciphertext.size != 48) return null
        return iv to ciphertext
    }
}
