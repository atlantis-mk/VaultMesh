package com.vaultmesh.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

/** Android Keystore seals the device secret; Rust combines it with the PIN and owns the Vault Key. */
internal class PinUnlockService(private val context: Context) {
    private val alias = "vaultmesh-pin-device-secret-v1"
    private val record = context.filesDir.toPath().resolve("vaultmesh-pin-device-seal.json")

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun enabled(): Boolean = runCatching {
        Files.isRegularFile(record) && keyStore().containsAlias(alias)
    }.getOrDefault(false)

    fun enroll(): String? = runCatching {
        disableLocal()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        val key = generator.generateKey()
        val secret = ByteArray(32).also(SecureRandom()::nextBytes)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val ciphertext = cipher.doFinal(secret)
            try {
                require(cipher.iv.size == 12 && ciphertext.size == 48)
                val bytes = JSONObject().apply {
                    put("version", 1)
                    put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                    put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                }.toString().toByteArray(Charsets.UTF_8)
                val partial = record.resolveSibling("vaultmesh-pin-device-seal.partial")
                try {
                    Files.write(partial, bytes)
                    Files.move(partial, record, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                } finally {
                    Files.deleteIfExists(partial)
                    bytes.fill(0)
                }
                Base64.encodeToString(secret, Base64.NO_WRAP or Base64.NO_PADDING)
            } finally {
                ciphertext.fill(0)
            }
        } finally {
            secret.fill(0)
        }
    }.getOrNull()

    fun readDeviceSecret(): String? = runCatching {
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
        require(json.length() == 3 && json.getInt("version") == 1)
        val iv = Base64.decode(json.getString("iv"), Base64.NO_WRAP)
        val ciphertext = Base64.decode(json.getString("ciphertext"), Base64.NO_WRAP)
        try {
            require(iv.size == 12 && ciphertext.size == 48)
            val key = keyStore().getKey(alias, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            val secret = cipher.doFinal(ciphertext)
            try {
                require(secret.size == 32)
                Base64.encodeToString(secret, Base64.NO_WRAP or Base64.NO_PADDING)
            } finally {
                secret.fill(0)
            }
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
    }.getOrNull()

    fun disableLocal() {
        Files.deleteIfExists(record)
        Files.deleteIfExists(record.resolveSibling("vaultmesh-pin-device-seal.partial"))
        val store = keyStore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }
}
