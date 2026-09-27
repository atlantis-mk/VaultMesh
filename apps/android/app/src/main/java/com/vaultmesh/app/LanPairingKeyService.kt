package com.vaultmesh.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Unwraps one short-lived key for Rust's encrypted LAN identity and peer proof records. */
internal class LanPairingKeyService(private val context: Context) {
    private val alias = "vaultmesh-lan-pairing-wrap-v1"
    private val record = context.filesDir.toPath().resolve("lan-pairing-key-seal")

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun readOrCreate(): ByteArray? = runCatching {
        val store = keyStore()
        val recordExists = Files.exists(record)
        val keyExists = store.containsAlias(alias)
        if (recordExists != keyExists) return null
        if (recordExists) {
            if (Files.size(record) != 61L) return null
            val bytes = Files.readAllBytes(record)
            try {
                if (bytes.size != 61 || bytes[0] != 1.toByte()) return null
                val key = store.getKey(alias, null) as? SecretKey ?: return null
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes.copyOfRange(1, 13)))
                cipher.doFinal(bytes, 13, 48).takeIf { it.size == 32 }
            } finally {
                bytes.fill(0)
            }
        } else {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            generator.init(KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
            val key = generator.generateKey()
            val secret = ByteArray(32).also(SecureRandom()::nextBytes)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                val encrypted = cipher.doFinal(secret)
                try {
                    require(cipher.iv.size == 12 && encrypted.size == 48)
                    val bytes = byteArrayOf(1) + cipher.iv + encrypted
                    val partial = record.resolveSibling("lan-pairing-key-seal.partial")
                    try {
                        FileOutputStream(partial.toFile()).use { output ->
                            output.write(bytes)
                            output.fd.sync()
                        }
                        Files.move(partial, record, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                    } finally {
                        bytes.fill(0)
                        Files.deleteIfExists(partial)
                    }
                    secret.copyOf()
                } finally {
                    encrypted.fill(0)
                }
            } catch (failure: Exception) {
                store.deleteEntry(alias)
                throw failure
            } finally {
                secret.fill(0)
            }
        }
    }.getOrNull()
}
