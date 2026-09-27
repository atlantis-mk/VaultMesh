package com.vaultmesh.app

import android.app.Application
import android.net.Uri
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/** Copies encrypted Vault envelopes through one-shot document grants only. */
class BackupDocumentService(private val application: Application) {
    private val exportStage = File(application.filesDir, "vaultmesh-backup-export.vault")
    private val importStage = File(application.filesDir, "vaultmesh-backup-import.vault")
    private val importPartial = File(application.filesDir, "vaultmesh-backup-import.partial")

    fun clearExport() { exportStage.delete() }
    fun clearImport() {
        importStage.delete()
        importPartial.delete()
    }

    fun clearStaleStages() {
        clearExport()
        clearImport()
    }

    fun exportTo(uri: Uri): String = try {
        requireContent(uri)
        if (!exportStage.isFile || exportStage.length() > MAX_VAULT_BYTES) throw IOException()
        val expected = exportStage.inputStream().use(::digest)
        val output = application.contentResolver.openOutputStream(uri, "wt") ?: throw IOException()
        exportStage.inputStream().use { input -> output.use { input.copyTo(it) } }
        val actual = (application.contentResolver.openInputStream(uri) ?: throw IOException()).use(::digest)
        if (!MessageDigest.isEqual(expected, actual)) throw IOException()
        "ok"
    } catch (_: Exception) {
        "io_error"
    } finally {
        clearExport()
    }

    fun importFrom(uri: Uri): String = try {
        requireContent(uri)
        clearImport()
        val input = application.contentResolver.openInputStream(uri) ?: throw IOException()
        var count = 0L
        input.use { source ->
            FileOutputStream(importPartial).use { output ->
                val buffer = ByteArray(8192)
                while (true) {
                    val read = source.read(buffer)
                    if (read < 0) break
                    count += read
                    if (count > MAX_VAULT_BYTES) throw IOException()
                    output.write(buffer, 0, read)
                }
                output.fd.sync()
            }
        }
        if (count == 0L) throw IOException()
        Files.move(importPartial.toPath(), importStage.toPath(),
            StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        "ok"
    } catch (_: Exception) {
        clearImport()
        "io_error"
    }

    private fun requireContent(uri: Uri) {
        if (uri.scheme != "content") throw IOException()
    }

    private fun digest(input: java.io.InputStream): ByteArray {
        val hash = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        var count = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            count += read
            if (count > MAX_VAULT_BYTES) throw IOException()
            hash.update(buffer, 0, read)
        }
        return hash.digest()
    }

    companion object {
        private const val MAX_VAULT_BYTES = 64L * 1024L * 1024L
    }
}
