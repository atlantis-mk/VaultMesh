package com.vaultmesh.app

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Reads a user selected UTF-8 document into transient memory; no plaintext staging file. */
class RecoveryDocumentService(private val context: Context) {
    fun readText(uri: Uri): String? {
        if (uri.scheme != "content") return null
        return try {
            val bytes = context.contentResolver.openInputStream(uri)?.use { stream ->
                val output = ByteArray(32 * 1024 + 1)
                var count = 0
                var emptyReads = 0
                while (count < output.size) {
                    val read = stream.read(output, count, output.size - count)
                    if (read < 0) break
                    if (read == 0) {
                        if (++emptyReads > 3) return null
                        continue
                    }
                    emptyReads = 0
                    count += read
                }
                if (count == 0 || count > 32 * 1024) null else output.copyOf(count)
            } ?: return null
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: Exception) {
            null
        }
    }

    fun deleteIfUnchanged(uri: Uri, expectedDigest: ByteArray): Boolean {
        if (uri.scheme != "content" || !DocumentsContract.isDocumentUri(context, uri)) return false
        val current = readText(uri) ?: return false
        val digest = MessageDigest.getInstance("SHA-256").digest(current.toByteArray(StandardCharsets.UTF_8))
        if (!digest.contentEquals(expectedDigest)) return false
        return try {
            val flags = context.contentResolver.query(
                uri, arrayOf(DocumentsContract.Document.COLUMN_FLAGS), null, null, null,
            )?.use { cursor ->
                if (!cursor.moveToFirst()) null else cursor.getInt(0)
            } ?: return false
            if (flags and DocumentsContract.Document.FLAG_SUPPORTS_DELETE == 0) return false
            DocumentsContract.deleteDocument(context.contentResolver, uri)
        } catch (_: Exception) {
            false
        }
    }
}
