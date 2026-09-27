package com.vaultmesh.app

import android.app.Application
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.widget.Toast
import java.util.UUID

enum class ProtectedCopyField(val label: String) {
    LoginPassword("登录密码"),
    LoginTotpCode("验证码"),
    CardNumber("卡号"),
    CardSecurityCode("安全码"),
    CardPin("卡片 PIN"),
    SshPassword("SSH 密码"),
    SshPublicKey("SSH 公钥"),
    SshPrivateKey("SSH 私钥"),
    SshKeyPassphrase("SSH 密钥口令"),
    SecretValue("服务密钥值"),
}

data class ProtectedCopyTarget(val id: String, val title: String, val field: ProtectedCopyField)
data class ProtectedCopyDraft(val target: ProtectedCopyTarget, val masterPassword: String = "")

/** Android-owned clipboard access; secrets never enter Compose list or persisted state. */
class ProtectedClipboardService private constructor(application: Application) {
    private val context = application.applicationContext
    private val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private val handler = Handler(Looper.getMainLooper())
    private var ownedLabel: String? = null
    private var clearRunnable: Runnable? = null
    private fun currentLabel(): String? = try {
        clipboard.primaryClipDescription?.label?.toString()
    } catch (_: RuntimeException) {
        null
    }
    private val listener = ClipboardManager.OnPrimaryClipChangedListener {
        val expected = ownedLabel ?: return@OnPrimaryClipChangedListener
        // A null description can mean loss of focus; never clear an unknown clip.
        if (currentLabel() != expected) {
            ownedLabel = null
        }
    }

    init {
        clipboard.addPrimaryClipChangedListener(listener)
    }

    fun readValue(target: ProtectedCopyTarget, masterPassword: String): String =
        when (target.field) {
            ProtectedCopyField.LoginPassword -> VaultNativeBridge.copyLoginPassword(target.id, masterPassword)
            ProtectedCopyField.LoginTotpCode -> VaultNativeBridge.copyLoginTotpCode(target.id, masterPassword)
            ProtectedCopyField.CardNumber -> VaultNativeBridge.copyCardNumber(target.id, masterPassword)
            ProtectedCopyField.CardSecurityCode -> VaultNativeBridge.copyCardSecurityCode(target.id, masterPassword)
            ProtectedCopyField.CardPin -> VaultNativeBridge.copyCardPin(target.id, masterPassword)
            ProtectedCopyField.SshPassword -> VaultNativeBridge.copySshPassword(target.id, masterPassword)
            ProtectedCopyField.SshPublicKey -> VaultNativeBridge.copySshPublicKey(target.id, masterPassword)
            ProtectedCopyField.SshPrivateKey -> VaultNativeBridge.copySshPrivateKey(target.id, masterPassword)
            ProtectedCopyField.SshKeyPassphrase -> VaultNativeBridge.copySshKeyPassphrase(target.id, masterPassword)
            ProtectedCopyField.SecretValue -> VaultNativeBridge.copySecretValue(target.id, masterPassword)
        }

    fun writeResponse(response: String): String {
        if (!response.startsWith("value:")) return response
        return writeText(response.substring("value:".length))
    }

    fun writeText(value: String): String {
        val label = "vaultmesh-${UUID.randomUUID()}"
        val clip = ClipData.newPlainText(label, value)
        clip.description.extras = PersistableBundle().apply {
            putBoolean(
                if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE
                else "android.content.extra.IS_SENSITIVE",
                true,
            )
        }
        return try {
            clearRunnable?.let(handler::removeCallbacks)
            ownedLabel = label
            clipboard.setPrimaryClip(clip)
            val clear = Runnable {
                if (ownedLabel == label && currentLabel() == label) {
                    if (Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip()
                    else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                }
                if (ownedLabel == label) ownedLabel = null
            }
            clearRunnable = clear
            handler.postDelayed(clear, 30_000)
            if (Build.VERSION.SDK_INT <= 32) {
                Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
            }
            "ok"
        } catch (_: RuntimeException) {
            ownedLabel = null
            "io_error"
        }
    }

    companion object {
        @Volatile private var instance: ProtectedClipboardService? = null

        fun get(application: Application): ProtectedClipboardService =
            instance ?: synchronized(this) {
                instance ?: ProtectedClipboardService(application).also { instance = it }
            }
    }
}
