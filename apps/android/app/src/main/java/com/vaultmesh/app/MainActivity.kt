package com.vaultmesh.app

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.net.Uri
import android.view.WindowManager
import android.widget.Toast
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.getValue
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date
import java.security.MessageDigest
import org.json.JSONObject

private data class RecoverySource(val itemId: String, val uri: Uri, val digest: ByteArray)
private data class PinUiStatus(val enabled: Boolean = false, val remainingAttempts: Int = 5)
private enum class UnlockMethod { BiometricPending, Pin, MasterPassword }

class MainActivity : FragmentActivity() {
    private val viewModel: VaultViewModel by viewModels()
    private val biometricUnlock by lazy { BiometricUnlockService(application) }
    private val pinUnlock by lazy { PinUnlockService(application) }
    private var biometricEnabled by mutableStateOf(false)
    private var pinStatus by mutableStateOf(PinUiStatus())
    private var pinStatusReady by mutableStateOf(false)
    private var pinDraft by mutableStateOf("")
    private var unlockMethod by mutableStateOf(UnlockMethod.MasterPassword)
    private var unlockForegroundReady by mutableStateOf(false)
    private var foregroundVisit = 0L
    private var autoBiometricVisit = -1L
    private var pinEnrollmentPending = false
    private var biometricPrompt: BiometricPrompt? = null
    private var biometricFlow: String? = null
    private var pendingBiometricToken: String? = null
    private var pendingBiometricCiphertext: ByteArray? = null
    private val backupDocuments by lazy { BackupDocumentService(application) }
    private val recoveryDocuments by lazy { RecoveryDocumentService(application) }
    private var recoveryPickerTarget: String? = null
    private var pendingRecoveryImport: Pair<String, Uri>? = null
    private var recoverySource: RecoverySource? = null
    private var recoveryDeleteCandidate by mutableStateOf<RecoverySource?>(null)
    private var backupPrepared = false
    private var foregroundGeneration = 0L
    private val lanKeyService by lazy { LanPairingKeyService(application) }
    private val lanNativeLock = Any()
    private var lanPanel by mutableStateOf<LanPanelState?>(null)
    @Volatile
    private var lanPanelGeneration = 0L
    private var lanPollJob: Job? = null
    private var lanMulticastLock: WifiManager.MulticastLock? = null
    private var lanPermissionError = false
    private var syncUi by mutableStateOf<SyncUiState?>(null)
    private var syncError by mutableStateOf<String?>(null)
    private var syncServiceState by mutableStateOf("同步服务未启动")
    private var syncPaused by mutableStateOf(false)
    private var syncConflicts by mutableStateOf<List<SyncConflict>?>(null)
    private var syncPollJob: Job? = null
    private var syncActionBusy by mutableStateOf(false)
    private var lastSyncGeneration = 0L

    private fun runSyncAction(action: () -> String) {
        if (syncActionBusy || viewModel.state.value.status != "unlocked") return
        syncActionBusy = true
        val generation = foregroundGeneration
        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    synchronized(lanNativeLock) {
                        if (generation != foregroundGeneration) "stale" else action()
                    }
                }
                if (generation != foregroundGeneration) return@launch
                syncError = if (result == "ok") null else "同步操作失败，请重试。"
                if (result == "ok") { syncConflicts = null; viewModel.refresh() }
            } finally { syncActionBusy = false }
        }
    }
    private fun retrySync() {
        if (!localNetworkAllowed()) {
            if (Build.VERSION.SDK_INT >= 37) requestLocalNetworkPermission.launch(android.Manifest.permission.ACCESS_LOCAL_NETWORK)
            syncError = "请授予本地网络权限，重新解锁后重试。"
            return
        }
        LanSyncService.start(this, explicit = true)
        syncPaused = false
        if (LanSyncService.running) runSyncAction { VaultNativeBridge.syncRetry() }
    }
    private fun showSyncConflicts() {
        val generation = foregroundGeneration
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { VaultNativeBridge.syncConflicts() }
            if (generation != foregroundGeneration || viewModel.state.value.status != "unlocked") return@launch
            val parsed = runCatching {
                val array = org.json.JSONArray(result)
                List(array.length()) { i -> array.getJSONObject(i).let { SyncConflict(it.getString("id"), it.getString("kind"), it.getLong("savedAt")) } }
            }.getOrNull()
            syncConflicts = parsed
            if (parsed == null) syncError = "无法读取冲突历史，请重试。"
        }
    }
    override fun onResume() {
        super.onResume()
        unlockForegroundReady = true
        // Permission sheets can pause/resume without another onStart.
        if (!pinStatusReady) refreshPinStatus()
        syncPollJob?.cancel()
        syncPollJob = lifecycleScope.launch {
            while (isActive) {
                val generation = foregroundGeneration
                DeviceAssistService.startIfEnabled(this@MainActivity)
                if (viewModel.state.value.status == "unlocked") {
                    val needed = withContext(Dispatchers.IO) { VaultNativeBridge.syncNeeded() }
                    if (generation != foregroundGeneration) break
                    if (needed == "yes" && LanSyncService.networkAllowed(this@MainActivity)) LanSyncService.start(this@MainActivity)
                    if (needed == "no" && LanSyncService.running) stopService(android.content.Intent(this@MainActivity, LanSyncService::class.java))
                    val next = withContext(Dispatchers.IO) { decodeSyncStatus(VaultNativeBridge.syncStatus()) }
                    if (generation != foregroundGeneration || viewModel.state.value.status != "unlocked") break
                    syncUi = next
                    if (next != null && next.generation != lastSyncGeneration && !viewModel.state.value.busy) {
                        lastSyncGeneration = next.generation
                        viewModel.refresh()
                    }
                    syncServiceState = LanSyncService.state
                    syncPaused = LanSyncService.paused(this@MainActivity)
                } else {
                    syncUi = null
                    syncConflicts = null
                }
                delay(1000)
            }
        }
    }


    private val requestLocalNetworkPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        lanPermissionError = !granted
    }

    private fun clearBiometricPending() {
        biometricFlow = null
        pendingBiometricToken = null
        pendingBiometricCiphertext?.fill(0)
        pendingBiometricCiphertext = null
        biometricPrompt = null
    }

    private fun fallbackUnlockMethod(): UnlockMethod =
        if (pinStatus.enabled && pinStatus.remainingAttempts > 0) UnlockMethod.Pin
        else UnlockMethod.MasterPassword

    private fun showUnlockFallback() {
        if (viewModel.state.value.status == "locked") unlockMethod = fallbackUnlockMethod()
    }

    private fun selectUnlockMethod(method: UnlockMethod) {
        if (viewModel.state.value.status != "locked" || viewModel.state.value.busy ||
            viewModel.state.value.loadingPhase != null) return
        pinDraft = ""
        viewModel.updatePassword("")
        if (method == UnlockMethod.BiometricPending) {
            if (!biometricEnabled) return
            unlockMethod = method
            unlockWithBiometric()
        } else {
            unlockMethod = method
        }
    }

    private fun autoUnlockWithBiometric() {
        if (!unlockForegroundReady || !pinStatusReady ||
            viewModel.state.value.status != "locked" || viewModel.state.value.busy) return
        if (autoBiometricVisit == foregroundVisit) {
            if (unlockMethod == UnlockMethod.BiometricPending && biometricFlow == null) showUnlockFallback()
            return
        }
        autoBiometricVisit = foregroundVisit
        if (biometricEnabled) {
            unlockMethod = UnlockMethod.BiometricPending
            unlockWithBiometric()
        } else showUnlockFallback()
    }

    private fun biometricPromptInfo(title: String): BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("取消")
            .build()

    private fun authenticateBiometric(title: String, cipher: javax.crypto.Cipher) {
        val generation = foregroundGeneration
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (generation != foregroundGeneration) return
                val kind = biometricFlow
                val token = pendingBiometricToken
                val ciphertext = pendingBiometricCiphertext
                val authorizedCipher = result.cryptoObject?.cipher
                pendingBiometricCiphertext = null
                clearBiometricPending()
                if (generation != foregroundGeneration || !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) ||
                    authorizedCipher == null) {
                    ciphertext?.fill(0)
                    if (generation == foregroundGeneration && kind == "unlock") {
                        showUnlockFallback()
                        viewModel.reportBiometricFailure()
                    }
                    return
                }
                if (kind == "enable" && token != null) {
                    lifecycleScope.launch {
                        val stored = withContext(Dispatchers.IO) { biometricUnlock.storeSealedSecret(authorizedCipher, token) }
                        if (generation == foregroundGeneration && stored) biometricEnabled = true
                        else {
                            withContext(Dispatchers.IO) { runCatching { biometricUnlock.disableLocal() } }
                            viewModel.disableBiometricUnlock()
                            viewModel.reportBiometricFailure()
                        }
                    }
                } else if (kind == "unlock" && ciphertext != null) {
                    viewModel.beginOpeningVault()
                    lifecycleScope.launch {
                        val secret = withContext(Dispatchers.IO) { biometricUnlock.releaseSecret(authorizedCipher, ciphertext) }
                        if (generation != foregroundGeneration) return@launch
                        if (secret != null && viewModel.state.value.status == "locked" && !viewModel.state.value.busy) {
                            viewModel.unlockWithBiometricSecret(secret) { success ->
                                if (!success) showUnlockFallback()
                            }
                        } else {
                            showUnlockFallback()
                            viewModel.reportBiometricFailure()
                        }
                    }
                } else ciphertext?.fill(0)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (generation != foregroundGeneration) return
                val wasEnabling = biometricFlow == "enable"
                val wasUnlocking = biometricFlow == "unlock"
                clearBiometricPending()
                if (wasEnabling) viewModel.disableBiometricUnlock()
                if (generation == foregroundGeneration && wasUnlocking) {
                    showUnlockFallback()
                    if (errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON &&
                        errorCode != BiometricPrompt.ERROR_USER_CANCELED &&
                        errorCode != BiometricPrompt.ERROR_CANCELED) viewModel.reportBiometricFailure()
                }
            }
        })
        biometricPrompt = prompt
        prompt.authenticate(biometricPromptInfo(title), BiometricPrompt.CryptoObject(cipher))
    }

    private fun enableBiometricUnlock() {
        if (biometricFlow != null || viewModel.state.value.busy || !biometricUnlock.available() ||
            viewModel.state.value.status != "unlocked") {
            viewModel.reportBiometricFailure()
            return
        }
        biometricFlow = "preparing"
        viewModel.prepareBiometricUnlock { token ->
            if (token == null || viewModel.state.value.status != "unlocked") {
                clearBiometricPending()
                return@prepareBiometricUnlock
            }
            val cipher = biometricUnlock.enrollmentCipher()
            if (cipher == null) {
                clearBiometricPending()
                viewModel.disableBiometricUnlock()
                viewModel.reportBiometricFailure()
                return@prepareBiometricUnlock
            }
            biometricFlow = "enable"
            pendingBiometricToken = token
            authenticateBiometric("启用生物识别解锁", cipher)
        }
    }

    private fun unlockWithBiometric() {
        if (biometricFlow != null || viewModel.state.value.busy || viewModel.state.value.status != "locked") return
        biometricFlow = "preparing_unlock"
        val generation = foregroundGeneration
        lifecycleScope.launch {
            val prepared = withContext(Dispatchers.IO) { biometricUnlock.unlockCipher() }
            if (generation != foregroundGeneration) {
                prepared?.second?.fill(0)
                return@launch
            }
            if (prepared == null) {
                clearBiometricPending()
                showUnlockFallback()
                viewModel.reportBiometricFailure()
                return@launch
            }
            biometricFlow = "unlock"
            pendingBiometricCiphertext = prepared.second
            authenticateBiometric("解锁 VaultMesh", prepared.first)
        }
    }

    private fun disableBiometricUnlock() {
        lifecycleScope.launch {
            val cleared = withContext(Dispatchers.IO) { runCatching { biometricUnlock.disableLocal() }.isSuccess }
            biometricEnabled = biometricUnlock.enabled()
            viewModel.disableBiometricUnlock()
            if (!cleared) viewModel.reportBiometricFailure()
        }
    }

    private fun refreshPinStatus() {
        val generation = foregroundGeneration
        lifecycleScope.launch {
            val status = withContext(Dispatchers.IO) {
                runCatching {
                    val json = JSONObject(VaultNativeBridge.pinStatus())
                    PinUiStatus(
                        pinUnlock.enabled() && json.getBoolean("enabled"),
                        json.getInt("remainingAttempts"),
                    )
                }.getOrDefault(PinUiStatus())
            }
            if (generation == foregroundGeneration) {
                pinStatus = status
                pinStatusReady = true
                if (unlockMethod == UnlockMethod.Pin && (!status.enabled || status.remainingAttempts == 0)) {
                    pinDraft = ""
                    unlockMethod = UnlockMethod.MasterPassword
                }
            }
        }
    }

    private fun enablePinUnlock(pin: String) {
        if (viewModel.state.value.status != "unlocked" || viewModel.state.value.busy) return
        pinEnrollmentPending = true
        val generation = foregroundGeneration
        lifecycleScope.launch {
            val secret = withContext(Dispatchers.IO) { pinUnlock.enroll() }
            if (generation != foregroundGeneration || secret == null) {
                withContext(Dispatchers.IO) { runCatching { pinUnlock.disableLocal() } }
                pinEnrollmentPending = false
                if (generation == foregroundGeneration) viewModel.reportPinFailure()
                return@launch
            }
            if (viewModel.state.value.status != "unlocked" || viewModel.state.value.busy) {
                withContext(Dispatchers.IO) { runCatching { pinUnlock.disableLocal() } }
                pinEnrollmentPending = false
                viewModel.reportPinFailure()
                return@launch
            }
            viewModel.enablePinUnlock(pin, secret) { success ->
                pinEnrollmentPending = false
                if (success) refreshPinStatus()
                else lifecycleScope.launch {
                    withContext(Dispatchers.IO) { runCatching { pinUnlock.disableLocal() } }
                    refreshPinStatus()
                }
            }
        }
    }

    private fun unlockWithPin() {
        val pin = pinDraft
        pinDraft = ""
        if (pin.length != 6 || viewModel.state.value.status != "locked" || pinStatus.remainingAttempts == 0) return
        viewModel.beginOpeningVault()
        val generation = foregroundGeneration
        lifecycleScope.launch {
            val secret = withContext(Dispatchers.IO) { pinUnlock.readDeviceSecret() }
            if (generation != foregroundGeneration) return@launch
            if (secret == null) {
                refreshPinStatus()
                viewModel.reportPinFailure()
                return@launch
            }
            viewModel.unlockWithPin(pin, secret, ::refreshPinStatus)
        }
    }

    private fun enterPinDigit(digit: String) {
        if (digit.length != 1 || digit[0] !in '0'..'9' || unlockMethod != UnlockMethod.Pin ||
            viewModel.state.value.status != "locked" || viewModel.state.value.busy ||
            viewModel.state.value.loadingPhase != null || pinDraft.length >= 6) return
        pinDraft += digit
        if (pinDraft.length == 6) unlockWithPin()
    }

    private fun deletePinDigit() {
        if (unlockMethod == UnlockMethod.Pin && !viewModel.state.value.busy &&
            viewModel.state.value.loadingPhase == null) {
            pinDraft = pinDraft.dropLast(1)
        }
    }

    private fun disablePinUnlock() {
        lifecycleScope.launch {
            val cleared = withContext(Dispatchers.IO) { runCatching { pinUnlock.disableLocal() }.isSuccess }
            viewModel.disablePinUnlock { refreshPinStatus() }
            if (!cleared) viewModel.reportPinFailure()
        }
    }
    private val createBackupDocument = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        if (!backupPrepared || uri == null) {
            backupPrepared = false
            backupDocuments.clearExport()
            return@registerForActivityResult
        }
        backupPrepared = false
        val generation = foregroundGeneration
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { backupDocuments.exportTo(uri) }
            if (generation == foregroundGeneration && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                if (result == "ok") Toast.makeText(this@MainActivity, "加密备份已写入", Toast.LENGTH_SHORT).show()
                else viewModel.reportDocumentFailure()
            }
        }
    }
    private val openBackupDocument = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        val generation = foregroundGeneration
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { backupDocuments.importFrom(uri) }
            if (generation != foregroundGeneration || !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                backupDocuments.clearImport()
                return@launch
            }
            if (result == "ok") viewModel.beginRestoreFromStage()
            else viewModel.reportDocumentFailure()
        }
    }
    private val openRecoveryDocument = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        val target = recoveryPickerTarget
        recoveryPickerTarget = null
        if (target != null && uri?.scheme == "content") {
            pendingRecoveryImport = target to uri
            if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) &&
                viewModel.state.value.status == "unlocked" && !viewModel.state.value.busy) {
                resumeRecoveryFileImport()
            }
        }
    }

    private fun startRecoveryFileImport(itemId: String) {
        recoveryPickerTarget = itemId
        pendingRecoveryImport = null
        recoverySource = null
        recoveryDeleteCandidate = null
        viewModel.cancelRecovery()
        try {
            openRecoveryDocument.launch(arrayOf("text/plain", "application/octet-stream"))
        } catch (_: RuntimeException) {
            recoveryPickerTarget = null
            viewModel.reportDocumentFailure()
        }
    }

    private fun resumeRecoveryFileImport() {
        val (itemId, uri) = pendingRecoveryImport ?: return
        pendingRecoveryImport = null
        val generation = foregroundGeneration
        val importToken = viewModel.recoveryImportToken()
        lifecycleScope.launch {
            val text = withContext(Dispatchers.IO) { recoveryDocuments.readText(uri) }
            if (generation != foregroundGeneration || !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return@launch
            if (text == null || !viewModel.beginRecoveryImportedText(itemId, text, importToken)) {
                viewModel.reportDocumentFailure()
            } else {
                recoverySource = RecoverySource(itemId, uri,
                    MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)))
            }
        }
    }

    private fun recoveryCodesSaved(itemId: String, inputDigest: ByteArray?) {
        val source = recoverySource
        recoverySource = null
        if (source != null && itemId == source.itemId && inputDigest != null &&
            inputDigest.contentEquals(source.digest)) {
            recoveryDeleteCandidate = source
        }
    }

    private fun closeRecoveryEditor() {
        recoverySource = null
        viewModel.cancelRecovery()
    }

    private fun confirmRecoverySourceDelete() {
        val source = recoveryDeleteCandidate ?: return
        recoveryDeleteCandidate = null
        val generation = foregroundGeneration
        lifecycleScope.launch {
            val deleted = withContext(Dispatchers.IO) {
                recoveryDocuments.deleteIfUnchanged(source.uri, source.digest)
            }
            if (generation == foregroundGeneration && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                Toast.makeText(this@MainActivity,
                    if (deleted) "源文件已删除" else "源文件未删除，请自行检查",
                    Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun startBackup() {
        viewModel.prepareBackup { ready ->
            if (!ready || !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                backupDocuments.clearExport()
                return@prepareBackup
            }
            backupPrepared = true
            try {
                createBackupDocument.launch("VaultMesh-backup.vault")
            } catch (_: RuntimeException) {
                backupPrepared = false
                backupDocuments.clearExport()
                viewModel.reportDocumentFailure()
            }
        }
    }

    private fun startRestore() {
        try {
            openBackupDocument.launch(arrayOf("application/octet-stream"))
        } catch (_: RuntimeException) {
            viewModel.reportDocumentFailure()
        }
    }

    private fun releaseLanMulticast() {
        lanMulticastLock?.let { lock -> runCatching { if (lock.isHeld) lock.release() } }
        lanMulticastLock = null
    }

    private fun localNetworkAllowed(): Boolean {
        if (Build.VERSION.SDK_INT >= 37 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED) {
            return false
        }
        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        return manager.allNetworks.any { network ->
            val capabilities = manager.getNetworkCapabilities(network)
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true ||
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true
        }
    }

    private fun closeLanPanel() {
        synchronized(lanNativeLock) {
            lanPanelGeneration += 1
            VaultNativeBridge.lanClose()
        }
        lanPollJob?.cancel()
        lanPollJob = null
        lanPanel = null
        releaseLanMulticast()
    }

    private fun openLanPanel() {
        if (lanPanel != null || viewModel.state.value.status != "unlocked") return
        lanPanelGeneration += 1
        val panelGeneration = lanPanelGeneration
        val foreground = foregroundGeneration
        lanPanel = LanPanelState(error = if (lanPermissionError) "本地网络权限尚未授予。" else null)
        lifecycleScope.launch {
            val raw = withContext(Dispatchers.IO) {
                val key = lanKeyService.readOrCreate() ?: return@withContext "key_unavailable"
                try {
                    synchronized(lanNativeLock) {
                        if (panelGeneration != lanPanelGeneration) return@synchronized "stale"
                        val opened = VaultNativeBridge.lanOpen(key)
                        if (opened == "ok") VaultNativeBridge.lanStatus() else opened
                    }
                } finally { key.fill(0) }
            }
            if (panelGeneration != lanPanelGeneration || foreground != foregroundGeneration ||
                viewModel.state.value.status != "unlocked") {
                return@launch
            }
            val status = decodeLanStatus(raw)
            lanPanel = lanPanel?.copy(status = status,
                error = if (status == null) "无法安全读取设备身份或已配对设备。"
                    else if (lanPermissionError) "本地网络权限尚未授予，请重试开启发现。" else null)
            if (status != null) {
                lanPollJob?.cancel()
                lanPollJob = lifecycleScope.launch {
                    while (isActive && panelGeneration == lanPanelGeneration &&
                        viewModel.state.value.status == "unlocked") {
                        delay(1_000)
                        if (lanPanel?.busy == true) continue
                        if (!localNetworkAllowed() && lanPanel?.status?.discoverable == true) {
                            lanPermissionError = true
                            val stopped = withContext(Dispatchers.IO) {
                                synchronized(lanNativeLock) {
                                    if (panelGeneration != lanPanelGeneration) return@synchronized null
                                    VaultNativeBridge.lanStop()
                                    decodeLanStatus(VaultNativeBridge.lanStatus())
                                }
                            }
                            if (panelGeneration != lanPanelGeneration || foreground != foregroundGeneration) break
                            releaseLanMulticast()
                            if (stopped == null) {
                                closeLanPanel()
                                lanPanel = LanPanelState(error = "附近设备状态不可用，请重新加载。")
                                break
                            }
                            lanPanel = lanPanel?.clearAction()?.withStatus(stopped)?.copy(
                                error = "发现已停止。请连接同一局域网，并允许本地网络访问。")
                            continue
                        }
                        val current = withContext(Dispatchers.IO) {
                            synchronized(lanNativeLock) {
                                if (panelGeneration == lanPanelGeneration) VaultNativeBridge.lanStatus() else "stale"
                            }
                        }
                        if (panelGeneration != lanPanelGeneration || foreground != foregroundGeneration) break
                        if (lanPanel?.busy == true) continue
                        val next = decodeLanStatus(current)
                        if (next != null) {
                            lanPanel = lanPanel?.withStatus(next)
                            if (!next.discoverable) releaseLanMulticast()
                        } else {
                            closeLanPanel()
                            lanPanel = LanPanelState(error = "附近设备状态不可用，发现已停止。请重新加载。")
                        }
                    }
                }
            }
        }
    }

    private fun lanError(result: String): String = when (
        runCatching { JSONObject(result).optString("error").takeIf(String::isNotBlank) }
            .getOrNull() ?: result
    ) {
        "invalid_input" -> "配对码、设备引用或名称无效。"
        "locked" -> "保险库已锁定，请重新解锁。"
        "not_initialized" -> "附近设备页面已关闭，请重新打开。"
        "lan_listener_unavailable" -> "无法开启局域网监听。请检查系统网络限制。"
        "lan_discovery_unavailable" -> "无法发布局域网设备。请检查 Wi-Fi 多播支持。"
        "lan_scan_unavailable" -> "无法扫描局域网设备。请检查 Wi-Fi 多播支持。"
        "lan_identity_unavailable" -> "无法读取或保存设备身份。"
        else -> "附近设备操作失败。请检查本地网络权限、Wi-Fi 和设备信任存储。"
    }

    private fun runLanOperation(operation: () -> String, onSuccess: (LanPanelState) -> LanPanelState = { it }) {
        val current = lanPanel ?: return
        if (current.busy || viewModel.state.value.status != "unlocked") return
        val panelGeneration = lanPanelGeneration
        val foreground = foregroundGeneration
        lanPanel = current.copy(busy = true, error = null)
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                synchronized(lanNativeLock) {
                    if (panelGeneration == lanPanelGeneration) operation() else "stale"
                }
            }
            if (panelGeneration != lanPanelGeneration || foreground != foregroundGeneration ||
                viewModel.state.value.status != "unlocked") return@launch
            val directStatus = decodeLanStatus(result)
            if (result != "ok" && directStatus == null) {
                if (lanPanel?.status?.discoverable != true) releaseLanMulticast()
                lanPanel = lanPanel?.copy(busy = false, pairingPending = false, error = lanError(result))
                return@launch
            }
            val next = directStatus ?: withContext(Dispatchers.IO) {
                synchronized(lanNativeLock) {
                    if (panelGeneration == lanPanelGeneration) decodeLanStatus(VaultNativeBridge.lanStatus()) else null
                }
            }
            if (panelGeneration != lanPanelGeneration) return@launch
            lanPanel = lanPanel?.let { onSuccess((if (next != null) it.withStatus(next) else it).copy(busy = false)) }
        }
    }

    private fun startLanDiscovery() {
        if (lanPanel?.busy != false || viewModel.state.value.status != "unlocked") return
        if (Build.VERSION.SDK_INT >= 37 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED) {
            try { requestLocalNetworkPermission.launch(Manifest.permission.ACCESS_LOCAL_NETWORK) }
            catch (_: RuntimeException) { lanPanel = lanPanel?.copy(error = "无法请求本地网络权限。") }
            return
        }
        if (!localNetworkAllowed()) {
            lanPanel = lanPanel?.copy(error = "请连接同一局域网的 Wi-Fi 或以太网后重试。")
            return
        }
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        if (wifi == null) {
            lanPanel = lanPanel?.copy(error = "Wi-Fi 多播服务不可用。")
            return
        }
        val lock = runCatching {
            wifi.createMulticastLock("vaultmesh-lan-pairing").apply {
                setReferenceCounted(false)
                acquire()
            }
        }.getOrNull()
        if (lock == null) {
            lanPanel = lanPanel?.copy(error = "无法开启局域网发现。")
            return
        }
        lanMulticastLock = lock
        runLanOperation({ VaultNativeBridge.lanStart() }) {
            if (it.status?.discoverable != true) releaseLanMulticast()
            it
        }
    }

    private fun stopLanDiscovery() {
        runLanOperation({ VaultNativeBridge.lanStop() }) { it.clearAction() }
        releaseLanMulticast()
    }

    private fun beginLanPairing() {
        val panel = lanPanel ?: return
        val peer = panel.pairingRef ?: return
        val code = panel.codeInput
        if (!panel.canBeginPairing()) return
        lanPanel = panel.copy(codeInput = "", pairingPending = true)
        runLanOperation({ VaultNativeBridge.lanBegin(peer, code) })
    }

    private fun revokeLanPeer() {
        val peer = lanPanel?.revokeRef ?: return
        runLanOperation({ VaultNativeBridge.lanRevoke(peer) }) { it.clearAction().notify("已撤销设备配对") }
    }

    private fun renameLanPeer() {
        val panel = lanPanel ?: return
        val peer = panel.renameRef ?: return
        val label = panel.labelInput.trim()
        if (label.isEmpty() || label.length > 64) return
        runLanOperation({ VaultNativeBridge.lanRename(peer, label) }) { it.clearAction().notify("设备名称已更新") }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        backupDocuments.clearStaleStages()
        viewModel.cancelRestore()
        check(VaultNativeBridge.initialize(filesDir.absolutePath) == "ok")
        biometricEnabled = biometricUnlock.enabled()
        unlockMethod = UnlockMethod.BiometricPending
        refreshPinStatus()
        setContent {
            VaultMeshTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        VaultScreen(viewModel, ::startBackup, ::startRestore,
                            biometricEnabled, ::enableBiometricUnlock, ::disableBiometricUnlock,
                            unlockMethod, unlockForegroundReady, pinStatusReady, ::autoUnlockWithBiometric,
                            ::selectUnlockMethod,
                            pinStatus, pinDraft, ::enterPinDigit, ::deletePinDigit,
                            ::enablePinUnlock, ::disablePinUnlock,
                            ::refreshPinStatus, ::closeLanPanel, ::openLanPanel,
                            nearbyContent = { modifier ->
                                LanDevicesPage(lanPanel ?: LanPanelState(error = "设备列表已关闭，请重新加载。"), ::startLanDiscovery, ::stopLanDiscovery,
                                    { runLanOperation({ VaultNativeBridge.lanStatus() }) },
                                    { closeLanPanel(); openLanPanel() },
                                    { lanPanel = lanPanel?.clearAction()?.copy(pairingRef = it) },
                                    { lanPanel = lanPanel?.copy(codeInput = it.filter { char -> char in '0'..'9' }.take(6)) },
                                    ::beginLanPairing,
                                    { lanPanel = lanPanel?.clearAction()?.copy(revokeRef = it) },
                                    ::revokeLanPeer,
                                    { peer, label -> lanPanel = lanPanel?.clearAction()?.copy(renameRef = peer, labelInput = label) },
                                    { lanPanel = lanPanel?.copy(labelInput = it.take(64)) },
                                    ::renameLanPeer,
                                    { lanPanel = lanPanel?.clearAction() },
                                    modifier = modifier,
                                    syncContent = {
                                        LanSyncPanel(syncUi, syncServiceState, syncPaused,
                                            ::retrySync,
                                            { LanSyncService.pause(this@MainActivity); stopService(android.content.Intent(this@MainActivity, LanSyncService::class.java)); syncPaused = true },
                                            ::showSyncConflicts, syncError)
                                        DeviceAssistPanel(lanPanel?.status?.trusted.orEmpty())
                                    },
                                    deviceSettings = { peer ->
                                        LanSyncPeerSettings(syncUi, peer, syncActionBusy,
                                            { ref, enabled -> runSyncAction { VaultNativeBridge.syncSetEnabled(ref, enabled) } }, syncError)
                                        DeviceAssistPanel(lanPanel?.status?.trusted.orEmpty(), settingsPeer = peer)
                                    })
                                syncConflicts?.let { conflicts ->
                                    SyncConflictDialog(conflicts,
                                        { id -> runSyncAction { VaultNativeBridge.syncRestoreConflict(id) } },
                                        { runSyncAction { VaultNativeBridge.syncClearConflicts() } },
                                        { syncConflicts = null })
                                }
                            },
                            ::startRecoveryFileImport, ::resumeRecoveryFileImport,
                            ::recoveryCodesSaved, ::closeRecoveryEditor, recoveryDeleteCandidate != null,
                            ::confirmRecoverySourceDelete, { recoveryDeleteCandidate = null })
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        // A visible permission overlay does not start a new automatic prompt visit.
        foregroundVisit += 1
        biometricEnabled = biometricUnlock.enabled()
        pinStatusReady = false
        viewModel.refresh()
    }

    private fun lockForLeavingForeground() {
        foregroundGeneration += 1
        unlockForegroundReady = false
        unlockMethod = UnlockMethod.BiometricPending
        syncPollJob?.cancel()
        syncUi = null
        syncConflicts = null
        syncError = null
        closeLanPanel()
        biometricPrompt?.cancelAuthentication()
        clearBiometricPending()
        pinDraft = ""
        pinStatus = PinUiStatus()
        pinStatusReady = false
        if (pinEnrollmentPending) {
            lifecycleScope.launch(Dispatchers.IO) { runCatching { pinUnlock.disableLocal() } }
            pinEnrollmentPending = false
        }
        recoverySource = null
        recoveryDeleteCandidate = null
        if (recoveryPickerTarget == null) pendingRecoveryImport = null
        viewModel.lock()
    }

    override fun onPause() {
        lockForLeavingForeground()
        super.onPause()
    }

    override fun onStop() {
        // Android can skip a visible stop during a rapid pause/resume transition.
        // Keep this as an idempotent fallback for any stop not preceded by pause.
        lockForLeavingForeground()
        super.onStop()
    }
}

@Composable
private fun VaultScreen(
    viewModel: VaultViewModel,
    onBackup: () -> Unit,
    onRestore: () -> Unit,
    biometricEnabled: Boolean,
    onEnableBiometric: () -> Unit,
    onDisableBiometric: () -> Unit,
    unlockMethod: UnlockMethod,
    unlockForegroundReady: Boolean,
    pinStatusReady: Boolean,
    onAutoBiometricUnlock: () -> Unit,
    onSelectUnlockMethod: (UnlockMethod) -> Unit,
    pinStatus: PinUiStatus,
    pinDraft: String,
    onPinDigit: (String) -> Unit,
    onPinDelete: () -> Unit,
    onEnablePin: (String) -> Unit,
    onDisablePin: () -> Unit,
    onUnlocked: () -> Unit,
    onLocked: () -> Unit,
    onNearby: () -> Unit,
    nearbyContent: @Composable (Modifier) -> Unit,
    onRecoveryFile: (String) -> Unit,
    onReadyForRecoveryFile: () -> Unit,
    onRecoverySaved: (String, ByteArray?) -> Unit,
    onCloseRecovery: () -> Unit,
    showRecoveryDelete: Boolean,
    onDeleteRecoverySource: () -> Unit,
    onKeepRecoverySource: () -> Unit,
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    LaunchedEffect(state.status, state.busy, biometricEnabled, unlockForegroundReady, pinStatusReady) {
        if (state.status == "locked" && !state.busy && unlockForegroundReady && pinStatusReady) {
            onAutoBiometricUnlock()
        }
    }
    LaunchedEffect(state.status) {
        if (state.status == "unlocked") onUnlocked()
        else onLocked()
    }
    LaunchedEffect(state.status, state.busy) {
        if (state.status == "unlocked" && !state.busy) onReadyForRecoveryFile()
    }
    Box(modifier = Modifier.fillMaxSize()) {
        when {
            state.loadingPhase != null -> VaultLoadingScreen(state.loadingPhase)
            state.status == "unlocked" -> UnlockedVaultScreen(state, viewModel, onBackup, onRestore,
                biometricEnabled, onEnableBiometric, onDisableBiometric,
                pinStatus.enabled, onEnablePin, onDisablePin, onNearby, onLocked, nearbyContent)
            else -> LockedVaultScreen(state, viewModel, onRestore, biometricEnabled, unlockMethod,
                onSelectUnlockMethod, pinStatus, pinDraft, onPinDigit, onPinDelete)
        }
        state.editor?.let { draft ->
            LoginEditorDialog(draft, state.busy, viewModel)
        }
        state.otherDraft?.let { draft ->
            OtherEditorDialog(draft, state.busy, viewModel)
        }
        state.passwordRotation?.let { draft ->
            PasswordRotationDialog(draft, state.busy, viewModel)
        }
        state.protectedCopy?.let { draft ->
            ProtectedCopyDialog(draft, state.busy, viewModel)
        }
        state.protectedReveal?.let { draft ->
            ProtectedRevealDialog(draft, state.busy, viewModel)
        }
        state.totp?.let { draft ->
            TotpDialog(draft, state.busy, viewModel)
        }
        state.recovery?.let { draft ->
            RecoveryDialog(draft, state.busy, viewModel, onRecoveryFile, onRecoverySaved, onCloseRecovery)
        }
        if (showRecoveryDelete) {
            AlertDialog(
                onDismissRequest = onKeepRecoverySource,
                title = { Text("删除导入的源文件？") },
                text = { Text("恢复码已经保存。仅当所选文件内容未变化且文件提供者允许删除时，才会尝试删除源文件。") },
                confirmButton = { TextButton(onClick = onDeleteRecoverySource) { Text("删除源文件") } },
                dismissButton = { TextButton(onClick = onKeepRecoverySource) { Text("保留文件") } },
            )
        }
        state.restorePassword?.let { password ->
            RestoreBackupDialog(password, state.busy, state.error, viewModel)
        }
        state.health?.let { panel ->
            PasswordHealthDialog(panel, state.logins, viewModel)
        }
        state.generator?.let { draft ->
            GeneratorDialog(draft, state.editor != null, viewModel)
        }
        state.history?.let { panel ->
            HistoryDialog(panel, viewModel)
        }
        state.restoreRevisionCandidate?.let { entry ->
            AlertDialog(
                onDismissRequest = viewModel::cancelRestoreRevision,
                title = { Text("恢复历史版本？") },
                text = { Text("当前条目将替换为“${entry.title}”的旧版本；当前版本会保存到历史中。") },
                confirmButton = { TextButton(onClick = viewModel::confirmRestoreRevision) { Text("恢复") } },
                dismissButton = { TextButton(onClick = viewModel::cancelRestoreRevision) { Text("取消") } },
            )
        }
        if (state.confirmClearHistory) {
            AlertDialog(
                onDismissRequest = viewModel::cancelClearHistory,
                title = { Text("清空历史？") },
                text = { Text("这个条目的全部历史版本将永久删除。") },
                confirmButton = { TextButton(onClick = viewModel::confirmClearHistory) { Text("清空") } },
                dismissButton = { TextButton(onClick = viewModel::cancelClearHistory) { Text("取消") } },
            )
        }
        state.otherDeleteCandidate?.let { item ->
            AlertDialog(
                onDismissRequest = viewModel::cancelOtherDelete,
                title = { Text(if (item.section == VaultSection.Secrets) "永久删除密钥？" else "删除条目？") },
                text = { Text(if (item.section == VaultSection.Secrets) "“${item.title}”将永久删除，无法恢复。" else "“${item.title}”将进入加密回收站。") },
                confirmButton = { TextButton(onClick = viewModel::confirmOtherDelete) { Text("删除") } },
                dismissButton = { TextButton(onClick = viewModel::cancelOtherDelete) { Text("取消") } },
            )
        }
        state.otherPurgeCandidate?.let { target ->
            AlertDialog(
                onDismissRequest = viewModel::cancelOtherPurge,
                title = { Text("永久删除？") },
                text = { Text("“${target.item.title}”及其历史版本将无法恢复。") },
                confirmButton = { TextButton(onClick = viewModel::confirmOtherPurge) { Text("永久删除") } },
                dismissButton = { TextButton(onClick = viewModel::cancelOtherPurge) { Text("取消") } },
            )
        }
        if (state.confirmOtherEmptyTrash) {
            AlertDialog(
                onDismissRequest = viewModel::cancelOtherEmptyTrash,
                title = { Text("清空回收站？") },
                text = { Text("当前类型的所有回收站条目及其历史版本都将永久删除。") },
                confirmButton = { TextButton(onClick = viewModel::confirmOtherEmptyTrash) { Text("清空") } },
                dismissButton = { TextButton(onClick = viewModel::cancelOtherEmptyTrash) { Text("取消") } },
            )
        }
        state.deleteCandidate?.let { item ->
            AlertDialog(
                onDismissRequest = viewModel::cancelDeleteLogin,
                title = { Text("删除登录项？") },
                text = { Text("“${item.title}”将进入加密回收站。") },
                confirmButton = {
                    TextButton(onClick = viewModel::confirmDeleteLogin) { Text("删除") }
                },
                dismissButton = {
                    TextButton(onClick = viewModel::cancelDeleteLogin) { Text("取消") }
                },
            )
        }
        state.purgeCandidate?.let { item ->
            AlertDialog(
                onDismissRequest = viewModel::cancelPurgeLogin,
                title = { Text("永久删除？") },
                text = { Text("“${item.title}”及其历史版本将无法恢复。") },
                confirmButton = {
                    TextButton(onClick = viewModel::confirmPurgeLogin) { Text("永久删除") }
                },
                dismissButton = {
                    TextButton(onClick = viewModel::cancelPurgeLogin) { Text("取消") }
                },
            )
        }
        if (state.confirmEmptyTrash) {
            AlertDialog(
                onDismissRequest = viewModel::cancelEmptyTrash,
                title = { Text("清空回收站？") },
                text = { Text("所有回收站登录项及其历史版本都将永久删除。") },
                confirmButton = {
                    TextButton(onClick = viewModel::confirmEmptyTrash) { Text("清空") }
                },
                dismissButton = {
                    TextButton(onClick = viewModel::cancelEmptyTrash) { Text("取消") }
                },
            )
        }
    }
}

@Composable
private fun VaultLoadingScreen(phase: VaultLoadingPhase?) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Spacer(Modifier.height(16.dp))
        Text(if (phase == VaultLoadingPhase.Opening) "正在打开保险库…" else "正在加载保险库条目…",
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun LockedVaultScreen(
    state: VaultUiState, viewModel: VaultViewModel, onRestore: () -> Unit,
    biometricEnabled: Boolean, unlockMethod: UnlockMethod, onSelectUnlockMethod: (UnlockMethod) -> Unit,
    pinStatus: PinUiStatus, pinDraft: String, onPinDigit: (String) -> Unit, onPinDelete: () -> Unit,
) {
    if (state.status == "locked" && unlockMethod == UnlockMethod.BiometricPending) return
    val pinActive = state.status == "locked" && unlockMethod == UnlockMethod.Pin &&
        pinStatus.enabled && pinStatus.remainingAttempts > 0
    var showMethodPicker by remember { mutableStateOf(false) }
    val compact = LocalConfiguration.current.screenHeightDp < 800
    Column(
        modifier = Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()
            .padding(horizontal = 24.dp, vertical = if (compact) 12.dp else 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("VaultMesh", style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.weight(if (pinActive) 0.5f else 1f))
        Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primaryContainer) {
            Icon(painterResource(R.drawable.ic_lock), contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(if (compact) 12.dp else 20.dp)
                    .size(if (pinActive) 32.dp else 48.dp))
        }
        Spacer(Modifier.height(if (compact) 12.dp else 24.dp))
        Text(if (state.status == "missing") "创建保险库" else if (pinActive) "输入 PIN" else "解锁保险库",
            style = MaterialTheme.typography.headlineLarge)
        Spacer(Modifier.height(8.dp))
        Text(if (state.status == "missing") "设置主密码以保护你的保险库"
            else if (pinActive) "输入六位数字解锁保险库"
            else "输入主密码，继续访问你的保险库",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(if (compact) 16.dp else if (pinActive) 28.dp else 36.dp))

        if (pinActive) {
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp),
                verticalAlignment = Alignment.CenterVertically) {
                repeat(6) { index ->
                    Box(Modifier.size(16.dp).background(
                        if (index < pinDraft.length) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.primaryContainer, CircleShape))
                }
            }
            Spacer(Modifier.weight(0.5f))
            listOf(listOf("1", "2", "3"), listOf("4", "5", "6"),
                listOf("7", "8", "9"), listOf("", "0", "⌫")).forEach { keys ->
                Row(modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    keys.forEach { key ->
                        Box(Modifier.weight(1f), contentAlignment = Alignment.Center) {
                            if (key.isNotEmpty()) FilledTonalButton(
                                onClick = {
                                    if (key == "⌫") onPinDelete() else onPinDigit(key)
                                },
                                enabled = !state.busy,
                                modifier = Modifier.size(if (compact) 52.dp else 64.dp),
                                contentPadding = PaddingValues(0.dp),
                                shape = CircleShape,
                            ) { Text(key, style = MaterialTheme.typography.headlineSmall) }
                        }
                    }
                }
                Spacer(Modifier.height(if (compact) 8.dp else 12.dp))
            }
            Text("剩余 ${pinStatus.remainingAttempts} 次尝试",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            OutlinedTextField(
                value = state.password,
                onValueChange = viewModel::updatePassword,
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.busy,
                label = { Text(if (state.status == "missing") "设置主密码" else "主密码") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                visualTransformation = PasswordVisualTransformation(),
            )
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = if (state.status == "missing") viewModel::create else viewModel::unlock,
                enabled = state.password.isNotEmpty() && !state.busy,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                colors = ButtonDefaults.buttonColors(
                    disabledContainerColor = if (state.authenticating) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f),
                    disabledContentColor = if (state.authenticating) MaterialTheme.colorScheme.onPrimary
                        else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
                ),
            ) {
                Row(modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically) {
                    if (state.authenticating) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp,
                        )
                        Spacer(Modifier.width(10.dp))
                    }
                    Text(when {
                        state.authenticating && state.status == "missing" -> "正在创建…"
                        state.authenticating -> "正在解锁…"
                        state.status == "missing" -> "创建保险库"
                        else -> "解锁"
                    })
                }
            }
        }
        state.error?.let {
            Spacer(Modifier.height(12.dp))
            Text(errorLabel(it), color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.weight(1f))
        if (state.status == "locked" && (biometricEnabled || pinStatus.enabled)) {
            TextButton(onClick = { showMethodPicker = true }, enabled = !state.busy) {
                Text("其他解锁方式")
            }
        }
        if (!pinActive) TextButton(onClick = onRestore, enabled = !state.busy) {
            Text("从加密备份恢复")
        }
    }
    if (showMethodPicker) {
        AlertDialog(
            onDismissRequest = { showMethodPicker = false },
            title = { Text("选择解锁方式") },
            text = {
                Column {
                    if (unlockMethod != UnlockMethod.MasterPassword) {
                        TextButton(onClick = {
                            showMethodPicker = false
                            onSelectUnlockMethod(UnlockMethod.MasterPassword)
                        }) { Text("主密码") }
                    }
                    if (pinStatus.enabled && pinStatus.remainingAttempts > 0 && unlockMethod != UnlockMethod.Pin) {
                        TextButton(onClick = {
                            showMethodPicker = false
                            onSelectUnlockMethod(UnlockMethod.Pin)
                        }) { Text("六位 PIN") }
                    }
                    if (biometricEnabled) {
                        TextButton(onClick = {
                            showMethodPicker = false
                            onSelectUnlockMethod(UnlockMethod.BiometricPending)
                        }) { Text("生物识别") }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { showMethodPicker = false }) { Text("取消") } },
        )
    }
}

@Composable
private fun RestoreBackupDialog(password: String, busy: Boolean, error: String?, viewModel: VaultViewModel) {
    AlertDialog(
        onDismissRequest = viewModel::cancelRestore,
        title = { Text("替换本机保险库？") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("恢复将替换本机 Vault。请先确认已有数据已备份；恢复后局域网设备需要重新授权。")
                OutlinedTextField(
                    value = password,
                    onValueChange = viewModel::updateRestorePassword,
                    label = { Text("备份的主密码") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    visualTransformation = PasswordVisualTransformation(),
                )
                error?.let { Text(errorLabel(it), color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = { TextButton(onClick = viewModel::submitRestore,
            enabled = !busy && password.isNotEmpty()) { Text("确认替换") } },
        dismissButton = { TextButton(onClick = viewModel::cancelRestore, enabled = !busy) { Text("取消") } },
    )
}

@Composable
private fun PasswordHealthDialog(panel: HealthPanel, logins: List<LoginSummary>, viewModel: VaultViewModel) {
    AlertDialog(
        onDismissRequest = viewModel::closePasswordHealth,
        title = { Text("密码健康") },
        text = {
            if (panel.loading) CircularProgressIndicator()
            else panel.report?.let { report ->
                LazyColumn(modifier = Modifier.heightIn(max = 400.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    item { Text("健康分数：${report.score}%", style = MaterialTheme.typography.titleMedium) }
                    listOf("弱密码" to report.weakItemIds,
                        "重复使用" to report.reusedItemIds,
                        "长期未更换" to report.oldItemIds).forEach { (label, ids) ->
                        item { Text("$label：${ids.size} 项") }
                        items(logins.filter { it.id in ids }, key = { "$label-${it.id}" }) { entry ->
                            Text("• ${entry.title}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = viewModel::closePasswordHealth) { Text("关闭") } },
    )
}

@Composable
private fun GeneratorDialog(draft: GeneratorDraft, canApply: Boolean, viewModel: VaultViewModel) {
    AlertDialog(
        onDismissRequest = viewModel::closeGenerator,
        title = { Text("生成凭据") },
        text = {
            Column(modifier = Modifier.heightIn(max = 460.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(modifier = Modifier.horizontalScroll(rememberScrollState())) {
                    GeneratorKind.entries.forEach { kind ->
                        TextButton(onClick = { viewModel.updateGenerator { it.copy(kind = kind) } }) {
                            Text((if (draft.kind == kind) "• " else "") + when (kind) {
                                GeneratorKind.Password -> "密码"
                                GeneratorKind.Username -> "用户名"
                                GeneratorKind.EmailAlias -> "邮箱别名"
                            })
                        }
                    }
                }
                OutlinedTextField(value = draft.length,
                    onValueChange = { value -> viewModel.updateGenerator { it.copy(length = value) } },
                    label = { Text("长度") }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true)
                if (draft.kind == GeneratorKind.Password) {
                    listOf("小写字母" to draft.lowercase, "大写字母" to draft.uppercase,
                        "数字" to draft.digits, "符号" to draft.symbols).forEachIndexed { index, (label, checked) ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = checked, onCheckedChange = { value ->
                                viewModel.updateGenerator { current -> when (index) {
                                    0 -> current.copy(lowercase = value)
                                    1 -> current.copy(uppercase = value)
                                    2 -> current.copy(digits = value)
                                    else -> current.copy(symbols = value)
                                } }
                            })
                            Text(label)
                        }
                    }
                }
                if (draft.kind == GeneratorKind.EmailAlias) {
                    OutlinedTextField(value = draft.domain,
                        onValueChange = { value -> viewModel.updateGenerator { it.copy(domain = value) } },
                        label = { Text("邮箱域名") }, singleLine = true)
                }
                draft.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (draft.result.isNotEmpty()) {
                    Text(draft.result, style = MaterialTheme.typography.titleMedium)
                    Row(modifier = Modifier.horizontalScroll(rememberScrollState())) {
                        TextButton(onClick = viewModel::copyGeneratedCredential) { Text("复制") }
                        if (canApply) TextButton(onClick = viewModel::applyGeneratedCredential) { Text("填入登录项") }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = viewModel::generateCredential) { Text("生成") } },
        dismissButton = { TextButton(onClick = viewModel::closeGenerator) { Text("关闭") } },
    )
}

@Composable
private fun PasswordRotationDialog(
    draft: PasswordRotationDraft,
    busy: Boolean,
    viewModel: VaultViewModel,
) {
    val matching = draft.newPassword == draft.confirmPassword
    val canSubmit = !busy && draft.currentPassword.isNotEmpty() &&
        draft.newPassword.isNotEmpty() && matching
    AlertDialog(
        onDismissRequest = viewModel::cancelPasswordRotation,
        title = { Text("修改主密码") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = draft.currentPassword,
                    onValueChange = { value -> viewModel.updatePasswordRotation { it.copy(currentPassword = value) } },
                    label = { Text("当前主密码") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    visualTransformation = PasswordVisualTransformation(),
                )
                OutlinedTextField(
                    value = draft.newPassword,
                    onValueChange = { value -> viewModel.updatePasswordRotation { it.copy(newPassword = value) } },
                    label = { Text("新主密码") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    visualTransformation = PasswordVisualTransformation(),
                )
                OutlinedTextField(
                    value = draft.confirmPassword,
                    onValueChange = { value -> viewModel.updatePasswordRotation { it.copy(confirmPassword = value) } },
                    label = { Text("再次输入新主密码") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    visualTransformation = PasswordVisualTransformation(),
                )
                if (draft.confirmPassword.isNotEmpty() && !matching) {
                    Text("两次输入的新主密码不一致", color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = viewModel::submitPasswordRotation, enabled = canSubmit) {
                Text("确认修改")
            }
        },
        dismissButton = {
            TextButton(onClick = viewModel::cancelPasswordRotation, enabled = !busy) {
                Text("取消")
            }
        },
    )
}

@Composable
private fun ProtectedCopyDialog(
    draft: ProtectedCopyDraft,
    busy: Boolean,
    viewModel: VaultViewModel,
) {
    AlertDialog(
        onDismissRequest = viewModel::cancelProtectedCopy,
        title = { Text("复制${draft.target.field.label}") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("“${draft.target.title}”需要重新验证主密码。")
                OutlinedTextField(
                    value = draft.masterPassword,
                    onValueChange = viewModel::updateProtectedCopyPassword,
                    label = { Text("当前主密码") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    visualTransformation = PasswordVisualTransformation(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = viewModel::submitProtectedCopy,
                enabled = !busy && draft.masterPassword.isNotEmpty()) { Text("复制") }
        },
        dismissButton = {
            TextButton(onClick = viewModel::cancelProtectedCopy, enabled = !busy) { Text("取消") }
        },
    )
}

@Composable
private fun ProtectedRevealDialog(
    draft: ProtectedRevealDraft,
    busy: Boolean,
    viewModel: VaultViewModel,
) {
    AlertDialog(
        onDismissRequest = viewModel::closeProtectedReveal,
        title = { Text("查看${draft.target.field.label} · ${draft.target.title}") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (draft.value == null) {
                    Text("每次查看都需要重新输入主密码。")
                    OutlinedTextField(
                        value = draft.masterPassword,
                        onValueChange = viewModel::updateProtectedRevealPassword,
                        label = { Text("主密码") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                    )
                } else {
                    Text("30 秒后自动关闭")
                    LazyColumn(modifier = Modifier.heightIn(max = 400.dp)) {
                        items(draft.value.chunked(4096)) { chunk -> Text(chunk) }
                    }
                }
                draft.error?.let { Text(errorLabel(it), color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            if (draft.value == null) {
                TextButton(onClick = viewModel::submitProtectedReveal,
                    enabled = !busy && draft.masterPassword.isNotEmpty()) { Text("查看") }
            }
        },
        dismissButton = {
            TextButton(onClick = viewModel::closeProtectedReveal, enabled = !busy) { Text("关闭") }
        },
    )
}

@Composable
private fun HistoryDialog(panel: HistoryPanel, viewModel: VaultViewModel) {
    AlertDialog(
        onDismissRequest = viewModel::closeHistory,
        title = { Text("${panel.target.title} · 历史") },
        text = {
            if (panel.loading) {
                CircularProgressIndicator()
            } else if (panel.entries.isEmpty()) {
                Text("还没有历史版本。")
            } else {
                LazyColumn(modifier = Modifier.heightIn(max = 400.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(panel.entries, key = HistorySummary::revisionId) { entry ->
                        Column {
                            Text(entry.title, style = MaterialTheme.typography.titleSmall)
                            entry.subtitle?.takeIf(String::isNotBlank)?.let { Text(it) }
                            Text(DateFormat.getDateTimeInstance().format(Date(
                                entry.savedAt.coerceIn(0, 253402300799L) * 1000,
                            )), style = MaterialTheme.typography.bodySmall)
                            TextButton(onClick = { viewModel.requestRestoreRevision(entry) }) { Text("恢复此版本") }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = viewModel::requestClearHistory,
                enabled = !panel.loading && panel.entries.isNotEmpty()) { Text("清空历史") }
        },
        dismissButton = { TextButton(onClick = viewModel::closeHistory) { Text("关闭") } },
    )
}

@Composable
private fun TotpDialog(draft: TotpDraft, busy: Boolean, viewModel: VaultViewModel) {
    AlertDialog(
        onDismissRequest = viewModel::cancelTotp,
        title = { Text("${draft.title} · TOTP") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("输入 Base32 密钥或 otpauth://totp 链接。已有密钥不会显示。")
                if (!draft.clear) {
                    OutlinedTextField(
                        value = draft.secret,
                        onValueChange = viewModel::updateTotpSecret,
                        label = { Text(if (draft.hasExisting) "新密钥（将替换原密钥）" else "TOTP 密钥") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                    )
                }
                if (draft.hasExisting) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = draft.clear, onCheckedChange = { viewModel.toggleTotpRemoval() })
                        Text("移除现有 TOTP 密钥")
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = viewModel::submitTotp,
                enabled = !busy && (draft.clear || draft.secret.isNotBlank())) {
                Text(if (draft.clear) "确认移除" else if (draft.hasExisting) "替换密钥" else "保存密钥")
            }
        },
        dismissButton = { TextButton(onClick = viewModel::cancelTotp, enabled = !busy) { Text("取消") } },
    )
}

@Composable
private fun RecoveryDialog(
    draft: RecoveryDraft,
    busy: Boolean,
    viewModel: VaultViewModel,
    onRecoveryFile: (String) -> Unit,
    onRecoverySaved: (String, ByteArray?) -> Unit,
    onClose: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("${draft.title} · 2FA 恢复码") },
        text = {
            Column(
                modifier = Modifier.heightIn(max = 460.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("每行一个恢复码。保存会替换已有恢复码；普通列表只显示是否存在。")
                TextButton(onClick = { onRecoveryFile(draft.id) }, enabled = !busy) {
                    Text("从 UTF-8 文本文件导入…")
                }
                if (!draft.clear) {
                    OutlinedTextField(
                        value = draft.input,
                        onValueChange = viewModel::updateRecoveryInput,
                        label = { Text(if (draft.hasExisting) "新恢复码（将替换）" else "恢复码") },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 3,
                        maxLines = 5,
                        visualTransformation = PasswordVisualTransformation(),
                    )
                }
                if (draft.hasExisting) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = draft.clear, onCheckedChange = { viewModel.toggleRecoveryClear() })
                        Text("清除现有恢复码")
                    }
                    OutlinedTextField(
                        value = draft.viewPassword,
                        onValueChange = viewModel::updateRecoveryViewPassword,
                        label = { Text("主密码（每次查看）") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                    )
                    TextButton(onClick = viewModel::submitRecoveryView,
                        enabled = !busy && draft.viewPassword.isNotEmpty()) { Text("查看恢复码") }
                }
                draft.codes.forEachIndexed { index, code ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("${index + 1}. $code", modifier = Modifier.weight(1f))
                        TextButton(onClick = { viewModel.requestRecoveryCopy(index) }, enabled = !busy) {
                            Text("复制")
                        }
                    }
                }
                if (draft.copyIndex != null) {
                    OutlinedTextField(
                        value = draft.copyPassword,
                        onValueChange = viewModel::updateRecoveryCopyPassword,
                        label = { Text("主密码（复制第 ${draft.copyIndex + 1} 个）") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                    )
                    Row {
                        TextButton(onClick = viewModel::submitRecoveryCopy,
                            enabled = !busy && draft.copyPassword.isNotEmpty()) { Text("确认复制") }
                        TextButton(onClick = viewModel::cancelRecoveryCopy, enabled = !busy) { Text("取消复制") }
                    }
                }
                draft.error?.let { Text(errorLabel(it), color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(onClick = { viewModel.submitRecoverySet(onRecoverySaved) },
                enabled = !busy && (draft.clear || draft.input.isNotBlank())) {
                Text(if (draft.clear) "确认清除" else if (draft.hasExisting) "替换恢复码" else "保存恢复码")
            }
        },
        dismissButton = { TextButton(onClick = onClose, enabled = !busy) { Text("关闭") } },
    )
}

@Composable
internal fun TrashRow(item: TrashSummary, viewModel: VaultViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(item.title, style = MaterialTheme.typography.titleMedium)
            if (item.username.isNotEmpty()) Text(item.username)
            Row(modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.End) {
                TextButton(onClick = { viewModel.restoreLogin(item) }) { Text("恢复") }
                TextButton(onClick = { viewModel.requestPurgeLogin(item) }) { Text("永久删除") }
            }
        }
    }
}

@Composable
internal fun LoginRow(item: LoginSummary, viewModel: VaultViewModel,
    selected: Boolean = false, onToggle: (() -> Unit)? = null) {
    val copy = buildList {
        if (item.username.isNotBlank()) add(VaultRowAction("用户名") {
            viewModel.copySummaryText(VaultSection.Logins, item.id, item.username)
        })
        if (item.hasPassword) add(VaultRowAction("密码") {
            viewModel.requestProtectedCopy(ProtectedCopyTarget(item.id, item.title,
                ProtectedCopyField.LoginPassword))
        })
        if (item.hasTotpSecret) add(VaultRowAction("验证码") {
            viewModel.requestProtectedCopy(ProtectedCopyTarget(item.id, item.title,
                ProtectedCopyField.LoginTotpCode))
        })
    }
    val more = buildList {
        add(VaultRowAction("编辑") { viewModel.beginEditLogin(item) })
        if (item.hasPassword) add(VaultRowAction("查看密码") {
            viewModel.requestProtectedReveal(ProtectedCopyTarget(item.id, item.title,
                ProtectedCopyField.LoginPassword))
        })
        add(VaultRowAction(if (item.hasTotpSecret) "管理 TOTP" else "设置 TOTP") {
            viewModel.beginTotp(item)
        })
        add(VaultRowAction(if (item.hasRecoveryCodes) "管理恢复码" else "添加恢复码") {
            viewModel.beginRecovery(item)
        })
        add(VaultRowAction("历史") {
            viewModel.requestHistory(HistoryTarget(VaultSection.Logins, item.id, item.title))
        })
        add(VaultRowAction("删除") { viewModel.requestDeleteLogin(item) })
    }
    VaultEntryRow(VaultSection.Logins, item.title, item.username.ifBlank { item.url.orEmpty() },
        selected, onToggle, { viewModel.beginEditLogin(item) }, copy, more)
}

@Composable
private fun LoginEditorDialog(draft: LoginDraft, busy: Boolean, viewModel: VaultViewModel) {
    AlertDialog(
        onDismissRequest = viewModel::cancelLoginEditor,
        title = { Text(if (draft.id == null) "新增登录项" else "编辑登录项") },
        text = {
            Column(modifier = Modifier.heightIn(max = 500.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = draft.title,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(title = value) } },
                    label = { Text("标题") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = draft.username,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(username = value) } },
                    label = { Text("用户名") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = draft.password,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(password = value) } },
                    label = { Text(if (draft.id == null) "密码" else "新密码（留空则保留）") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    visualTransformation = PasswordVisualTransformation(),
                )
                TextButton(onClick = viewModel::beginGenerator, enabled = !busy) { Text("生成凭据…") }
                OutlinedTextField(
                    value = draft.url,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(url = value) } },
                    label = { Text("网址") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                )
                Text("附加网址", style = MaterialTheme.typography.titleSmall)
                draft.additionalUrls.forEachIndexed { index, url ->
                    OutlinedTextField(
                        value = url,
                        onValueChange = { value -> viewModel.updateLoginDraft { current ->
                            current.copy(additionalUrls = current.additionalUrls.mapIndexed { i, old -> if (i == index) value else old })
                        } },
                        label = { Text("附加网址 ${index + 1}") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    )
                    TextButton(onClick = { viewModel.updateLoginDraft { current ->
                        current.copy(additionalUrls = current.additionalUrls.filterIndexed { i, _ -> i != index })
                    } }) { Text("移除网址") }
                }
                if (draft.additionalUrls.size < 20) TextButton(onClick = { viewModel.updateLoginDraft {
                    it.copy(additionalUrls = it.additionalUrls + "")
                } }) { Text("添加网址") }
                OutlinedTextField(
                    value = draft.notes,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(notes = value) } },
                    label = { Text("备注") },
                    minLines = 3,
                )
                OutlinedTextField(
                    value = draft.folder,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(folder = value) } },
                    label = { Text("文件夹") },
                    singleLine = true,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = draft.favorite, onCheckedChange = { checked ->
                        viewModel.updateLoginDraft { it.copy(favorite = checked) }
                    })
                    Text("收藏")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = draft.autofillOnPageLoad, onCheckedChange = { checked ->
                        viewModel.updateLoginDraft { it.copy(autofillOnPageLoad = checked) }
                    })
                    Text("页面加载时自动填充")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = draft.masterPasswordReprompt, onCheckedChange = { checked ->
                        viewModel.updateLoginDraft { it.copy(masterPasswordReprompt = checked) }
                    })
                    Text("使用时要求主密码")
                }
                Text("自定义字段", style = MaterialTheme.typography.titleSmall)
                draft.customFields.forEachIndexed { index, field ->
                    OutlinedTextField(
                        value = field.label,
                        onValueChange = { value -> viewModel.updateLoginDraft { current ->
                            current.copy(customFields = current.customFields.mapIndexed { i, old -> if (i == index) old.copy(label = value) else old })
                        } },
                        label = { Text("字段 ${index + 1} 名称") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = field.value,
                        onValueChange = { value -> viewModel.updateLoginDraft { current ->
                            current.copy(customFields = current.customFields.mapIndexed { i, old -> if (i == index) old.copy(value = value) else old })
                        } },
                        label = { Text("字段 ${index + 1} 值") },
                    )
                    TextButton(onClick = { viewModel.updateLoginDraft { current ->
                        current.copy(customFields = current.customFields.filterIndexed { i, _ -> i != index })
                    } }) { Text("移除字段") }
                }
                if (draft.customFields.size < 50) TextButton(onClick = { viewModel.updateLoginDraft {
                    it.copy(customFields = it.customFields + LoginCustomFieldDraft())
                } }) { Text("添加自定义字段") }
            }
        },
        confirmButton = {
            TextButton(
                onClick = viewModel::saveLogin,
                enabled = draft.title.isNotBlank() && (draft.id != null || draft.password.isNotEmpty()) &&
                    draft.additionalUrls.all { it.isNotBlank() } &&
                    draft.customFields.all { it.label.isNotBlank() } && !busy,
            ) { Text("保存") }
        },
        dismissButton = {
            TextButton(onClick = viewModel::cancelLoginEditor, enabled = !busy) { Text("取消") }
        },
    )
}

private fun statusLabel(status: String): String = when (status) {
    "missing" -> "尚未创建本地保险库"
    "locked" -> "保险库已锁定"
    "unlocked" -> "保险库已解锁"
    else -> "保险库不可用"
}

internal fun errorLabel(code: String): String = when (code) {
    "already_exists" -> "本地保险库已存在"
    "unlock_failed" -> "主密码错误或保险库已被修改"
    "pin_failed" -> "PIN 不正确，请检查后重试"
    "pin_locked" -> "PIN 已锁定，请使用主密码解锁"
    "invalid_vault" -> "保险库格式无效或暂不支持"
    "invalid_input" -> "请输入有效的条目字段"
    "biometric_unavailable" -> "生物识别不可用，请使用其他解锁方式"
    "pin_unavailable" -> "PIN 设备凭据不可用，请使用主密码"
    "item_not_found" -> "条目已不存在"
    "value_unavailable" -> "该字段没有可复制的值"
    "trash_item_not_found" -> "回收站条目已不存在"
    "revision_not_found" -> "历史版本已不存在"
    "locked" -> "保险库已锁定"
    "missing" -> "找不到本地保险库"
    else -> "操作失败"
}
