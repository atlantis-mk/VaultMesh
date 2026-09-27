package com.vaultmesh.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.security.MessageDigest

data class VaultUiState(
    val status: String = "missing",
    val password: String = "",
    val busy: Boolean = true,
    val authenticating: Boolean = false,
    val loadingPhase: VaultLoadingPhase? = null,
    val error: String? = null,
    val logins: List<LoginSummary> = emptyList(),
    val trash: List<TrashSummary> = emptyList(),
    val cards: List<CardSummary> = emptyList(),
    val ssh: List<SshSummary> = emptyList(),
    val identities: List<IdentitySummary> = emptyList(),
    val secrets: List<SecretSummary> = emptyList(),
    val otherTrash: Map<VaultSection, List<OtherTrashSummary>> = emptyMap(),
    val section: VaultSection = VaultSection.Logins,
    val trashType: VaultSection = VaultSection.Logins,
    val query: String = "",
    val editor: LoginDraft? = null,
    val otherDraft: OtherDraft? = null,
    val deleteCandidate: LoginSummary? = null,
    val otherDeleteCandidate: OtherTarget? = null,
    val purgeCandidate: TrashSummary? = null,
    val otherPurgeCandidate: OtherTrashTarget? = null,
    val confirmEmptyTrash: Boolean = false,
    val confirmOtherEmptyTrash: Boolean = false,
    val passwordRotation: PasswordRotationDraft? = null,
    val protectedCopy: ProtectedCopyDraft? = null,
    val protectedReveal: ProtectedRevealDraft? = null,
    val history: HistoryPanel? = null,
    val restoreRevisionCandidate: HistorySummary? = null,
    val confirmClearHistory: Boolean = false,
    val totp: TotpDraft? = null,
    val restorePassword: String? = null,
    val health: HealthPanel? = null,
    val generator: GeneratorDraft? = null,
    val recovery: RecoveryDraft? = null,
    val batchDeleteNotice: String? = null,
)

enum class VaultSection { Logins, Cards, Ssh, Identities, Secrets, Trash }
enum class VaultLoadingPhase { Opening, Summaries }

data class LoginCustomFieldDraft(val label: String = "", val value: String = "")

data class LoginDraft(
    val id: String? = null,
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val notes: String = "",
    val folder: String = "",
    val favorite: Boolean = false,
    val additionalUrls: List<String> = emptyList(),
    val autofillOnPageLoad: Boolean = true,
    val masterPasswordReprompt: Boolean = false,
    val customFields: List<LoginCustomFieldDraft> = emptyList(),
)

data class PasswordRotationDraft(
    val currentPassword: String = "",
    val newPassword: String = "",
    val confirmPassword: String = "",
)

data class ProtectedRevealDraft(
    val requestId: Long,
    val target: ProtectedCopyTarget,
    val masterPassword: String = "",
    val value: String? = null,
    val error: String? = null,
)

data class HistoryTarget(val section: VaultSection, val id: String, val title: String)
data class HistoryPanel(
    val target: HistoryTarget,
    val entries: List<HistorySummary> = emptyList(),
    val loading: Boolean = true,
)

data class TotpDraft(
    val id: String,
    val title: String,
    val hasExisting: Boolean,
    val secret: String = "",
    val clear: Boolean = false,
)

data class RecoveryDraft(
    val id: String,
    val title: String,
    val hasExisting: Boolean,
    val imported: Boolean = false,
    val input: String = "",
    val clear: Boolean = false,
    val viewPassword: String = "",
    val codes: List<String> = emptyList(),
    val copyIndex: Int? = null,
    val copyPassword: String = "",
    val error: String? = null,
)

data class HealthPanel(
    val requestId: Long,
    val report: PasswordHealth? = null,
    val loading: Boolean = true,
)

enum class GeneratorKind { Password, Username, EmailAlias }
data class GeneratorDraft(
    val kind: GeneratorKind = GeneratorKind.Password,
    val length: String = "20",
    val lowercase: Boolean = true,
    val uppercase: Boolean = true,
    val digits: Boolean = true,
    val symbols: Boolean = true,
    val domain: String = "",
    val result: String = "",
    val error: String? = null,
)

class VaultViewModel(application: Application) : AndroidViewModel(application) {
    private val mutableState = MutableStateFlow(VaultUiState())
    val state: StateFlow<VaultUiState> = mutableState.asStateFlow()
    private val nativeCallGate = Any()
    private val protectedClipboard = ProtectedClipboardService.get(application)
    private val backupDocuments = BackupDocumentService(application)
    @Volatile
    private var lifecycleGeneration = 0L
    private var refreshToken = 0L
    private var pendingOperations = 0
    private var healthRequestId = 0L
    private var recoveryImportGeneration = 0L
    private var revealRequestId = 0L
    private var editorRequestGeneration = 0L

    fun refresh() {
        val generation = lifecycleGeneration
        val token = ++refreshToken
        if (pendingOperations == 0) {
            mutableState.update { it.copy(busy = true) }
        }
        viewModelScope.launch {
            val refreshed = withContext(Dispatchers.IO) { readVaultState() }
            if (generation != lifecycleGeneration || token != refreshToken || pendingOperations != 0) {
                return@launch
            }
            mutableState.update {
                it.copy(
                    status = refreshed.status,
                    logins = refreshed.logins,
                    trash = refreshed.trash,
                    cards = refreshed.cards,
                    ssh = refreshed.ssh,
                    identities = refreshed.identities,
                    secrets = refreshed.secrets,
                    otherTrash = refreshed.otherTrash,
                    busy = false,
                    loadingPhase = null,
                    error = refreshed.error,
                )
            }
        }
    }

    fun updatePassword(value: String) {
        mutableState.update { it.copy(password = value, error = null) }
    }

    fun create() = submit(VaultNativeBridge::create)

    fun unlock() = submit(VaultNativeBridge::unlock)

    fun beginOpeningVault() {
        if (mutableState.value.status == "locked" && !mutableState.value.busy) {
            mutableState.update { it.copy(loadingPhase = VaultLoadingPhase.Opening, error = null) }
        }
    }

    fun prepareBiometricUnlock(onReady: (String?) -> Unit) {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy) return
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation, VaultNativeBridge::prepareBiometricUnlock)
                }
                if (generation != lifecycleGeneration) return@launch
                val token = result.removePrefix("value:").takeIf { result.startsWith("value:") }
                if (token == null) mutableState.update { it.copy(error = result) }
                onReady(token)
            } finally {
                endOperation()
            }
        }
    }

    fun unlockWithBiometricSecret(encoded: String, onFinished: (Boolean) -> Unit) {
        if (mutableState.value.status != "locked" || mutableState.value.busy) return
        var secret = encoded
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(password = "", busy = true,
            loadingPhase = VaultLoadingPhase.Opening, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { VaultNativeBridge.unlockWithBiometricSecret(secret) }
                }
                secret = ""
                finishMutation(result, generation)
                if (generation == lifecycleGeneration) {
                    onFinished(result == "ok" && mutableState.value.status == "unlocked")
                }
            } finally {
                secret = ""
                endOperation()
            }
        }
    }

    fun disableBiometricUnlock(onFinished: (Boolean) -> Unit = {}) {
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(busy = true) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation, VaultNativeBridge::disableBiometricUnlock)
                }
                if (generation == lifecycleGeneration) {
                    mutableState.update { it.copy(error = result.takeUnless { code -> code == "ok" }) }
                    onFinished(result == "ok")
                }
            } finally {
                endOperation()
            }
        }
    }

    fun reportBiometricFailure() {
        mutableState.update { it.copy(loadingPhase = null, error = "biometric_unavailable") }
    }

    fun reportPinFailure() {
        mutableState.update { it.copy(loadingPhase = null, error = "pin_unavailable") }
    }

    fun enablePinUnlock(pin: String, deviceSecret: String, onFinished: (Boolean) -> Unit) {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy) return
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { VaultNativeBridge.enablePinUnlock(pin, deviceSecret) }
                }
                if (generation != lifecycleGeneration) {
                    withContext(Dispatchers.IO) {
                        synchronized(nativeCallGate) { VaultNativeBridge.disablePinUnlock() }
                    }
                } else {
                    mutableState.update { it.copy(error = result.takeUnless { code -> code == "ok" }) }
                    onFinished(result == "ok")
                }
            } finally {
                endOperation()
            }
        }
    }

    fun unlockWithPin(pin: String, deviceSecret: String, onFinished: () -> Unit) {
        if (mutableState.value.status != "locked" || mutableState.value.busy) return
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(password = "", busy = true,
            loadingPhase = VaultLoadingPhase.Opening, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { VaultNativeBridge.unlockWithPin(pin, deviceSecret) }
                }
                finishMutation(result, generation)
                if (generation == lifecycleGeneration) onFinished()
            } finally {
                endOperation()
            }
        }
    }

    fun disablePinUnlock(onFinished: (Boolean) -> Unit = {}) {
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation, VaultNativeBridge::disablePinUnlock)
                }
                if (generation == lifecycleGeneration) {
                    mutableState.update { it.copy(error = result.takeUnless { code -> code == "ok" }) }
                    onFinished(result == "ok")
                }
            } finally {
                endOperation()
            }
        }
    }

    fun beginPasswordRotation() {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy) return
        mutableState.update { it.copy(passwordRotation = PasswordRotationDraft(), error = null) }
    }

    fun updatePasswordRotation(transform: (PasswordRotationDraft) -> PasswordRotationDraft) {
        mutableState.update { state ->
            state.copy(passwordRotation = state.passwordRotation?.let(transform), error = null)
        }
    }

    fun cancelPasswordRotation() {
        mutableState.update { it.copy(passwordRotation = null) }
    }

    fun submitPasswordRotation() {
        val draft = mutableState.value.passwordRotation ?: return
        if (mutableState.value.status != "unlocked" || mutableState.value.busy ||
            draft.currentPassword.isEmpty() || draft.newPassword.isEmpty() ||
            draft.newPassword != draft.confirmPassword
        ) return
        var current = draft.currentPassword
        var next = draft.newPassword
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(passwordRotation = null, busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) {
                        VaultNativeBridge.changeMasterPassword(current, next)
                    }
                }
                current = ""
                next = ""
                finishMutation(result, generation)
            } finally {
                current = ""
                next = ""
                endOperation()
            }
        }
    }

    fun requestProtectedCopy(target: ProtectedCopyTarget) {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy) return
        mutableState.update { it.copy(protectedCopy = ProtectedCopyDraft(target), error = null) }
    }

    fun copySummaryText(section: VaultSection, id: String, value: String) {
        val current = mutableState.value
        if (current.status != "unlocked" || current.busy || value.isBlank()) return
        val stillPresent = when (section) {
            VaultSection.Logins -> current.logins.any { it.id == id && it.username == value }
            VaultSection.Cards -> current.cards.any { it.id == id && it.cardholderName == value }
            VaultSection.Ssh -> current.ssh.any { it.id == id && it.username == value }
            VaultSection.Identities -> current.identities.any { it.id == id && it.displayName == value }
            VaultSection.Secrets -> current.secrets.any { it.id == id && it.account == value }
            VaultSection.Trash -> false
        }
        if (stillPresent) {
            val result = protectedClipboard.writeText(value)
            if (result != "ok") mutableState.update { it.copy(error = result) }
        }
    }

    fun deleteSelectedItems(targets: List<VaultSelection>) {
        val current = mutableState.value
        if (current.status != "unlocked" || current.busy || targets.isEmpty() ||
            targets.distinct().size != targets.size) return
        val valid = targets.all { target -> when (target.section) {
            VaultSection.Logins -> current.logins.any { it.id == target.id }
            VaultSection.Cards -> current.cards.any { it.id == target.id }
            VaultSection.Ssh -> current.ssh.any { it.id == target.id && !it.managed }
            VaultSection.Identities -> current.identities.any { it.id == target.id }
            VaultSection.Secrets -> current.secrets.any { it.id == target.id }
            VaultSection.Trash -> false
        } }
        if (!valid) return
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null, batchDeleteNotice = null) }
        viewModelScope.launch {
            try {
                var completed = 0
                val result = withContext(Dispatchers.IO) {
                    var failure = "ok"
                    for (target in targets) {
                        failure = runCurrentOperation(generation) {
                            when (target.section) {
                                VaultSection.Logins -> VaultNativeBridge.deleteLogin(target.id)
                                VaultSection.Cards -> VaultNativeBridge.deleteCard(target.id)
                                VaultSection.Ssh -> VaultNativeBridge.deleteSsh(target.id)
                                VaultSection.Identities -> VaultNativeBridge.deleteIdentity(target.id)
                                VaultSection.Secrets -> VaultNativeBridge.deleteSecret(target.id)
                                VaultSection.Trash -> "invalid_input"
                            }
                        }
                        if (failure != "ok") break
                        completed += 1
                    }
                    failure
                }
                finishMutation(result, generation)
                if (generation == lifecycleGeneration) mutableState.update {
                    it.copy(batchDeleteNotice = when {
                        result == "ok" -> "已删除 $completed 项"
                        completed > 0 -> "已删除 $completed 项，其余未处理，请检查列表"
                        else -> null
                    })
                }
            } finally {
                endOperation()
            }
        }
    }

    fun updateProtectedCopyPassword(value: String) {
        mutableState.update { state ->
            state.copy(protectedCopy = state.protectedCopy?.copy(masterPassword = value), error = null)
        }
    }

    fun cancelProtectedCopy() {
        mutableState.update { it.copy(protectedCopy = null) }
    }

    fun submitProtectedCopy() {
        val draft = mutableState.value.protectedCopy ?: return
        if (mutableState.value.status != "unlocked" || mutableState.value.busy ||
            draft.masterPassword.isEmpty()
        ) return
        var password = draft.masterPassword
        val target = draft.target
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(protectedCopy = null, busy = true, error = null) }
        viewModelScope.launch {
            try {
                var response = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { protectedClipboard.readValue(target, password) }
                }
                password = ""
                if (generation != lifecycleGeneration) {
                    response = ""
                    return@launch
                }
                val result = protectedClipboard.writeResponse(response)
                response = ""
                mutableState.update { it.copy(busy = false, error = result.takeUnless { code -> code == "ok" }) }
            } finally {
                password = ""
                endOperation()
            }
        }
    }

    fun requestProtectedReveal(target: ProtectedCopyTarget) {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy ||
            target.field == ProtectedCopyField.LoginTotpCode) return
        val requestId = ++revealRequestId
        mutableState.update { it.copy(protectedReveal = ProtectedRevealDraft(requestId, target), error = null) }
    }

    fun updateProtectedRevealPassword(value: String) {
        mutableState.update { it.copy(protectedReveal = it.protectedReveal?.copy(masterPassword = value, error = null)) }
    }

    fun closeProtectedReveal() {
        revealRequestId += 1
        mutableState.update { it.copy(protectedReveal = null) }
    }

    fun submitProtectedReveal() {
        val draft = mutableState.value.protectedReveal ?: return
        if (mutableState.value.status != "unlocked" || mutableState.value.busy ||
            draft.masterPassword.isEmpty() || draft.value != null) return
        var password = draft.masterPassword
        val requestId = draft.requestId
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(protectedReveal = draft.copy(masterPassword = ""), busy = true) }
        viewModelScope.launch {
            try {
                var response = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { protectedClipboard.readValue(draft.target, password) }
                }
                password = ""
                if (generation != lifecycleGeneration ||
                    mutableState.value.protectedReveal?.requestId != requestId) {
                    response = ""
                    return@launch
                }
                val value = response.takeIf { it.startsWith("value:") }?.substring(6)
                val error = if (value == null) response else null
                response = ""
                mutableState.update { it.copy(protectedReveal = it.protectedReveal?.copy(value = value, error = error)) }
                if (value != null) {
                    viewModelScope.launch {
                        delay(30_000)
                        if (generation == lifecycleGeneration &&
                            mutableState.value.protectedReveal?.requestId == requestId) {
                            closeProtectedReveal()
                        }
                    }
                }
            } finally {
                password = ""
                endOperation()
            }
        }
    }

    fun beginTotp(item: LoginSummary) {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy) return
        mutableState.update { it.copy(totp = TotpDraft(item.id, item.title, item.hasTotpSecret), error = null) }
    }

    fun updateTotpSecret(value: String) {
        mutableState.update { state -> state.copy(totp = state.totp?.copy(secret = value, clear = false), error = null) }
    }

    fun toggleTotpRemoval() {
        mutableState.update { state ->
            state.copy(totp = state.totp?.let { draft ->
                if (!draft.hasExisting) draft else draft.copy(secret = "", clear = !draft.clear)
            })
        }
    }

    fun cancelTotp() {
        mutableState.update { it.copy(totp = null) }
    }

    fun submitTotp() {
        val draft = mutableState.value.totp ?: return
        if (mutableState.value.status != "unlocked" || mutableState.value.busy ||
            (!draft.clear && draft.secret.isBlank())
        ) return
        var secret = draft.secret
        val clear = draft.clear
        val id = draft.id
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(totp = null, busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { VaultNativeBridge.setLoginTotp(id, secret, clear) }
                }
                secret = ""
                finishMutation(result, generation)
            } finally {
                secret = ""
                endOperation()
            }
        }
    }

    fun beginRecovery(item: LoginSummary) {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy) return
        recoveryImportGeneration += 1
        mutableState.update { it.copy(recovery = RecoveryDraft(item.id, item.title, item.hasRecoveryCodes), error = null) }
    }

    fun recoveryImportToken(): Long = recoveryImportGeneration

    fun beginRecoveryImportedText(itemId: String, text: String, token: Long): Boolean {
        if (token != recoveryImportGeneration || mutableState.value.status != "unlocked" ||
            mutableState.value.busy || mutableState.value.section != VaultSection.Logins ||
            mutableState.value.recovery != null) return false
        val item = mutableState.value.logins.find { it.id == itemId } ?: return false
        recoveryImportGeneration += 1
        mutableState.update { it.copy(recovery = RecoveryDraft(item.id, item.title, item.hasRecoveryCodes,
            imported = true, input = text), error = null) }
        return true
    }

    fun updateRecoveryInput(value: String) {
        if (value.toByteArray(Charsets.UTF_8).size > 32 * 1024) return
        mutableState.update { it.copy(recovery = it.recovery?.copy(input = value, clear = false, error = null)) }
    }

    fun toggleRecoveryClear() {
        mutableState.update { state -> state.copy(recovery = state.recovery?.let { draft ->
            if (!draft.hasExisting) draft else draft.copy(input = "", clear = !draft.clear, error = null)
        }) }
    }

    fun updateRecoveryViewPassword(value: String) {
        mutableState.update { it.copy(recovery = it.recovery?.copy(viewPassword = value, error = null)) }
    }

    fun updateRecoveryCopyPassword(value: String) {
        mutableState.update { it.copy(recovery = it.recovery?.copy(copyPassword = value, error = null)) }
    }

    fun requestRecoveryCopy(index: Int) {
        mutableState.update { state -> state.copy(recovery = state.recovery?.let { draft ->
            if (index !in draft.codes.indices) draft else draft.copy(copyIndex = index, copyPassword = "", error = null)
        }) }
    }

    fun cancelRecoveryCopy() {
        mutableState.update { it.copy(recovery = it.recovery?.copy(copyIndex = null, copyPassword = "")) }
    }

    fun cancelRecovery() {
        recoveryImportGeneration += 1
        mutableState.update { it.copy(recovery = null) }
    }

    fun submitRecoverySet(onSaved: (String, ByteArray?) -> Unit) {
        val draft = mutableState.value.recovery ?: return
        if (mutableState.value.status != "unlocked" || mutableState.value.busy ||
            (!draft.clear && draft.input.isBlank())) return
        var input = draft.input
        val clear = draft.clear
        val inputDigest = if (clear) null else MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray(Charsets.UTF_8))
        val id = draft.id
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(recovery = null, busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { VaultNativeBridge.setLoginRecoveryCodes(id, input, clear) }
                }
                input = ""
                finishMutation(result, generation)
                if (result == "ok" && generation == lifecycleGeneration) {
                    onSaved(id, if (draft.imported) inputDigest else null)
                }
            } finally {
                input = ""
                endOperation()
            }
        }
    }

    fun submitRecoveryView() {
        val draft = mutableState.value.recovery ?: return
        if (mutableState.value.status != "unlocked" || mutableState.value.busy ||
            draft.viewPassword.isEmpty() || !draft.hasExisting) return
        var password = draft.viewPassword
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(recovery = draft.copy(viewPassword = "", codes = emptyList()), busy = true) }
        viewModelScope.launch {
            try {
                var response = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { VaultNativeBridge.viewLoginRecoveryCodes(draft.id, password) }
                }
                password = ""
                if (generation != lifecycleGeneration || mutableState.value.recovery?.id != draft.id) return@launch
                val codes = if (response.startsWith("value:")) runCatching {
                    val array = JSONArray(response.substring(6))
                    require(array.length() in 1..100)
                    List(array.length()) { index -> array.getString(index) }
                }.getOrNull() else null
                val error = if (codes == null) response.takeUnless { it.startsWith("value:") } ?: "io_error" else null
                response = ""
                mutableState.update { it.copy(recovery = it.recovery?.copy(codes = codes.orEmpty(), error = error)) }
            } finally {
                password = ""
                endOperation()
            }
        }
    }

    fun submitRecoveryCopy() {
        val draft = mutableState.value.recovery ?: return
        val index = draft.copyIndex ?: return
        if (mutableState.value.status != "unlocked" || mutableState.value.busy ||
            draft.copyPassword.isEmpty() || index !in draft.codes.indices) return
        var password = draft.copyPassword
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(recovery = draft.copy(copyIndex = null, copyPassword = ""), busy = true) }
        viewModelScope.launch {
            try {
                var response = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { VaultNativeBridge.copyLoginRecoveryCode(draft.id, index, password) }
                }
                password = ""
                if (generation != lifecycleGeneration || mutableState.value.recovery?.id != draft.id) {
                    response = ""
                    return@launch
                }
                val result = protectedClipboard.writeResponse(response)
                response = ""
                mutableState.update { it.copy(recovery = it.recovery?.copy(error = result.takeUnless { code -> code == "ok" })) }
            } finally {
                password = ""
                endOperation()
            }
        }
    }

    fun prepareBackup(onReady: (Boolean) -> Unit) {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy) return
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation, VaultNativeBridge::prepareEncryptedBackup)
                }
                if (generation != lifecycleGeneration) {
                    backupDocuments.clearExport()
                    return@launch
                }
                mutableState.update { it.copy(busy = false, error = result.takeUnless { code -> code == "ok" }) }
                onReady(result == "ok")
            } finally {
                endOperation()
            }
        }
    }

    fun beginRestoreFromStage() {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(restorePassword = "", error = null) }
    }

    fun updateRestorePassword(value: String) {
        mutableState.update { it.copy(restorePassword = value, error = null) }
    }

    fun cancelRestore() {
        mutableState.update { it.copy(restorePassword = null) }
        backupDocuments.clearImport()
    }

    fun submitRestore() {
        val entered = mutableState.value.restorePassword ?: return
        if (mutableState.value.busy || entered.isEmpty()) return
        var password = entered
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(restorePassword = null, busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { VaultNativeBridge.restoreStagedBackup(password) }
                }
                password = ""
                if (result == "ok") {
                    backupDocuments.clearImport()
                    finishMutation(result, generation)
                } else if (generation == lifecycleGeneration) {
                    mutableState.update { it.copy(restorePassword = "", busy = false, error = result) }
                }
            } finally {
                password = ""
                endOperation()
            }
        }
    }

    fun reportDocumentFailure() {
        mutableState.update { it.copy(error = "io_error") }
    }

    fun requestPasswordHealth() {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy) return
        val generation = lifecycleGeneration
        val requestId = ++healthRequestId
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(health = HealthPanel(requestId), busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    AndroidItemDtos.passwordHealth(runCurrentOperation(generation, VaultNativeBridge::passwordHealth))
                }
                if (generation != lifecycleGeneration || mutableState.value.health?.requestId != requestId) return@launch
                mutableState.update { it.copy(
                    health = result.report?.let { report -> HealthPanel(requestId, report, false) },
                    busy = false,
                    error = result.error,
                ) }
            } finally {
                endOperation()
            }
        }
    }

    fun closePasswordHealth() {
        mutableState.update { it.copy(health = null) }
    }

    fun beginGenerator() {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy) return
        mutableState.update { it.copy(generator = GeneratorDraft(), error = null) }
    }

    fun updateGenerator(transform: (GeneratorDraft) -> GeneratorDraft) {
        mutableState.update { state -> state.copy(generator = state.generator?.let(transform)?.copy(result = "", error = null)) }
    }

    fun generateCredential() {
        val draft = mutableState.value.generator ?: return
        val length = draft.length.toIntOrNull()
        if (length == null) {
            mutableState.update { it.copy(generator = draft.copy(result = "", error = "请输入有效长度")) }
            return
        }
        val generated = runCatching {
            when (draft.kind) {
                GeneratorKind.Password -> AndroidCredentialGenerator.password(length, draft.lowercase,
                    draft.uppercase, draft.digits, draft.symbols)
                GeneratorKind.Username -> AndroidCredentialGenerator.username(length)
                GeneratorKind.EmailAlias -> AndroidCredentialGenerator.emailAlias(length, draft.domain)
            }
        }
        mutableState.update { it.copy(generator = draft.copy(
            result = generated.getOrNull().orEmpty(),
            error = generated.exceptionOrNull()?.message,
        )) }
    }

    fun copyGeneratedCredential() {
        val draft = mutableState.value.generator ?: return
        if (draft.result.isEmpty()) return
        val result = protectedClipboard.writeResponse("value:${draft.result}")
        mutableState.update { it.copy(generator = null, error = result.takeUnless { code -> code == "ok" }) }
    }

    fun applyGeneratedCredential() {
        val draft = mutableState.value.generator ?: return
        if (draft.result.isEmpty() || mutableState.value.editor == null) return
        mutableState.update { state -> state.copy(
            editor = state.editor?.let { editor ->
                if (draft.kind == GeneratorKind.Password) editor.copy(password = draft.result)
                else editor.copy(username = draft.result)
            },
            generator = null,
        ) }
    }

    fun closeGenerator() {
        mutableState.update { it.copy(generator = null) }
    }

    fun lock() {
        AutofillRequests.clear()
        markLocked()
        synchronized(nativeCallGate) {
            VaultNativeBridge.lock()
            backupDocuments.clearImport()
        }
    }

    private fun markLocked() {
        lifecycleGeneration += 1
        recoveryImportGeneration += 1
        revealRequestId += 1
        editorRequestGeneration += 1
        refreshToken += 1
        mutableState.value = VaultUiState(status = "locked", busy = pendingOperations != 0)
    }

    fun beginCreateLogin() {
        editorRequestGeneration += 1
        mutableState.update { it.copy(editor = LoginDraft(), error = null) }
    }

    fun showLogins() {
        showSection(VaultSection.Logins)
    }

    fun showTrash() {
        showTrashFor(VaultSection.Logins)
    }

    fun showSection(section: VaultSection) {
        if (section == VaultSection.Trash) return
        recoveryImportGeneration += 1
        editorRequestGeneration += 1
        mutableState.update {
            it.copy(section = section, query = "", editor = null, otherDraft = null,
                passwordRotation = null, protectedCopy = null, protectedReveal = null, history = null, totp = null,
                health = null, generator = null, recovery = null,
                restoreRevisionCandidate = null, confirmClearHistory = false, error = null,
                batchDeleteNotice = null)
        }
    }

    fun showTrashFor(section: VaultSection) {
        if (section == VaultSection.Secrets || section == VaultSection.Trash) return
        recoveryImportGeneration += 1
        editorRequestGeneration += 1
        mutableState.update {
            it.copy(section = VaultSection.Trash, trashType = section, query = "", editor = null,
                otherDraft = null, passwordRotation = null, protectedCopy = null, protectedReveal = null, history = null,
                totp = null, health = null, generator = null, recovery = null,
                restoreRevisionCandidate = null, confirmClearHistory = false, error = null,
                batchDeleteNotice = null)
        }
    }

    fun requestHistory(target: HistoryTarget) {
        if (mutableState.value.status != "unlocked" || mutableState.value.busy ||
            target.section == VaultSection.Secrets || target.section == VaultSection.Trash
        ) return
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(history = HistoryPanel(target), busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    AndroidItemDtos.history(runCurrentOperation(generation) {
                        when (target.section) {
                            VaultSection.Logins -> VaultNativeBridge.listLoginHistory(target.id)
                            VaultSection.Cards -> VaultNativeBridge.listCardHistory(target.id)
                            VaultSection.Ssh -> VaultNativeBridge.listSshHistory(target.id)
                            VaultSection.Identities -> VaultNativeBridge.listIdentityHistory(target.id)
                            VaultSection.Secrets, VaultSection.Trash -> "invalid_input"
                        }
                    })
                }
                if (generation != lifecycleGeneration || mutableState.value.history?.target != target) return@launch
                mutableState.update {
                    it.copy(history = if (result.error == null) HistoryPanel(target, result.items, false) else null,
                        busy = false, error = result.error)
                }
            } finally {
                endOperation()
            }
        }
    }

    fun closeHistory() {
        mutableState.update { it.copy(history = null, restoreRevisionCandidate = null,
            confirmClearHistory = false) }
    }

    fun requestRestoreRevision(entry: HistorySummary) {
        val panel = mutableState.value.history ?: return
        if (mutableState.value.busy || !panel.entries.contains(entry)) return
        mutableState.update { it.copy(restoreRevisionCandidate = entry) }
    }

    fun cancelRestoreRevision() {
        mutableState.update { it.copy(restoreRevisionCandidate = null) }
    }

    fun confirmRestoreRevision() {
        val panel = mutableState.value.history ?: return
        val entry = mutableState.value.restoreRevisionCandidate ?: return
        if (!panel.entries.contains(entry)) return
        closeHistory()
        performMutation {
            when (panel.target.section) {
                VaultSection.Logins -> VaultNativeBridge.restoreLoginRevision(panel.target.id, entry.revisionId)
                VaultSection.Cards -> VaultNativeBridge.restoreCardRevision(panel.target.id, entry.revisionId)
                VaultSection.Ssh -> VaultNativeBridge.restoreSshRevision(panel.target.id, entry.revisionId)
                VaultSection.Identities -> VaultNativeBridge.restoreIdentityRevision(panel.target.id, entry.revisionId)
                else -> "invalid_input"
            }
        }
    }

    fun requestClearHistory() {
        if (mutableState.value.busy || mutableState.value.history?.entries.isNullOrEmpty()) return
        mutableState.update { it.copy(confirmClearHistory = true) }
    }

    fun cancelClearHistory() {
        mutableState.update { it.copy(confirmClearHistory = false) }
    }

    fun confirmClearHistory() {
        val target = mutableState.value.history?.target ?: return
        if (!mutableState.value.confirmClearHistory) return
        closeHistory()
        performMutation {
            when (target.section) {
                VaultSection.Logins -> VaultNativeBridge.clearLoginHistory(target.id)
                VaultSection.Cards -> VaultNativeBridge.clearCardHistory(target.id)
                VaultSection.Ssh -> VaultNativeBridge.clearSshHistory(target.id)
                VaultSection.Identities -> VaultNativeBridge.clearIdentityHistory(target.id)
                else -> "invalid_input"
            }
        }
    }

    fun updateQuery(value: String) {
        mutableState.update { it.copy(query = value) }
    }

    fun beginEditLogin(item: LoginSummary) {
        if (mutableState.value.busy) return
        val request = ++editorRequestGeneration
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val detail = withContext(Dispatchers.IO) {
                    AndroidItemDtos.loginExtras(runCurrentOperation(generation) {
                        VaultNativeBridge.loginEditorDetail(item.id)
                    })
                }
                if (generation != lifecycleGeneration || request != editorRequestGeneration ||
                    mutableState.value.section != VaultSection.Logins) return@launch
                mutableState.update { state -> state.copy(
                    editor = detail.item?.let { extras -> LoginDraft(
                        id = item.id, title = item.title, username = item.username,
                        url = item.url.orEmpty(), notes = extras.notes, folder = extras.folder,
                        favorite = extras.favorite, additionalUrls = extras.additionalUrls,
                        autofillOnPageLoad = extras.autofillOnPageLoad,
                        masterPasswordReprompt = extras.masterPasswordReprompt,
                        customFields = extras.customFields,
                    ) },
                    error = detail.error,
                ) }
            } finally {
                endOperation()
            }
        }
    }

    fun updateLoginDraft(transform: (LoginDraft) -> LoginDraft) {
        mutableState.update { state ->
            state.copy(editor = state.editor?.let(transform), error = null)
        }
    }

    fun cancelLoginEditor() {
        editorRequestGeneration += 1
        mutableState.update { it.copy(editor = null, generator = null) }
    }

    fun beginCard(item: CardSummary? = null) {
        if (mutableState.value.busy) return
        val request = ++editorRequestGeneration
        if (item == null) {
            mutableState.update { it.copy(otherDraft = OtherDraft.Card(), error = null) }
            return
        }
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val detail = withContext(Dispatchers.IO) {
                    AndroidItemDtos.cardExtras(runCurrentOperation(generation) {
                        VaultNativeBridge.cardEditorDetail(item.id)
                    })
                }
                if (generation != lifecycleGeneration || request != editorRequestGeneration ||
                    mutableState.value.section != VaultSection.Cards) return@launch
                mutableState.update { state -> state.copy(
                    otherDraft = detail.item?.let { extras -> OtherDraft.Card(
                        id = item.id, title = item.title, holder = item.cardholderName,
                        month = item.expirationMonth.toString(), year = item.expirationYear.toString(),
                        issuer = extras.issuer, network = extras.network,
                        billingAddress = extras.billingAddress, notes = extras.notes,
                        folder = extras.folder, favorite = extras.favorite,
                        masterPasswordReprompt = extras.masterPasswordReprompt,
                    ) },
                    error = detail.error,
                ) }
            } finally {
                endOperation()
            }
        }
    }

    fun beginSsh(item: SshSummary? = null) {
        if (mutableState.value.busy || item?.managed == true) return
        val request = ++editorRequestGeneration
        if (item == null) {
            mutableState.update { it.copy(otherDraft = OtherDraft.Ssh(), error = null) }
            return
        }
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val detail = withContext(Dispatchers.IO) {
                    AndroidItemDtos.sshExtras(runCurrentOperation(generation) {
                        VaultNativeBridge.sshEditorDetail(item.id)
                    })
                }
                if (generation != lifecycleGeneration || request != editorRequestGeneration ||
                    mutableState.value.section != VaultSection.Ssh) return@launch
                mutableState.update { state -> state.copy(
                    otherDraft = detail.item?.let { extras -> OtherDraft.Ssh(
                        id = item.id, title = item.title, host = item.host.orEmpty(),
                        port = item.port.toString(), username = item.username,
                        notes = extras.notes, folder = extras.folder,
                        favorite = extras.favorite,
                        masterPasswordReprompt = extras.masterPasswordReprompt,
                    ) },
                    error = detail.error,
                ) }
            } finally {
                endOperation()
            }
        }
    }

    fun beginIdentity(item: IdentitySummary? = null) {
        if (mutableState.value.busy) return
        val request = ++editorRequestGeneration
        if (item == null) {
            mutableState.update { it.copy(otherDraft = OtherDraft.Identity(), error = null) }
            return
        }
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val detail = withContext(Dispatchers.IO) {
                    AndroidItemDtos.identityComplete(
                        runCurrentOperation(generation) { VaultNativeBridge.identityEditorDetail(item.id) },
                        item.id,
                    )
                }
                if (generation != lifecycleGeneration || request != editorRequestGeneration ||
                    mutableState.value.section != VaultSection.Identities) return@launch
                mutableState.update {
                    it.copy(
                        otherDraft = detail.item,
                        error = detail.error,
                    )
                }
            } finally {
                endOperation()
            }
        }
    }

    fun beginSecret(item: SecretSummary? = null) {
        if (mutableState.value.busy) return
        val request = ++editorRequestGeneration
        if (item == null) {
            mutableState.update { it.copy(otherDraft = OtherDraft.Secret(), error = null) }
            return
        }
        val generation = lifecycleGeneration
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val detail = withContext(Dispatchers.IO) {
                    AndroidItemDtos.secretExtras(runCurrentOperation(generation) {
                        VaultNativeBridge.secretEditorDetail(item.id)
                    })
                }
                if (generation != lifecycleGeneration || request != editorRequestGeneration ||
                    mutableState.value.section != VaultSection.Secrets) return@launch
                mutableState.update { state -> state.copy(
                    otherDraft = detail.item?.let { extras -> OtherDraft.Secret(
                        id = item.id, title = item.title, kind = item.kind,
                        provider = item.provider.orEmpty(), account = item.account.orEmpty(),
                        environment = extras.environment, scopes = extras.scopes.joinToString("\n"),
                        expiresAt = extras.expiresAt, website = extras.website,
                        notes = extras.notes, folder = extras.folder,
                        favorite = extras.favorite,
                        masterPasswordReprompt = extras.masterPasswordReprompt,
                    ) },
                    error = detail.error,
                ) }
            } finally {
                endOperation()
            }
        }
    }

    fun updateOtherDraft(transform: (OtherDraft) -> OtherDraft) {
        mutableState.update { state ->
            state.copy(otherDraft = state.otherDraft?.let(transform), error = null)
        }
    }

    fun cancelOtherEditor() {
        editorRequestGeneration += 1
        mutableState.update { it.copy(otherDraft = null) }
    }

    fun saveOther() {
        var draft: OtherDraft? = mutableState.value.otherDraft ?: return
        if (draft?.title.isNullOrBlank() || mutableState.value.busy) return
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(otherDraft = null, busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) {
                        when (val item = draft) {
                            is OtherDraft.Card -> {
                                val month = item.month.toIntOrNull()
                                val year = item.year.toIntOrNull()
                                if (month == null || year == null) "invalid_input"
                                else if (item.id == null) VaultNativeBridge.addCardComplete(
                                    item.title, item.holder, item.number, month, year,
                                    item.securityCode, item.pin, AndroidItemDtos.cardExtrasJson(item),
                                ) else VaultNativeBridge.updateCardComplete(
                                    item.id, item.title, item.holder, item.number, month, year,
                                    item.securityCode, item.clearSecurityCode, item.pin, item.clearPin,
                                    AndroidItemDtos.cardExtrasJson(item),
                                )
                            }
                            is OtherDraft.Ssh -> {
                                val port = item.port.toIntOrNull()
                                if (port == null) "invalid_input"
                                else if (item.id == null) VaultNativeBridge.addSshComplete(
                                    item.title, item.host, port, item.username, item.password,
                                    item.publicKey, item.privateKey, item.passphrase,
                                    AndroidItemDtos.sshExtrasJson(item),
                                ) else VaultNativeBridge.updateSshComplete(
                                    item.id, item.title, item.host, port, item.username,
                                    item.password, item.clearPassword, item.publicKey,
                                    item.clearPublicKey, item.privateKey, item.clearPrivateKey,
                                    item.passphrase, item.clearPassphrase,
                                    AndroidItemDtos.sshExtrasJson(item),
                                )
                            }
                            is OtherDraft.Identity -> if (item.id == null) {
                                VaultNativeBridge.addIdentityComplete(AndroidItemDtos.identityCompleteJson(item))
                            } else VaultNativeBridge.updateIdentityComplete(
                                item.id, AndroidItemDtos.identityCompleteJson(item),
                            )
                            is OtherDraft.Secret -> if (item.id == null) VaultNativeBridge.addSecretComplete(
                                item.title, item.kind, item.provider, item.account, item.value,
                                AndroidItemDtos.secretExtrasJson(item),
                            ) else VaultNativeBridge.updateSecretComplete(
                                item.id, item.title, item.provider, item.account, item.value,
                                AndroidItemDtos.secretExtrasJson(item),
                            )
                            null -> "invalid_input"
                        }
                    }
                }
                draft = null
                finishMutation(result, generation)
            } finally {
                draft = null
                endOperation()
            }
        }
    }

    fun requestOtherDelete(target: OtherTarget) {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(otherDeleteCandidate = target, error = null) }
    }

    fun cancelOtherDelete() {
        mutableState.update { it.copy(otherDeleteCandidate = null) }
    }

    fun confirmOtherDelete() {
        val target = mutableState.value.otherDeleteCandidate ?: return
        mutableState.update { it.copy(otherDeleteCandidate = null) }
        performMutation {
            when (target.section) {
                VaultSection.Cards -> VaultNativeBridge.deleteCard(target.id)
                VaultSection.Ssh -> VaultNativeBridge.deleteSsh(target.id)
                VaultSection.Identities -> VaultNativeBridge.deleteIdentity(target.id)
                VaultSection.Secrets -> VaultNativeBridge.deleteSecret(target.id)
                else -> "invalid_input"
            }
        }
    }

    fun restoreOther(target: OtherTrashTarget) {
        performMutation {
            when (target.section) {
                VaultSection.Cards -> VaultNativeBridge.restoreCard(target.item.trashId)
                VaultSection.Ssh -> VaultNativeBridge.restoreSsh(target.item.trashId)
                VaultSection.Identities -> VaultNativeBridge.restoreIdentity(target.item.trashId)
                else -> "invalid_input"
            }
        }
    }

    fun requestOtherPurge(target: OtherTrashTarget) {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(otherPurgeCandidate = target, error = null) }
    }

    fun cancelOtherPurge() {
        mutableState.update { it.copy(otherPurgeCandidate = null) }
    }

    fun confirmOtherPurge() {
        val target = mutableState.value.otherPurgeCandidate ?: return
        mutableState.update { it.copy(otherPurgeCandidate = null) }
        performMutation {
            when (target.section) {
                VaultSection.Cards -> VaultNativeBridge.purgeCard(target.item.trashId)
                VaultSection.Ssh -> VaultNativeBridge.purgeSsh(target.item.trashId)
                VaultSection.Identities -> VaultNativeBridge.purgeIdentity(target.item.trashId)
                else -> "invalid_input"
            }
        }
    }

    fun requestOtherEmptyTrash() {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(confirmOtherEmptyTrash = true, error = null) }
    }

    fun cancelOtherEmptyTrash() {
        mutableState.update { it.copy(confirmOtherEmptyTrash = false) }
    }

    fun confirmOtherEmptyTrash() {
        val section = mutableState.value.trashType
        mutableState.update { it.copy(confirmOtherEmptyTrash = false) }
        performMutation {
            when (section) {
                VaultSection.Cards -> VaultNativeBridge.emptyCardTrash()
                VaultSection.Ssh -> VaultNativeBridge.emptySshTrash()
                VaultSection.Identities -> VaultNativeBridge.emptyIdentityTrash()
                else -> "invalid_input"
            }
        }
    }

    fun saveLogin() {
        var draft: LoginDraft? = mutableState.value.editor ?: return
        if (draft?.title.isNullOrBlank() || (draft?.id == null && draft?.password.isNullOrEmpty()) ||
            mutableState.value.busy) return
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update {
            it.copy(editor = null, generator = null, busy = true, error = null)
        }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) {
                        val item = draft ?: return@runCurrentOperation "invalid_input"
                        val extras = AndroidItemDtos.loginExtrasJson(item)
                        if (item.id == null) VaultNativeBridge.addLoginComplete(
                            item.title, item.username, item.password, item.url, extras,
                        ) else VaultNativeBridge.updateLoginComplete(
                            item.id, item.title, item.username, item.password, item.url, extras,
                        )
                    }
                }
                draft = null
                finishMutation(result, generation)
            } finally {
                draft = null
                endOperation()
            }
        }
    }

    fun requestDeleteLogin(item: LoginSummary) {
        mutableState.update { it.copy(deleteCandidate = item, error = null) }
    }

    fun cancelDeleteLogin() {
        mutableState.update { it.copy(deleteCandidate = null) }
    }

    fun confirmDeleteLogin() {
        val id = mutableState.value.deleteCandidate?.id ?: return
        mutableState.update { it.copy(deleteCandidate = null) }
        performMutation { VaultNativeBridge.deleteLogin(id) }
    }

    fun restoreLogin(item: TrashSummary) {
        performMutation { VaultNativeBridge.restoreLogin(item.trashId) }
    }

    fun requestPurgeLogin(item: TrashSummary) {
        mutableState.update { it.copy(purgeCandidate = item, error = null) }
    }

    fun cancelPurgeLogin() {
        mutableState.update { it.copy(purgeCandidate = null) }
    }

    fun confirmPurgeLogin() {
        val trashId = mutableState.value.purgeCandidate?.trashId ?: return
        mutableState.update { it.copy(purgeCandidate = null) }
        performMutation { VaultNativeBridge.purgeLogin(trashId) }
    }

    fun requestEmptyTrash() {
        if (mutableState.value.trash.isNotEmpty()) {
            mutableState.update { it.copy(confirmEmptyTrash = true, error = null) }
        }
    }

    fun cancelEmptyTrash() {
        mutableState.update { it.copy(confirmEmptyTrash = false) }
    }

    fun confirmEmptyTrash() {
        mutableState.update { it.copy(confirmEmptyTrash = false) }
        performMutation(VaultNativeBridge::emptyTrash)
    }

    private fun submit(operation: (String) -> String) {
        if (mutableState.value.busy) return
        var password = mutableState.value.password
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(password = "", busy = true, authenticating = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation) { operation(password) }
                }
                password = ""
                showSummaryLoadingAfterUnlock(result, generation)
                val refreshed = withContext(Dispatchers.IO) { readVaultState() }
                if (generation != lifecycleGeneration) {
                    return@launch
                }
                mutableState.update {
                    it.copy(
                        status = refreshed.status,
                        logins = refreshed.logins,
                        trash = refreshed.trash,
                        cards = refreshed.cards,
                        ssh = refreshed.ssh,
                        identities = refreshed.identities,
                        secrets = refreshed.secrets,
                        otherTrash = refreshed.otherTrash,
                        password = "",
                        busy = false,
                        authenticating = false,
                        loadingPhase = null,
                        error = result.takeUnless { code -> code == "ok" } ?: refreshed.error,
                    )
                }
            } finally {
                password = ""
                endOperation()
            }
        }
    }

    private suspend fun finishMutation(result: String, generation: Long) {
        showSummaryLoadingAfterUnlock(result, generation)
        val refreshed = withContext(Dispatchers.IO) { readVaultState() }
        if (generation != lifecycleGeneration) {
            return
        }
        mutableState.update {
            it.copy(
                status = refreshed.status,
                logins = refreshed.logins,
                trash = refreshed.trash,
                cards = refreshed.cards,
                ssh = refreshed.ssh,
                identities = refreshed.identities,
                secrets = refreshed.secrets,
                otherTrash = refreshed.otherTrash,
                busy = false,
                loadingPhase = null,
                error = result.takeUnless { code -> code == "ok" } ?: refreshed.error,
            )
        }
    }

    private fun performMutation(operation: () -> String) {
        if (mutableState.value.busy || mutableState.value.status != "unlocked") return
        val generation = lifecycleGeneration
        refreshToken += 1
        pendingOperations += 1
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    runCurrentOperation(generation, operation)
                }
                finishMutation(result, generation)
            } finally {
                endOperation()
            }
        }
    }

    private fun runCurrentOperation(generation: Long, operation: () -> String): String =
        synchronized(nativeCallGate) {
            if (generation != lifecycleGeneration) {
                "locked"
            } else {
                val result = operation()
                if (generation != lifecycleGeneration) {
                    VaultNativeBridge.lock()
                    "locked"
                } else {
                    result
                }
            }
        }

    private fun showSummaryLoadingAfterUnlock(result: String, generation: Long) {
        if (generation != lifecycleGeneration || result != "ok" ||
            mutableState.value.status == "unlocked") return
        mutableState.update { it.copy(authenticating = false,
            loadingPhase = VaultLoadingPhase.Summaries) }
    }

    private fun endOperation() {
        pendingOperations -= 1
        refreshToken += 1
        if (pendingOperations == 0) {
            mutableState.update { it.copy(busy = false, authenticating = false, loadingPhase = null) }
        }
    }

    private fun readVaultState(): RefreshedVaultState {
        val status = VaultNativeBridge.status()
        if (status != "unlocked") return RefreshedVaultState(status = status)
        val autofillPreview = AutofillPreviewCache(getApplication())
        val previewDigest = autofillPreview.vaultDigest()
        val result = VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins())
        if (result.error == null) runCatching { autofillPreview.refreshLogins(result.items, previewDigest) }
        val trash = VaultNativeBridge.decodeTrash(VaultNativeBridge.listTrash())
        val cards = AndroidItemDtos.cards(VaultNativeBridge.listCards())
        val ssh = AndroidItemDtos.ssh(VaultNativeBridge.listSsh())
        val identities = AndroidItemDtos.identities(VaultNativeBridge.listIdentities())
        val secrets = AndroidItemDtos.secrets(VaultNativeBridge.listSecrets())
        val cardTrash = AndroidItemDtos.trash(VaultNativeBridge.listCardTrash())
        val sshTrash = AndroidItemDtos.trash(VaultNativeBridge.listSshTrash())
        val identityTrash = AndroidItemDtos.trash(VaultNativeBridge.listIdentityTrash())
        return RefreshedVaultState(
            status = status,
            logins = result.items,
            trash = trash.items,
            cards = cards.items,
            ssh = ssh.items,
            identities = identities.items,
            secrets = secrets.items,
            otherTrash = mapOf(
                VaultSection.Cards to cardTrash.items,
                VaultSection.Ssh to sshTrash.items,
                VaultSection.Identities to identityTrash.items,
            ),
            error = result.error ?: trash.error ?: cards.error ?: ssh.error ?:
                identities.error ?: secrets.error ?: cardTrash.error ?: sshTrash.error ?: identityTrash.error,
        )
    }
}

private data class RefreshedVaultState(
    val status: String,
    val logins: List<LoginSummary> = emptyList(),
    val trash: List<TrashSummary> = emptyList(),
    val cards: List<CardSummary> = emptyList(),
    val ssh: List<SshSummary> = emptyList(),
    val identities: List<IdentitySummary> = emptyList(),
    val secrets: List<SecretSummary> = emptyList(),
    val otherTrash: Map<VaultSection, List<OtherTrashSummary>> = emptyMap(),
    val error: String? = null,
)
