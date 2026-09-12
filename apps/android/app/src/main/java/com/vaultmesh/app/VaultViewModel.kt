package com.vaultmesh.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class VaultUiState(
    val status: String = "missing",
    val password: String = "",
    val busy: Boolean = false,
    val error: String? = null,
    val logins: List<LoginSummary> = emptyList(),
    val trash: List<TrashSummary> = emptyList(),
    val section: VaultSection = VaultSection.Logins,
    val query: String = "",
    val editor: LoginDraft? = null,
    val deleteCandidate: LoginSummary? = null,
    val purgeCandidate: TrashSummary? = null,
    val confirmEmptyTrash: Boolean = false,
)

enum class VaultSection { Logins, Trash }

data class LoginDraft(
    val id: String? = null,
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
)

class VaultViewModel : ViewModel() {
    private val mutableState = MutableStateFlow(VaultUiState())
    val state: StateFlow<VaultUiState> = mutableState.asStateFlow()
    private var lifecycleGeneration = 0L

    fun refresh() {
        val generation = lifecycleGeneration
        viewModelScope.launch {
            val refreshed = withContext(Dispatchers.IO) { readVaultState() }
            if (generation != lifecycleGeneration) return@launch
            mutableState.update {
                it.copy(
                    status = refreshed.status,
                    logins = refreshed.logins,
                    trash = refreshed.trash,
                    busy = false,
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

    fun lock() {
        lifecycleGeneration += 1
        VaultNativeBridge.lock()
        mutableState.value = VaultUiState(status = "locked")
    }

    fun markLocked() {
        lifecycleGeneration += 1
        mutableState.value = VaultUiState(status = "locked")
    }

    fun beginCreateLogin() {
        mutableState.update { it.copy(editor = LoginDraft(), error = null) }
    }

    fun showLogins() {
        mutableState.update { it.copy(section = VaultSection.Logins, query = "", error = null) }
    }

    fun showTrash() {
        mutableState.update { it.copy(section = VaultSection.Trash, query = "", error = null) }
    }

    fun updateQuery(value: String) {
        mutableState.update { it.copy(query = value) }
    }

    fun beginEditLogin(item: LoginSummary) {
        mutableState.update {
            it.copy(
                editor = LoginDraft(
                    id = item.id,
                    title = item.title,
                    username = item.username,
                    url = item.url.orEmpty(),
                ),
                error = null,
            )
        }
    }

    fun updateLoginDraft(transform: (LoginDraft) -> LoginDraft) {
        mutableState.update { state ->
            state.copy(editor = state.editor?.let(transform), error = null)
        }
    }

    fun cancelLoginEditor() {
        mutableState.update { it.copy(editor = null) }
    }

    fun saveLogin() {
        val draft = mutableState.value.editor ?: return
        if (draft.title.isBlank() || mutableState.value.busy) return
        val id = draft.id
        val title = draft.title
        val username = draft.username
        val url = draft.url
        var password = draft.password
        val generation = lifecycleGeneration
        mutableState.update {
            it.copy(editor = null, busy = true, error = null)
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                if (id == null) {
                    VaultNativeBridge.addLogin(title, username, password, url)
                } else {
                    VaultNativeBridge.updateLogin(
                        id,
                        title,
                        username,
                        password,
                        password.isNotEmpty(),
                        url,
                    )
                }
            }
            password = ""
            finishMutation(result, generation)
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
        val password = mutableState.value.password
        val generation = lifecycleGeneration
        mutableState.update { it.copy(password = "", busy = true, error = null) }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { operation(password) }
            val refreshed = withContext(Dispatchers.IO) { readVaultState() }
            if (generation != lifecycleGeneration) {
                withContext(Dispatchers.IO) { VaultNativeBridge.lock() }
                return@launch
            }
            mutableState.update {
                it.copy(
                    status = refreshed.status,
                    logins = refreshed.logins,
                    trash = refreshed.trash,
                    password = "",
                    busy = false,
                    error = result.takeUnless { code -> code == "ok" } ?: refreshed.error,
                )
            }
        }
    }

    private suspend fun finishMutation(result: String, generation: Long) {
        val refreshed = withContext(Dispatchers.IO) { readVaultState() }
        if (generation != lifecycleGeneration) {
            withContext(Dispatchers.IO) { VaultNativeBridge.lock() }
            return
        }
        mutableState.update {
            it.copy(
                status = refreshed.status,
                logins = refreshed.logins,
                trash = refreshed.trash,
                busy = false,
                error = result.takeUnless { code -> code == "ok" } ?: refreshed.error,
            )
        }
    }

    private fun performMutation(operation: () -> String) {
        if (mutableState.value.busy) return
        val generation = lifecycleGeneration
        mutableState.update { it.copy(busy = true, error = null) }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { operation() }
            finishMutation(result, generation)
        }
    }

    private fun readVaultState(): RefreshedVaultState {
        val status = VaultNativeBridge.status()
        if (status != "unlocked") return RefreshedVaultState(status = status)
        val result = VaultNativeBridge.decodeLogins(VaultNativeBridge.listLogins())
        val trash = VaultNativeBridge.decodeTrash(VaultNativeBridge.listTrash())
        return RefreshedVaultState(
            status = status,
            logins = result.items,
            trash = trash.items,
            error = result.error ?: trash.error,
        )
    }
}

private data class RefreshedVaultState(
    val status: String,
    val logins: List<LoginSummary> = emptyList(),
    val trash: List<TrashSummary> = emptyList(),
    val error: String? = null,
)
