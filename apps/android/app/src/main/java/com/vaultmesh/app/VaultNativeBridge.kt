package com.vaultmesh.app

import org.json.JSONArray
import org.json.JSONObject

data class LoginSummary(
    val id: String,
    val title: String,
    val username: String,
    val url: String?,
    val hasPassword: Boolean,
    val hasTotpSecret: Boolean,
    val hasRecoveryCodes: Boolean,
)

data class LoginListResult(
    val items: List<LoginSummary> = emptyList(),
    val error: String? = null,
)

data class TrashSummary(
    val trashId: String,
    val itemId: String,
    val title: String,
    val username: String,
    val deletedAt: Long,
)

data class TrashListResult(
    val items: List<TrashSummary> = emptyList(),
    val error: String? = null,
)

class VaultNativeBridge private constructor() {
    companion object {
        init {
            System.loadLibrary("vaultmesh_android_runtime")
        }

        @JvmStatic external fun initialize(appDataDirectory: String): String
        @JvmStatic external fun autofillBegin(requestId: String, targetJson: String, masterPassword: String): String
        @JvmStatic external fun autofillBeginBiometric(requestId: String, targetJson: String, secret: String): String
        @JvmStatic external fun autofillBeginPin(requestId: String, targetJson: String, pin: String, deviceSecret: String): String
        @JvmStatic external fun autofillPreviewFingerprint(appDataDirectory: String): String
        @JvmStatic external fun autofillCandidates(token: String, query: String, appLabel: String, recentIdsJson: String): String
        @JvmStatic external fun autofillFill(token: String, requestId: String, id: String, confirmed: Boolean, rememberAssociation: Boolean, includePassword: Boolean): String
        @JvmStatic external fun autofillSave(token: String, requestId: String, id: String, title: String, username: String, password: String): String
        @JvmStatic external fun autofillCancel(token: String): String
        @JvmStatic external fun status(): String
        @JvmStatic external fun create(masterPassword: String): String
        @JvmStatic external fun unlock(masterPassword: String): String
        @JvmStatic external fun changeMasterPassword(currentPassword: String, newPassword: String): String
        @JvmStatic external fun prepareBiometricUnlock(): String
        @JvmStatic external fun unlockWithBiometricSecret(secret: String): String
        @JvmStatic external fun disableBiometricUnlock(): String
        @JvmStatic external fun pinStatus(): String
        @JvmStatic external fun enablePinUnlock(pin: String, deviceSecret: String): String
        @JvmStatic external fun unlockWithPin(pin: String, deviceSecret: String): String
        @JvmStatic external fun disablePinUnlock(): String
        @JvmStatic external fun prepareEncryptedBackup(): String
        @JvmStatic external fun restoreStagedBackup(masterPassword: String): String
        @JvmStatic external fun lock(): String
        @JvmStatic external fun assistOpen(wrappingKey: ByteArray): String
        @JvmStatic external fun assistStatus(): String
        @JvmStatic external fun assistGrant(peer: String, phone: Boolean, sms: Boolean): String
        @JvmStatic external fun assistTick(network: Boolean, phone: String, smsAllowed: Boolean): String
        @JvmStatic external fun assistStop(): String
        @JvmStatic external fun assistCode(code: String, source: String, age: Long, dedup: String, request: String): String
        @JvmStatic external fun syncNeeded(): String
        @JvmStatic external fun syncOpen(wrappingKey: ByteArray): String
        @JvmStatic external fun syncTick(networkAllowed: Boolean): String
        @JvmStatic external fun syncClose(): String
        @JvmStatic external fun syncStatus(): String
        @JvmStatic external fun syncRetry(): String
        @JvmStatic external fun syncSetEnabled(pairingRef: String, enabled: Boolean): String
        @JvmStatic external fun syncConflicts(): String
        @JvmStatic external fun syncRestoreConflict(id: String): String
        @JvmStatic external fun syncClearConflicts(): String
        @JvmStatic external fun lanOpen(wrappingKey: ByteArray): String
        @JvmStatic external fun lanStatus(): String
        @JvmStatic external fun lanStart(): String
        @JvmStatic external fun lanStop(): String
        @JvmStatic external fun lanBegin(pairingRef: String, pairingCode: String): String
        @JvmStatic external fun lanClose(): String
        @JvmStatic external fun lanRevoke(pairingRef: String): String
        @JvmStatic external fun lanRename(pairingRef: String, label: String): String
        @JvmStatic external fun listLogins(): String
        @JvmStatic external fun loginEditorDetail(id: String): String
        @JvmStatic external fun addLogin(
            title: String,
            username: String,
            password: String,
            url: String,
        ): String

        @JvmStatic external fun updateLogin(
            id: String,
            title: String,
            username: String,
            password: String,
            replacePassword: Boolean,
            url: String,
        ): String

        @JvmStatic external fun addLoginComplete(title: String, username: String, password: String, url: String, extrasJson: String): String
        @JvmStatic external fun updateLoginComplete(id: String, title: String, username: String, password: String, url: String, extrasJson: String): String

        @JvmStatic external fun deleteLogin(id: String): String
        @JvmStatic external fun listTrash(): String
        @JvmStatic external fun restoreLogin(trashId: String): String
        @JvmStatic external fun purgeLogin(trashId: String): String
        @JvmStatic external fun emptyTrash(): String
        @JvmStatic external fun listLoginHistory(id: String): String
        @JvmStatic external fun restoreLoginRevision(id: String, revisionId: String): String
        @JvmStatic external fun clearLoginHistory(id: String): String
        @JvmStatic external fun setLoginTotp(id: String, secret: String, clear: Boolean): String
        @JvmStatic external fun copyLoginTotpCode(id: String, masterPassword: String): String
        @JvmStatic external fun setLoginRecoveryCodes(id: String, input: String, clear: Boolean): String
        @JvmStatic external fun viewLoginRecoveryCodes(id: String, masterPassword: String): String
        @JvmStatic external fun copyLoginRecoveryCode(id: String, index: Int, masterPassword: String): String
        @JvmStatic external fun passwordHealth(): String

        @JvmStatic external fun listCards(): String
        @JvmStatic external fun cardEditorDetail(id: String): String
        @JvmStatic external fun addCard(title: String, cardholderName: String, cardNumber: String, month: Int, year: Int, securityCode: String, pin: String): String
        @JvmStatic external fun updateCard(id: String, title: String, cardholderName: String, cardNumber: String, month: Int, year: Int, securityCode: String, clearSecurityCode: Boolean, pin: String, clearPin: Boolean): String
        @JvmStatic external fun addCardComplete(title: String, cardholderName: String, cardNumber: String, month: Int, year: Int, securityCode: String, pin: String, extrasJson: String): String
        @JvmStatic external fun updateCardComplete(id: String, title: String, cardholderName: String, cardNumber: String, month: Int, year: Int, securityCode: String, clearSecurityCode: Boolean, pin: String, clearPin: Boolean, extrasJson: String): String
        @JvmStatic external fun deleteCard(id: String): String
        @JvmStatic external fun listCardTrash(): String
        @JvmStatic external fun restoreCard(trashId: String): String
        @JvmStatic external fun purgeCard(trashId: String): String
        @JvmStatic external fun emptyCardTrash(): String
        @JvmStatic external fun listCardHistory(id: String): String
        @JvmStatic external fun restoreCardRevision(id: String, revisionId: String): String
        @JvmStatic external fun clearCardHistory(id: String): String

        @JvmStatic external fun listSsh(): String
        @JvmStatic external fun sshEditorDetail(id: String): String
        @JvmStatic external fun addSsh(title: String, host: String, port: Int, username: String, password: String, publicKey: String, privateKey: String, keyPassphrase: String): String
        @JvmStatic external fun addSshComplete(title: String, host: String, port: Int, username: String, password: String, publicKey: String, privateKey: String, keyPassphrase: String, extrasJson: String): String
        @JvmStatic external fun updateSsh(id: String, title: String, host: String, port: Int, username: String, password: String, clearPassword: Boolean, publicKey: String, clearPublicKey: Boolean, privateKey: String, clearPrivateKey: Boolean, keyPassphrase: String, clearKeyPassphrase: Boolean): String
        @JvmStatic external fun updateSshComplete(id: String, title: String, host: String, port: Int, username: String, password: String, clearPassword: Boolean, publicKey: String, clearPublicKey: Boolean, privateKey: String, clearPrivateKey: Boolean, keyPassphrase: String, clearKeyPassphrase: Boolean, extrasJson: String): String
        @JvmStatic external fun deleteSsh(id: String): String
        @JvmStatic external fun listSshTrash(): String
        @JvmStatic external fun restoreSsh(trashId: String): String
        @JvmStatic external fun purgeSsh(trashId: String): String
        @JvmStatic external fun emptySshTrash(): String
        @JvmStatic external fun listSshHistory(id: String): String
        @JvmStatic external fun restoreSshRevision(id: String, revisionId: String): String
        @JvmStatic external fun clearSshHistory(id: String): String

        @JvmStatic external fun listIdentities(): String
        @JvmStatic external fun identityBasic(id: String): String
        @JvmStatic external fun identityEditorDetail(id: String): String
        @JvmStatic external fun addIdentity(title: String, firstName: String, lastName: String, organization: String): String
        @JvmStatic external fun addIdentityComplete(inputJson: String): String
        @JvmStatic external fun updateIdentity(id: String, title: String, firstName: String, lastName: String, organization: String): String
        @JvmStatic external fun updateIdentityComplete(id: String, inputJson: String): String
        @JvmStatic external fun deleteIdentity(id: String): String
        @JvmStatic external fun listIdentityTrash(): String
        @JvmStatic external fun restoreIdentity(trashId: String): String
        @JvmStatic external fun purgeIdentity(trashId: String): String
        @JvmStatic external fun emptyIdentityTrash(): String
        @JvmStatic external fun listIdentityHistory(id: String): String
        @JvmStatic external fun restoreIdentityRevision(id: String, revisionId: String): String
        @JvmStatic external fun clearIdentityHistory(id: String): String

        @JvmStatic external fun listSecrets(): String
        @JvmStatic external fun secretEditorDetail(id: String): String
        @JvmStatic external fun addSecret(title: String, kind: String, provider: String, account: String, value: String): String
        @JvmStatic external fun updateSecret(id: String, title: String, provider: String, account: String, value: String): String
        @JvmStatic external fun addSecretComplete(title: String, kind: String, provider: String, account: String, value: String, extrasJson: String): String
        @JvmStatic external fun updateSecretComplete(id: String, title: String, provider: String, account: String, value: String, extrasJson: String): String
        @JvmStatic external fun deleteSecret(id: String): String

        @JvmStatic external fun copyLoginPassword(id: String, masterPassword: String): String
        @JvmStatic external fun copyCardNumber(id: String, masterPassword: String): String
        @JvmStatic external fun copyCardSecurityCode(id: String, masterPassword: String): String
        @JvmStatic external fun copyCardPin(id: String, masterPassword: String): String
        @JvmStatic external fun copySshPassword(id: String, masterPassword: String): String
        @JvmStatic external fun copySshPublicKey(id: String, masterPassword: String): String
        @JvmStatic external fun copySshPrivateKey(id: String, masterPassword: String): String
        @JvmStatic external fun copySshKeyPassphrase(id: String, masterPassword: String): String
        @JvmStatic external fun copySecretValue(id: String, masterPassword: String): String

        fun decodeLogins(value: String): LoginListResult = runCatching {
            if (value.startsWith("{")) {
                return LoginListResult(error = JSONObject(value).optString("error", "io_error"))
            }
            val array = JSONArray(value)
            LoginListResult(
                items = buildList {
                    repeat(array.length()) { index ->
                        val item = array.getJSONObject(index)
                        add(
                            LoginSummary(
                                id = item.getString("id"),
                                title = item.getString("title"),
                                username = item.getString("username"),
                                url = if (item.isNull("url")) {
                                    null
                                } else {
                                    item.getString("url").takeIf(String::isNotEmpty)
                                },
                                hasPassword = item.getBoolean("hasPassword"),
                                hasTotpSecret = item.getBoolean("hasTotpSecret"),
                                hasRecoveryCodes = item.getBoolean("hasRecoveryCodes"),
                            ),
                        )
                    }
                },
            )
        }.getOrElse { LoginListResult(error = "io_error") }

        fun decodeTrash(value: String): TrashListResult = runCatching {
            if (value.startsWith("{")) {
                return TrashListResult(error = JSONObject(value).optString("error", "io_error"))
            }
            val array = JSONArray(value)
            TrashListResult(
                items = buildList {
                    repeat(array.length()) { index ->
                        val item = array.getJSONObject(index)
                        add(
                            TrashSummary(
                                trashId = item.getString("trashId"),
                                itemId = item.getString("itemId"),
                                title = item.getString("title"),
                                username = item.getString("username"),
                                deletedAt = item.getLong("deletedAt"),
                            ),
                        )
                    }
                },
            )
        }.getOrElse { TrashListResult(error = "io_error") }
    }
}
