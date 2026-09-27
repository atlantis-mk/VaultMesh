package com.vaultmesh.app

import java.util.UUID

data class IdentityContactDraft(
    val id: String = UUID.randomUUID().toString(),
    val label: String = "",
    val value: String = "",
    val preferred: Boolean = false,
)

data class IdentityAddressDraft(
    val id: String = UUID.randomUUID().toString(),
    val label: String = "",
    val addressLine1: String = "",
    val addressLine2: String = "",
    val city: String = "",
    val region: String = "",
    val postalCode: String = "",
    val countryCode: String = "",
    val country: String = "",
    val preferred: Boolean = false,
)

sealed interface OtherDraft {
    val id: String?
    val title: String

    data class Card(
        override val id: String? = null,
        override val title: String = "",
        val holder: String = "",
        val number: String = "",
        val month: String = "",
        val year: String = "",
        val securityCode: String = "",
        val pin: String = "",
        val clearSecurityCode: Boolean = false,
        val clearPin: Boolean = false,
        val issuer: String = "",
        val network: String = "",
        val billingAddress: String = "",
        val notes: String = "",
        val folder: String = "",
        val favorite: Boolean = false,
        val masterPasswordReprompt: Boolean = false,
    ) : OtherDraft

    data class Ssh(
        override val id: String? = null,
        override val title: String = "",
        val host: String = "",
        val port: String = "22",
        val username: String = "",
        val password: String = "",
        val publicKey: String = "",
        val privateKey: String = "",
        val passphrase: String = "",
        val clearPassword: Boolean = false,
        val clearPublicKey: Boolean = false,
        val clearPrivateKey: Boolean = false,
        val clearPassphrase: Boolean = false,
        val notes: String = "",
        val folder: String = "",
        val favorite: Boolean = false,
        val masterPasswordReprompt: Boolean = false,
    ) : OtherDraft

    data class Identity(
        override val id: String? = null,
        override val title: String = "",
        val firstName: String = "",
        val middleName: String = "",
        val lastName: String = "",
        val birthDate: String = "",
        val emails: List<IdentityContactDraft> = emptyList(),
        val phones: List<IdentityContactDraft> = emptyList(),
        val addresses: List<IdentityAddressDraft> = emptyList(),
        val organization: String = "",
        val department: String = "",
        val jobTitle: String = "",
        val website: String = "",
        val notes: String = "",
        val folder: String = "",
        val favorite: Boolean = false,
    ) : OtherDraft

    data class Secret(
        override val id: String? = null,
        override val title: String = "",
        val kind: String = "api-key",
        val provider: String = "",
        val account: String = "",
        val value: String = "",
        val environment: String = "",
        val scopes: String = "",
        val expiresAt: String = "",
        val website: String = "",
        val notes: String = "",
        val folder: String = "",
        val favorite: Boolean = false,
        val masterPasswordReprompt: Boolean = false,
    ) : OtherDraft
}

data class OtherTarget(val section: VaultSection, val id: String, val title: String)
data class OtherTrashTarget(val section: VaultSection, val item: OtherTrashSummary)
