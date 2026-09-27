package com.vaultmesh.app

import org.json.JSONArray
import org.json.JSONObject

data class AndroidListResult<T>(
    val items: List<T> = emptyList(),
    val error: String? = null,
)

data class CardSummary(
    val id: String,
    val title: String,
    val cardholderName: String,
    val maskedNumber: String,
    val expirationMonth: Int,
    val expirationYear: Int,
    val hasSecurityCode: Boolean,
    val hasPin: Boolean,
)

data class CardExtras(
    val issuer: String = "",
    val network: String = "",
    val billingAddress: String = "",
    val notes: String = "",
    val folder: String = "",
    val favorite: Boolean = false,
    val masterPasswordReprompt: Boolean = false,
)

data class CardExtrasResult(val item: CardExtras? = null, val error: String? = null)

data class LoginExtras(
    val notes: String = "",
    val folder: String = "",
    val favorite: Boolean = false,
    val additionalUrls: List<String> = emptyList(),
    val autofillOnPageLoad: Boolean = true,
    val masterPasswordReprompt: Boolean = false,
    val customFields: List<LoginCustomFieldDraft> = emptyList(),
)

data class LoginExtrasResult(val item: LoginExtras? = null, val error: String? = null)

data class SshSummary(
    val id: String,
    val title: String,
    val host: String?,
    val port: Int,
    val username: String,
    val hasPassword: Boolean,
    val hasPublicKey: Boolean,
    val hasPrivateKey: Boolean,
    val hasKeyPassphrase: Boolean,
    val managed: Boolean,
)

data class SshExtras(
    val notes: String = "",
    val folder: String = "",
    val favorite: Boolean = false,
    val masterPasswordReprompt: Boolean = false,
)

data class SshExtrasResult(val item: SshExtras? = null, val error: String? = null)

data class IdentitySummary(
    val id: String,
    val title: String,
    val displayName: String?,
    val organization: String?,
)

data class IdentityBasic(
    val title: String,
    val firstName: String,
    val lastName: String,
    val organization: String,
)

data class IdentityBasicResult(
    val item: IdentityBasic? = null,
    val error: String? = null,
)

data class IdentityCompleteResult(
    val item: OtherDraft.Identity? = null,
    val error: String? = null,
)

data class SecretSummary(
    val id: String,
    val title: String,
    val kind: String,
    val provider: String?,
    val account: String?,
)

data class SecretExtras(
    val environment: String = "",
    val scopes: List<String> = emptyList(),
    val expiresAt: String = "",
    val website: String = "",
    val notes: String = "",
    val folder: String = "",
    val favorite: Boolean = false,
    val masterPasswordReprompt: Boolean = false,
)

data class SecretExtrasResult(val item: SecretExtras? = null, val error: String? = null)

data class OtherTrashSummary(
    val trashId: String,
    val itemId: String,
    val title: String,
    val subtitle: String,
    val deletedAt: Long,
)

data class HistorySummary(
    val revisionId: String,
    val title: String,
    val subtitle: String?,
    val savedAt: Long,
)

data class PasswordHealth(
    val score: Int,
    val weakItemIds: Set<String>,
    val reusedItemIds: Set<String>,
    val oldItemIds: Set<String>,
)

data class PasswordHealthResult(val report: PasswordHealth? = null, val error: String? = null)

object AndroidItemDtos {
    private fun JSONObject.nullable(name: String): String? =
        if (isNull(name)) null else getString(name)

    private fun <T> decode(value: String, parse: (JSONObject) -> T): AndroidListResult<T> =
        runCatching {
            if (value.startsWith("{")) {
                AndroidListResult(error = JSONObject(value).optString("error", "io_error"))
            } else {
                val array = JSONArray(value)
                AndroidListResult(items = buildList {
                    repeat(array.length()) { index -> add(parse(array.getJSONObject(index))) }
                })
            }
        }.getOrElse { AndroidListResult(error = "io_error") }

    fun loginExtras(value: String): LoginExtrasResult = runCatching {
        val item = JSONObject(value)
        if (item.has("error")) LoginExtrasResult(error = item.getString("error"))
        else {
            val urls = item.getJSONArray("additionalUrls")
            val fields = item.getJSONArray("customFields")
            LoginExtrasResult(item = LoginExtras(
                notes = item.nullable("notes").orEmpty(),
                folder = item.nullable("folder").orEmpty(),
                favorite = item.getBoolean("favorite"),
                additionalUrls = List(urls.length()) { index -> urls.getString(index) },
                autofillOnPageLoad = item.getBoolean("autofillOnPageLoad"),
                masterPasswordReprompt = item.getBoolean("masterPasswordReprompt"),
                customFields = List(fields.length()) { index -> fields.getJSONObject(index).let { field ->
                    LoginCustomFieldDraft(field.getString("label"), field.getString("value"))
                } },
            ))
        }
    }.getOrElse { LoginExtrasResult(error = "io_error") }

    fun loginExtrasJson(draft: LoginDraft): String = JSONObject().apply {
        put("notes", if (draft.notes.isEmpty()) JSONObject.NULL else draft.notes)
        put("folder", if (draft.folder.isEmpty()) JSONObject.NULL else draft.folder)
        put("favorite", draft.favorite)
        put("additionalUrls", JSONArray().apply { draft.additionalUrls.forEach { value -> put(value) } })
        put("autofillOnPageLoad", draft.autofillOnPageLoad)
        put("masterPasswordReprompt", draft.masterPasswordReprompt)
        put("customFields", JSONArray().apply { draft.customFields.forEach { field ->
            put(JSONObject().apply { put("label", field.label); put("value", field.value) })
        } })
    }.toString()

    fun cards(value: String): AndroidListResult<CardSummary> = decode(value) { item ->
        CardSummary(
            id = item.getString("id"),
            title = item.getString("title"),
            cardholderName = item.getString("cardholderName"),
            maskedNumber = item.getString("maskedNumber"),
            expirationMonth = item.getInt("expirationMonth"),
            expirationYear = item.getInt("expirationYear"),
            hasSecurityCode = item.getBoolean("hasSecurityCode"),
            hasPin = item.getBoolean("hasPin"),
        )
    }

    fun cardExtras(value: String): CardExtrasResult = runCatching {
        val item = JSONObject(value)
        if (item.has("error")) CardExtrasResult(error = item.getString("error"))
        else CardExtrasResult(item = CardExtras(
            issuer = item.nullable("issuer").orEmpty(),
            network = item.nullable("network").orEmpty(),
            billingAddress = item.nullable("billingAddress").orEmpty(),
            notes = item.nullable("notes").orEmpty(),
            folder = item.nullable("folder").orEmpty(),
            favorite = item.getBoolean("favorite"),
            masterPasswordReprompt = item.getBoolean("masterPasswordReprompt"),
        ))
    }.getOrElse { CardExtrasResult(error = "io_error") }

    fun cardExtrasJson(draft: OtherDraft.Card): String = JSONObject().apply {
        fun putOptional(name: String, value: String) {
            put(name, if (value.isEmpty()) JSONObject.NULL else value)
        }
        putOptional("issuer", draft.issuer)
        putOptional("network", draft.network)
        putOptional("billingAddress", draft.billingAddress)
        putOptional("notes", draft.notes)
        putOptional("folder", draft.folder)
        put("favorite", draft.favorite)
        put("masterPasswordReprompt", draft.masterPasswordReprompt)
    }.toString()

    fun ssh(value: String): AndroidListResult<SshSummary> = decode(value) { item ->
        SshSummary(
            id = item.getString("id"),
            title = item.getString("title"),
            host = item.nullable("host"),
            port = item.getInt("port"),
            username = item.getString("username"),
            hasPassword = item.getBoolean("hasPassword"),
            hasPublicKey = item.getBoolean("hasPublicKey"),
            hasPrivateKey = item.getBoolean("hasPrivateKey"),
            hasKeyPassphrase = item.getBoolean("hasKeyPassphrase"),
            managed = item.getBoolean("managed"),
        )
    }

    fun sshExtras(value: String): SshExtrasResult = runCatching {
        val item = JSONObject(value)
        if (item.has("error")) SshExtrasResult(error = item.getString("error"))
        else SshExtrasResult(item = SshExtras(
            notes = item.nullable("notes").orEmpty(),
            folder = item.nullable("folder").orEmpty(),
            favorite = item.getBoolean("favorite"),
            masterPasswordReprompt = item.getBoolean("masterPasswordReprompt"),
        ))
    }.getOrElse { SshExtrasResult(error = "io_error") }

    fun sshExtrasJson(draft: OtherDraft.Ssh): String = JSONObject().apply {
        put("notes", if (draft.notes.isEmpty()) JSONObject.NULL else draft.notes)
        put("folder", if (draft.folder.isEmpty()) JSONObject.NULL else draft.folder)
        put("favorite", draft.favorite)
        put("masterPasswordReprompt", draft.masterPasswordReprompt)
    }.toString()

    fun identities(value: String): AndroidListResult<IdentitySummary> = decode(value) { item ->
        IdentitySummary(
            id = item.getString("id"),
            title = item.getString("title"),
            displayName = item.nullable("displayName"),
            organization = item.nullable("organization"),
        )
    }

    fun identityBasic(value: String): IdentityBasicResult = runCatching {
        val item = JSONObject(value)
        if (item.has("error")) {
            IdentityBasicResult(error = item.optString("error", "io_error"))
        } else {
            IdentityBasicResult(item = IdentityBasic(
                title = item.getString("title"),
                firstName = item.nullable("firstName").orEmpty(),
                lastName = item.nullable("lastName").orEmpty(),
                organization = item.nullable("organization").orEmpty(),
            ))
        }
    }.getOrElse { IdentityBasicResult(error = "io_error") }

    fun identityComplete(value: String, id: String): IdentityCompleteResult = runCatching {
        val item = JSONObject(value)
        if (item.has("error")) IdentityCompleteResult(error = item.getString("error"))
        else {
            fun contacts(name: String): List<IdentityContactDraft> = item.getJSONArray(name).let { array ->
                List(array.length()) { index -> array.getJSONObject(index).let { entry ->
                    IdentityContactDraft(
                        id = entry.getString("id"), label = entry.getString("label"),
                        value = entry.getString("value"), preferred = entry.getBoolean("preferred"),
                    )
                } }
            }
            val addresses = item.getJSONArray("addresses").let { array ->
                List(array.length()) { index -> array.getJSONObject(index).let { entry ->
                    IdentityAddressDraft(
                        id = entry.getString("id"), label = entry.getString("label"),
                        addressLine1 = entry.getString("addressLine1"),
                        addressLine2 = entry.nullable("addressLine2").orEmpty(),
                        city = entry.nullable("city").orEmpty(),
                        region = entry.nullable("region").orEmpty(),
                        postalCode = entry.nullable("postalCode").orEmpty(),
                        countryCode = entry.nullable("countryCode").orEmpty(),
                        country = entry.nullable("country").orEmpty(),
                        preferred = entry.getBoolean("preferred"),
                    )
                } }
            }
            IdentityCompleteResult(item = OtherDraft.Identity(
                id = id, title = item.getString("title"),
                firstName = item.nullable("firstName").orEmpty(),
                middleName = item.nullable("middleName").orEmpty(),
                lastName = item.nullable("lastName").orEmpty(),
                birthDate = item.nullable("birthDate").orEmpty(),
                emails = contacts("emails"), phones = contacts("phones"), addresses = addresses,
                organization = item.nullable("organization").orEmpty(),
                department = item.nullable("department").orEmpty(),
                jobTitle = item.nullable("jobTitle").orEmpty(),
                website = item.nullable("website").orEmpty(),
                notes = item.nullable("notes").orEmpty(),
                folder = item.nullable("folder").orEmpty(),
                favorite = item.getBoolean("favorite"),
            ))
        }
    }.getOrElse { IdentityCompleteResult(error = "io_error") }

    fun identityCompleteJson(draft: OtherDraft.Identity): String = JSONObject().apply {
        fun putOptional(name: String, value: String) {
            put(name, if (value.isEmpty()) JSONObject.NULL else value)
        }
        put("title", draft.title)
        putOptional("firstName", draft.firstName)
        putOptional("middleName", draft.middleName)
        putOptional("lastName", draft.lastName)
        putOptional("birthDate", draft.birthDate)
        fun contacts(entries: List<IdentityContactDraft>): JSONArray = JSONArray().apply {
            entries.forEach { entry -> put(JSONObject().apply {
                put("id", entry.id); put("label", entry.label); put("value", entry.value)
                put("preferred", entry.preferred)
            }) }
        }
        put("emails", contacts(draft.emails))
        put("phones", contacts(draft.phones))
        put("addresses", JSONArray().apply {
            draft.addresses.forEach { entry -> put(JSONObject().apply {
                put("id", entry.id); put("label", entry.label)
                put("addressLine1", entry.addressLine1)
                put("addressLine2", if (entry.addressLine2.isEmpty()) JSONObject.NULL else entry.addressLine2)
                put("city", if (entry.city.isEmpty()) JSONObject.NULL else entry.city)
                put("region", if (entry.region.isEmpty()) JSONObject.NULL else entry.region)
                put("postalCode", if (entry.postalCode.isEmpty()) JSONObject.NULL else entry.postalCode)
                put("countryCode", if (entry.countryCode.isEmpty()) JSONObject.NULL else entry.countryCode)
                put("country", if (entry.country.isEmpty()) JSONObject.NULL else entry.country)
                put("preferred", entry.preferred)
            }) }
        })
        putOptional("organization", draft.organization)
        putOptional("department", draft.department)
        putOptional("jobTitle", draft.jobTitle)
        putOptional("website", draft.website)
        putOptional("notes", draft.notes)
        putOptional("folder", draft.folder)
        put("favorite", draft.favorite)
    }.toString()

    fun secrets(value: String): AndroidListResult<SecretSummary> = decode(value) { item ->
        SecretSummary(
            id = item.getString("id"),
            title = item.getString("title"),
            kind = item.getString("kind"),
            provider = item.nullable("provider"),
            account = item.nullable("account"),
        )
    }

    fun secretExtras(value: String): SecretExtrasResult = runCatching {
        val item = JSONObject(value)
        if (item.has("error")) SecretExtrasResult(error = item.getString("error"))
        else {
            val scopes = item.getJSONArray("scopes")
            SecretExtrasResult(item = SecretExtras(
                environment = item.nullable("environment").orEmpty(),
                scopes = List(scopes.length()) { index -> scopes.getString(index) },
                expiresAt = item.nullable("expiresAt").orEmpty(),
                website = item.nullable("website").orEmpty(),
                notes = item.nullable("notes").orEmpty(),
                folder = item.nullable("folder").orEmpty(),
                favorite = item.getBoolean("favorite"),
                masterPasswordReprompt = item.getBoolean("masterPasswordReprompt"),
            ))
        }
    }.getOrElse { SecretExtrasResult(error = "io_error") }

    fun secretExtrasJson(draft: OtherDraft.Secret): String = JSONObject().apply {
        fun putOptional(name: String, value: String) {
            put(name, if (value.isEmpty()) JSONObject.NULL else value)
        }
        putOptional("environment", draft.environment)
        put("scopes", JSONArray(draft.scopes.lines().filter { it.isNotBlank() }))
        putOptional("expiresAt", draft.expiresAt)
        putOptional("website", draft.website)
        putOptional("notes", draft.notes)
        putOptional("folder", draft.folder)
        put("favorite", draft.favorite)
        put("masterPasswordReprompt", draft.masterPasswordReprompt)
    }.toString()

    fun trash(value: String): AndroidListResult<OtherTrashSummary> = decode(value) { item ->
        OtherTrashSummary(
            trashId = item.getString("trashId"),
            itemId = item.getString("itemId"),
            title = item.getString("title"),
            subtitle = item.getString("subtitle"),
            deletedAt = item.getLong("deletedAt"),
        )
    }

    fun history(value: String): AndroidListResult<HistorySummary> = decode(value) { item ->
        HistorySummary(
            revisionId = item.getString("revisionId"),
            title = item.getString("title"),
            subtitle = item.nullable("subtitle"),
            savedAt = item.getLong("savedAt"),
        )
    }

    fun passwordHealth(value: String): PasswordHealthResult = runCatching {
        val item = JSONObject(value)
        if (item.has("error")) PasswordHealthResult(error = item.optString("error", "io_error"))
        else {
            fun ids(name: String): Set<String> = item.getJSONArray(name).let { array ->
                buildSet { repeat(array.length()) { index -> add(array.getString(index)) } }
            }
            PasswordHealthResult(report = PasswordHealth(
                score = item.getInt("score"),
                weakItemIds = ids("weakItemIds"),
                reusedItemIds = ids("reusedItemIds"),
                oldItemIds = ids("oldItemIds"),
            ))
        }
    }.getOrElse { PasswordHealthResult(error = "io_error") }
}
