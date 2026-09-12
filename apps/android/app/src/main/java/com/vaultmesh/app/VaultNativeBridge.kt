package com.vaultmesh.app

import org.json.JSONArray
import org.json.JSONObject

data class LoginSummary(
    val id: String,
    val title: String,
    val username: String,
    val url: String?,
    val hasPassword: Boolean,
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
        @JvmStatic external fun status(): String
        @JvmStatic external fun create(masterPassword: String): String
        @JvmStatic external fun unlock(masterPassword: String): String
        @JvmStatic external fun lock(): String
        @JvmStatic external fun listLogins(): String
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

        @JvmStatic external fun deleteLogin(id: String): String
        @JvmStatic external fun listTrash(): String
        @JvmStatic external fun restoreLogin(trashId: String): String
        @JvmStatic external fun purgeLogin(trashId: String): String
        @JvmStatic external fun emptyTrash(): String

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
