package com.vaultmesh.app

import org.json.JSONObject

internal data class LanNearby(val pairingRef: String, val status: String)
internal data class LanTrusted(val pairingRef: String, val label: String, val protocolMajor: Int)
internal data class LanStatus(
    val discoverable: Boolean,
    val expiresAt: Long?,
    val pairingCode: String?,
    val nearby: List<LanNearby>,
    val trusted: List<LanTrusted>,
)

internal data class LanPanelState(
    val status: LanStatus? = null,
    val busy: Boolean = false,
    val error: String? = null,
    val pairingRef: String? = null,
    val codeInput: String = "",
    val revokeRef: String? = null,
    val renameRef: String? = null,
    val labelInput: String = "",
    val pairingPending: Boolean = false,
    val notice: String? = null,
    val noticeId: Int = 0,
)

internal fun decodeLanStatus(raw: String): LanStatus? = runCatching {
    if (raw.length > 16 * 1024) return null
    val json = JSONObject(raw)
    if (json.has("error") || json.length() != 5) return null
    val code = json.optString("pairingCode").takeIf { it.isNotEmpty() && it != "null" }
    if (code != null && !code.matches(Regex("[0-9]{6}"))) return null
    val nearby = json.getJSONArray("nearby")
    val trusted = json.getJSONArray("trusted")
    if (nearby.length() > 32 || trusted.length() > 32) return null
    LanStatus(
        discoverable = json.getBoolean("discoverable"),
        expiresAt = if (json.isNull("expiresAt")) null else json.getLong("expiresAt").takeIf { it >= 0 },
        pairingCode = code,
        nearby = List(nearby.length()) { index ->
            nearby.getJSONObject(index).let { LanNearby(it.getString("pairingRef"), it.getString("status")) }
        }.also { devices -> require(devices.all { validLanRef(it.pairingRef) && it.status.length <= 64 }) },
        trusted = List(trusted.length()) { index ->
            trusted.getJSONObject(index).let { LanTrusted(it.getString("pairingRef"), it.getString("label"), it.getInt("protocolMajor")) }
        }.also { peers -> require(peers.all {
            validLanRef(it.pairingRef) && it.label.isNotBlank() &&
                it.label.codePointCount(0, it.label.length) <= 64 &&
                it.label.toByteArray(Charsets.UTF_8).size <= 256 && it.protocolMajor in 1..2
        }) },
    )
}.getOrNull()

private fun validLanRef(ref: String): Boolean = ref.matches(Regex("lan-peer-[a-f0-9]{32}"))
internal fun shortLanRef(ref: String): String = ref.takeLast(6).uppercase()

internal fun lanStatusLabel(status: String): String = when (status) {
    "connected" -> "已验证连通"
    "connecting" -> "正在安全配对"
    "code-rejected" -> "配对码错误或认证失败"
    "code-attempts-exhausted" -> "对方尝试次数已用完"
    "identity-changed", "peer-identity-rejected" -> "设备身份已变化，请先撤销旧信任"
    "local-storage-failed", "peer-storage-failed", "persistence-sync-failed" -> "双方未能保存信任"
    "transport-failed", "secure-channel-failed", "tls-failed" -> "无法建立安全连接"
    "unverified" -> "尚未配对"
    else -> "验证未完成，请重试"
}


internal fun LanPanelState.clearAction(): LanPanelState = copy(
    pairingRef = null, codeInput = "", pairingPending = false,
    renameRef = null, labelInput = "", revokeRef = null, error = null,
)

internal fun LanPanelState.notify(message: String): LanPanelState = copy(notice = message, noticeId = noticeId + 1)

// Polls and operation responses share the same transition, so accepting a request is
// never mistaken for completing the asynchronous, mutually persisted pairing.
internal fun LanPanelState.withStatus(next: LanStatus): LanPanelState {
    val previousRefs = status?.trusted?.map { it.pairingRef }?.toSet()
    val added = previousRefs != null && next.trusted.any { it.pairingRef !in previousRefs }
    var updated = copy(status = next)
    if (added) updated = updated.notify("配对成功，已授权当前保险库同步")
    val ref = pairingRef ?: return updated
    if (next.trusted.any { it.pairingRef == ref } || !next.discoverable) {
        return updated.copy(pairingRef = null, codeInput = "", pairingPending = false, error = null)
    }
    val peer = next.nearby.firstOrNull { it.pairingRef == ref }
    return when {
        peer == null -> updated.copy(pairingRef = null, codeInput = "", pairingPending = false,
            error = "设备已离开，请重新扫描。")
        peer.status == "connecting" -> updated.copy(pairingPending = true, error = null)
        peer.status !in setOf("unverified", "connected") -> updated.copy(
            pairingPending = false, error = lanStatusLabel(peer.status))
        else -> updated
    }
}

internal fun LanPanelState.canBeginPairing(): Boolean {
    val current = status ?: return false
    val peer = current.nearby.firstOrNull { it.pairingRef == pairingRef } ?: return false
    return current.discoverable && !busy && !pairingPending && codeInput.matches(Regex("[0-9]{6}")) &&
        peer.status !in setOf("connecting", "connected", "code-attempts-exhausted", "identity-changed", "peer-identity-rejected") &&
        current.trusted.none { it.pairingRef == pairingRef }
}
