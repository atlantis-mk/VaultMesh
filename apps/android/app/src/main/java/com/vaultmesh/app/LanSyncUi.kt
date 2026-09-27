package com.vaultmesh.app

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date

internal data class SyncPeer(val ref: String, val enabled: Boolean, val state: String, val lastSuccess: Long?)
internal data class SyncUiState(val peers: List<SyncPeer>, val conflictCount: Int, val generation: Long)
internal fun decodeSyncStatus(raw: String): SyncUiState? = runCatching {
    require(raw.length <= 16 * 1024)
    val json = JSONObject(raw)
    val peers = json.getJSONArray("peers")
    require(peers.length() <= 32)
    SyncUiState(List(peers.length()) { i -> peers.getJSONObject(i).let {
        SyncPeer(it.getString("peerRef"), it.getBoolean("enabled"), it.getString("state"),
            if (it.isNull("lastSuccessAt")) null else it.getLong("lastSuccessAt"))
    } }, json.getInt("conflictCount"), json.getLong("generation"))
}.getOrNull()
internal data class SyncConflict(val id: String, val kind: String, val savedAt: Long)
internal fun syncStateLabel(value: String): String = when (value) {
    "synced" -> "已同步"
    "syncing" -> "正在同步"
    "waiting-unlock" -> "等待双方解锁建立通道或合并"
    "delivered" -> "密文已送达，等待对端解锁合并"
    "failed" -> "同步失败，请重试"
    "disabled" -> "自动同步已关闭"
    else -> "对端离线或等待连接"
}
@Composable
internal fun LanSyncPanel(status: SyncUiState?, serviceState: String, paused: Boolean,
    onRetry: () -> Unit, onPause: () -> Unit,
    onConflicts: () -> Unit, error: String?) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("保险库自动同步", style = MaterialTheme.typography.titleMedium)
        Text(if (paused) "同步已暂停" else serviceState, style = MaterialTheme.typography.bodySmall)
        Text("关闭扫描或离开设备页后继续同步；锁定时仅收发密文。首次连接请解锁双方保险库。", style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onRetry) { Text(if (paused) "恢复同步" else "重试同步") }
            if (!paused) TextButton(onClick = onPause) { Text("暂停同步") }
            TextButton(onClick = onConflicts) { Text("冲突历史 (${status?.conflictCount ?: 0})") }
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
    }
}
@Composable
internal fun LanSyncPeerSettings(status: SyncUiState?, device: LanTrusted, busy: Boolean,
    onEnable: (String, Boolean) -> Unit, error: String?) {
    val peer = status?.peers?.firstOrNull { it.ref == device.pairingRef }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            Text("自动同步保险库", Modifier.weight(1f))
            Switch(checked = peer?.enabled == true, enabled = status != null && !busy,
                onCheckedChange = { onEnable(device.pairingRef, it) })
        }
        Text(if (status == null) "同步状态暂不可用，请重试" else syncStateLabel(peer?.state ?: "disabled"),
            style = MaterialTheme.typography.bodySmall)
        peer?.lastSuccess?.let { Text("上次成功：${DateFormat.getDateTimeInstance().format(Date(it))}", style = MaterialTheme.typography.bodySmall) }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
    }
}
@Composable
internal fun SyncConflictDialog(conflicts: List<SyncConflict>, onRestore: (String) -> Unit, onClear: () -> Unit, onClose: () -> Unit) {
    var selected by remember { mutableStateOf<String?>(null) }
    var clearing by remember { mutableStateOf(false) }
    AlertDialog(onDismissRequest = onClose, title = { Text("加密冲突历史") }, text = {
        androidx.compose.foundation.lazy.LazyColumn {
            if (conflicts.isEmpty()) item { Text("没有冲突历史") }
            items(conflicts.size) { i ->
                val conflict = conflicts[i]
                TextButton(onClick = { selected = conflict.id }) { Text("恢复 ${conflict.kind} · ${DateFormat.getDateTimeInstance().format(Date(conflict.savedAt))}") }
            }
            if (selected != null) item { Text("确认恢复所选历史版本？这将作为新修改同步。") }
            if (clearing) item { Text("确认永久清空冲突历史？") }
        }
    }, confirmButton = {
        when { selected != null -> TextButton(onClick = { onRestore(selected!!) }) { Text("确认恢复") }
            clearing -> TextButton(onClick = onClear) { Text("确认清空") }
            conflicts.isNotEmpty() -> TextButton(onClick = { clearing = true }) { Text("清空历史") } }
    }, dismissButton = { TextButton(onClick = onClose) { Text("关闭") } })
}
