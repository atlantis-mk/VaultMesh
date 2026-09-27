package com.vaultmesh.app

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.delay

@Composable
internal fun LanDevicesPage(
    panel: LanPanelState,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onRefresh: () -> Unit,
    onReload: () -> Unit,
    onSelectPair: (String) -> Unit,
    onCodeChange: (String) -> Unit,
    onBegin: () -> Unit,
    onSelectRevoke: (String) -> Unit,
    onRevoke: () -> Unit,
    onSelectRename: (String, String) -> Unit,
    onLabelChange: (String) -> Unit,
    onRename: () -> Unit,
    onCancelAction: () -> Unit,
    modifier: Modifier = Modifier,
    syncContent: @Composable () -> Unit = {},
    deviceSettings: @Composable (LanTrusted) -> Unit = {},
) {
    val status = panel.status
    var settingsRef by remember { mutableStateOf<String?>(null) }
    val settingsPeer = status?.trusted?.firstOrNull { it.pairingRef == settingsRef }
    LaunchedEffect(settingsRef, settingsPeer?.pairingRef) {
        if (settingsPeer == null) settingsRef = null
    }
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(panel.noticeId) {
        panel.notice?.let { snackbar.showSnackbar(it) }
    }
    val hasDialog = panel.pairingRef != null || panel.renameRef != null || panel.revokeRef != null
    Box(modifier = modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("已配对设备", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    if (status != null && status.trusted.isNotEmpty()) {
                        Surface(shape = CircleShape, color = MaterialTheme.colorScheme.surfaceVariant) {
                            Text(status.trusted.size.toString(), Modifier.padding(horizontal = 10.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelMedium)
                        }
                    }
                }
                when {
                    status == null -> Column(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 48.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        if (panel.error == null) {
                            CircularProgressIndicator(modifier = Modifier.size(40.dp))
                            Text("正在读取已配对设备…", color = MaterialTheme.colorScheme.onSurfaceVariant)
                        } else {
                            LanIcon(R.drawable.ic_lan_error_outline, Modifier.size(32.dp), error = true)
                            Text("暂时无法读取设备列表", style = MaterialTheme.typography.titleMedium)
                            Text(panel.error, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            OutlinedButton(onClick = onReload, enabled = !panel.busy) {
                                LanIcon(R.drawable.ic_lan_refresh)
                                Spacer(Modifier.width(8.dp))
                                Text("重新加载")
                            }
                        }
                    }
                    status.trusted.isEmpty() -> Column(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 40.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        LanIcon(R.drawable.ic_lan_devices_other, Modifier.size(64.dp), muted = true)
                        Text("还没有已配对设备", style = MaterialTheme.typography.titleMedium)
                        Text("开启发现，配对你的第一台设备", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    else -> status.trusted.forEachIndexed { index, peer ->
                        if (index > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                        TrustedDeviceRow(peer, status.nearby.firstOrNull { it.pairingRef == peer.pairingRef }?.status,
                            panel.busy) { settingsRef = peer.pairingRef }
                    }
                }
            }
            syncContent()
            DiscoveryPanel(panel, if (hasDialog) null else panel.error, onStart, onStop)
            if (status?.discoverable == true) {
                val nearby = status.nearby.filter { device -> status.trusted.none { it.pairingRef == device.pairingRef } }
                Column {
                    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text("附近设备", Modifier.weight(1f), style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold)
                        FilledTonalButton(onClick = onRefresh, enabled = !panel.busy,
                            colors = ButtonDefaults.filledTonalButtonColors(containerColor = MaterialTheme.colorScheme.primaryContainer,
                                contentColor = MaterialTheme.colorScheme.primary)) {
                            LanIcon(R.drawable.ic_lan_refresh)
                            Spacer(Modifier.width(6.dp))
                            Text("扫描")
                        }
                    }
                    if (nearby.isEmpty()) {
                        Text("暂无待配对设备", Modifier.padding(top = 16.dp), style = MaterialTheme.typography.titleSmall)
                        Text("请在另一台设备开启发现", Modifier.padding(top = 6.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    nearby.forEachIndexed { index, device ->
                        if (index > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                        Row(modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                            LanIcon(R.drawable.ic_nav_devices, Modifier.size(28.dp))
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text("VaultMesh ${shortLanRef(device.pairingRef)}", style = MaterialTheme.typography.titleSmall)
                                Text(lanStatusLabel(device.status), style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            if (device.status == "connecting") CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
                            else if (device.status !in setOf("connected", "code-attempts-exhausted", "identity-changed", "peer-identity-rejected")) {
                                FilledTonalButton(onClick = { onSelectPair(device.pairingRef) }, enabled = !panel.busy,
                                    colors = ButtonDefaults.filledTonalButtonColors(containerColor = MaterialTheme.colorScheme.primaryContainer,
                                        contentColor = MaterialTheme.colorScheme.primary)) { Text("配对") }
                            }
                        }
                    }
                    Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        LanIcon(R.drawable.ic_lan_info, Modifier.size(18.dp), muted = true)
                        Text("配对后将授权当前保险库同步", style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).padding(16.dp))
    }
    if (settingsPeer != null && !hasDialog) {
        key(settingsPeer.pairingRef) {
            AlertDialog(
                onDismissRequest = { settingsRef = null },
                title = { Column { Text("设备设置"); Text(settingsPeer.label, style = MaterialTheme.typography.titleSmall) } },
                text = {
                    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        deviceSettings(settingsPeer)
                        HorizontalDivider()
                        TextButton(onClick = {
                            settingsRef = null
                            onSelectRename(settingsPeer.pairingRef, settingsPeer.label)
                        }, enabled = !panel.busy) { Text("重命名") }
                        TextButton(onClick = {
                            settingsRef = null
                            onSelectRevoke(settingsPeer.pairingRef)
                        }, enabled = !panel.busy, colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)) {
                            Text("撤销配对")
                        }
                    }
                },
                confirmButton = { TextButton(onClick = { settingsRef = null }) { Text("完成") } },
            )
        }
    }
    if (panel.pairingRef != null) {
        val pending = panel.busy || panel.pairingPending
        AlertDialog(
            containerColor = MaterialTheme.colorScheme.surface,
            onDismissRequest = { if (!pending) onCancelAction() },
            properties = DialogProperties(dismissOnBackPress = !pending, dismissOnClickOutside = !pending),
            title = { Text("输入配对码") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text("输入 VaultMesh ${shortLanRef(panel.pairingRef)} 上显示的六位数字")
                    OutlinedTextField(value = panel.codeInput, onValueChange = onCodeChange,
                        modifier = Modifier.fillMaxWidth(), label = { Text("六位配对码") }, singleLine = true,
                        enabled = !pending, isError = panel.error != null,
                        textStyle = MaterialTheme.typography.headlineSmall.copy(letterSpacing = 4.sp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    panel.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                    if (pending) Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                        Text("正在安全配对…")
                    }
                    Text("配对成功后，将授权当前保险库同步", style = MaterialTheme.typography.bodySmall)
                }
            },
            dismissButton = {
                TextButton(onClick = if (panel.pairingPending) onStop else onCancelAction, enabled = !panel.busy) {
                    Text(if (panel.pairingPending) "停止配对" else "取消")
                }
            },
            confirmButton = {
                Button(onClick = onBegin, enabled = panel.canBeginPairing()) {
                    Text(if (panel.error == null) "开始配对" else "重试")
                }
            },
        )
    }
    if (panel.renameRef != null) {
        AlertDialog(
            containerColor = MaterialTheme.colorScheme.surface,
            onDismissRequest = { if (!panel.busy) onCancelAction() },
            title = { Text("重命名设备") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(value = panel.labelInput, onValueChange = onLabelChange,
                        modifier = Modifier.fillMaxWidth(), label = { Text("设备名称") }, singleLine = true,
                        enabled = !panel.busy, supportingText = { Text("${panel.labelInput.length}/64") })
                    panel.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                }
            },
            dismissButton = { TextButton(onClick = onCancelAction, enabled = !panel.busy) { Text("取消") } },
            confirmButton = { Button(onClick = onRename, enabled = !panel.busy && panel.labelInput.isNotBlank() && panel.labelInput.length <= 64) {
                if (panel.busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                else Text("保存")
            } },
        )
    }
    if (panel.revokeRef != null) {
        AlertDialog(
            containerColor = MaterialTheme.colorScheme.surface,
            onDismissRequest = { if (!panel.busy) onCancelAction() },
            icon = { LanIcon(R.drawable.ic_lan_link_off, Modifier.size(36.dp)) },
            title = { Text("撤销与此设备的配对？") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(status?.trusted?.firstOrNull { it.pairingRef == panel.revokeRef }?.label ?: "所选设备",
                        style = MaterialTheme.typography.titleMedium)
                    Text("将移除此设备的信任和当前保险库同步授权。再次连接需要重新配对。")
                    panel.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                }
            },
            dismissButton = { TextButton(onClick = onCancelAction, enabled = !panel.busy) { Text("取消") } },
            confirmButton = { TextButton(onClick = onRevoke, enabled = !panel.busy,
                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)) {
                if (panel.busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                else Text("撤销配对")
            } },
        )
    }
}

@Composable
private fun TrustedDeviceRow(peer: LanTrusted, connection: String?, busy: Boolean,
    onSettings: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 12.dp), verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)) {
        LanIcon(R.drawable.ic_nav_devices, Modifier.size(28.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(peer.label, style = MaterialTheme.typography.titleMedium)
            Text(if (connection != null && connection != "unverified") lanStatusLabel(connection) else "已配对",
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        IconButton(onClick = onSettings, enabled = !busy) {
            Icon(painterResource(R.drawable.ic_lan_more_vert), contentDescription = "${peer.label}的更多操作")
        }
    }
}

@Composable
private fun DiscoveryPanel(panel: LanPanelState, pageError: String?, onStart: () -> Unit, onStop: () -> Unit) {
    val status = panel.status
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(status?.discoverable) {
        while (status?.discoverable == true) { now = System.currentTimeMillis(); delay(1_000) }
    }
    Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.6f)) {
        Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp), verticalAlignment = Alignment.Top) {
                Box(Modifier.size(56.dp).background(MaterialTheme.colorScheme.primaryContainer, CircleShape), contentAlignment = Alignment.Center) {
                    Icon(painterResource(R.drawable.ic_lan_wifi_tethering), null, Modifier.size(30.dp), tint = MaterialTheme.colorScheme.primary)
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(if (status?.discoverable == true) "本机配对码" else "配对新设备", style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold)
                    if (status?.discoverable == true) {
                        Text(status.pairingCode?.chunked(3)?.joinToString(" ") ?: "尝试次数已用完",
                            style = if (status.pairingCode != null) MaterialTheme.typography.headlineLarge else MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                        status.expiresAt?.let {
                            val remaining = ((it - now).coerceAtLeast(0) / 1000)
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                                LanIcon(R.drawable.ic_lan_schedule, Modifier.size(18.dp), muted = true)
                                Text("剩余 ${remaining / 60}:${(remaining % 60).toString().padStart(2, '0')}", style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                        Text(if (status.pairingCode == null) "请停止后重新开启发现" else "在另一台设备输入此码",
                            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        Text(if (status == null) "列表读取完成后可开启发现" else "与同一局域网中的设备安全配对",
                            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (status != null) Text("发现已关闭", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            if (status != null && pageError != null) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    LanIcon(R.drawable.ic_lan_error_outline, Modifier.size(20.dp), error = true)
                    Text(pageError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                }
            }
            if (status?.discoverable == true) {
                OutlinedButton(onClick = onStop, enabled = !panel.busy,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.primary),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = if (panel.busy) 0.3f else 0.7f)),
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp), shape = RoundedCornerShape(16.dp)) { Text("停止发现") }
            } else Button(onClick = onStart, enabled = status != null && !panel.busy,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp), shape = RoundedCornerShape(16.dp)) {
                if (panel.busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                else Text(if (pageError != null && status != null) "重试开启" else "开启发现")
            }
            Text("每次最多 10 分钟，离开页面即停止", Modifier.fillMaxWidth(), textAlign = TextAlign.Center,
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun LanIcon(resource: Int, modifier: Modifier = Modifier.size(24.dp), error: Boolean = false, muted: Boolean = false) {
    Icon(painterResource(resource), contentDescription = null, modifier = modifier,
        tint = when { error -> MaterialTheme.colorScheme.error; muted -> MaterialTheme.colorScheme.onSurfaceVariant; else -> LocalContentColor.current })
}
