package com.vaultmesh.app

import android.Manifest
import android.app.Application
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.*
import org.json.JSONObject

@Composable
internal fun DeviceAssistPanel(peers: List<LanTrusted>, settingsPeer: LanTrusted? = null) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf<JSONObject?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var serviceState by remember { mutableStateOf(DeviceAssistService.state) }
    var busy by remember { mutableStateOf(false) }
    var serviceEnabled by remember { mutableStateOf(DeviceAssistService.enabled(context)) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { }
    suspend fun open(): Boolean = withContext(Dispatchers.IO) {
        val key = LanPairingKeyService(context.applicationContext as Application).readOrCreate() ?: return@withContext false
        try { VaultNativeBridge.assistOpen(key) == "ok" } finally { key.fill(0) }
    }
    LaunchedEffect(peers.map { it.pairingRef }) {
        if (!open()) { error = "无法读取互通设置，请重新解锁"; return@LaunchedEffect }
        while (isActive) {
            status = withContext(Dispatchers.IO) { runCatching { JSONObject(VaultNativeBridge.assistStatus()) }.getOrNull() }
            serviceState = DeviceAssistService.state
            serviceEnabled = DeviceAssistService.enabled(context)
            delay(1000)
        }
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("设备填充互通", style = MaterialTheme.typography.titleMedium)
        if (settingsPeer != null) {
            Text("开启后，号码会加密注册到电脑，手机离线也可填入；换号或撤销在下次连通时更新。验证码推送到各授权电脑内存，两分钟内各可使用一次；只在电脑点选时填入。", style = MaterialTheme.typography.bodySmall)
            val peer = settingsPeer
            val grants = status?.optJSONArray("grants")
            val grant = grants?.let { a -> (0 until a.length()).map { a.getJSONObject(it) }.firstOrNull { it.optString("peer") == peer.pairingRef } }
            val phone = grant?.optBoolean("phone") == true
            val sms = grant?.optBoolean("sms") == true
            fun change(nextPhone: Boolean, nextSms: Boolean) {
                busy = true
                scope.launch {
                    val result = withContext(Dispatchers.IO) { VaultNativeBridge.assistGrant(peer.pairingRef, nextPhone, nextSms) }
                    error = if (result == "ok") null else "授权未保存，请重新解锁后重试"
                    status = withContext(Dispatchers.IO) { runCatching { JSONObject(VaultNativeBridge.assistStatus()) }.getOrNull() }
                    busy = false
                    if (result == "ok" && nextSms && !sms) permission.launch(arrayOf(Manifest.permission.RECEIVE_SMS))
                }
            }
            Row { Text("向此电脑提供手机号码", Modifier.weight(1f)); Switch(phone, { change(it, sms) }, enabled = !busy && status?.has("grants") == true) }
            Row { Text("向此电脑提供短信验证码", Modifier.weight(1f)); Switch(sms, { change(phone, it) }, enabled = !busy && status?.has("grants") == true) }
        }
        if (settingsPeer == null) {
            Text(serviceState, style = MaterialTheme.typography.bodySmall)
            Text("在设备条目的更多操作中设置同步与填充授权。", style = MaterialTheme.typography.bodySmall)
            if ((status?.optJSONArray("requests")?.length() ?: 0) > 0) {
                Text("有待处理的填充请求，可在对应设备设置中手动输入验证码。", style = MaterialTheme.typography.bodySmall)
            }
            if (Build.VERSION.SDK_INT >= 37) Text("此系统可能延迟验证码交付；收不到时可在设备设置中手动输入。", style = MaterialTheme.typography.bodySmall)
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            DeviceAssistSwitch(serviceEnabled, !busy && status?.has("grants") == true) { value ->
                if (DeviceAssistService.setEnabled(context, value)) {
                    serviceEnabled = value
                    error = null
                    if (value) {
                        val needed = buildList {
                            if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) add(Manifest.permission.POST_NOTIFICATIONS)
                            if (Build.VERSION.SDK_INT >= 37 && context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) != android.content.pm.PackageManager.PERMISSION_GRANTED) add(Manifest.permission.ACCESS_LOCAL_NETWORK)
                        }
                        if (needed.isNotEmpty()) permission.launch(needed.toTypedArray())
                        else DeviceAssistService.startIfEnabled(context)
                    }
                } else error = "无法保存互通开关，请重试"
            }
            Text("开关会保存。开启后锁屏、关闭应用仍可互通；系统允许时自动恢复，通知中可随时关闭。", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (serviceEnabled && Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    TextButton(onClick = { permission.launch(arrayOf(Manifest.permission.POST_NOTIFICATIONS)) }) { Text("通知权限") }
                }
                if (serviceEnabled && Build.VERSION.SDK_INT >= 37 && context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    TextButton(onClick = { permission.launch(arrayOf(Manifest.permission.ACCESS_LOCAL_NETWORK)) }) { Text("本地网络权限") }
                }
                TextButton(onClick = { permission.launch(arrayOf(Manifest.permission.RECEIVE_SMS)) }) { Text("短信权限") }
            }
        } else error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        val requests = if (settingsPeer != null) status?.optJSONArray("requests") else null
        if (requests != null) for (i in 0 until requests.length()) {
            val request = requests.getJSONObject(i)
            if (request.optString("peer") != settingsPeer?.pairingRef) continue
            key(request.optString("id")) {
                var code by remember { mutableStateOf("") }
                val peer = peers.firstOrNull { it.pairingRef == request.optString("peer") }
                Text("${peer?.label ?: "已配对电脑"} · ${request.optString("origin")}", style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(code, { code = it.filter(Char::isLetterOrDigit).take(10) }, label = { Text("手动输入或粘贴验证码") }, singleLine = true)
                Button(enabled = code.length in 4..10 && !busy, onClick = {
                    val value = code; code = ""; busy = true
                    scope.launch {
                        val result = withContext(Dispatchers.IO) { VaultNativeBridge.assistCode(value, "手动输入", 0, java.util.UUID.randomUUID().toString(), request.getString("id")) }
                        error = if (result == "ok") null else "请求已失效，请在电脑重新打开候选"
                        busy = false
                    }
                }) { Text("交付到此请求") }
            }
        }
    }
}

@Composable
internal fun DeviceAssistSwitch(checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        Text("保持设备互通", Modifier.weight(1f))
        Switch(checked = checked, enabled = enabled || checked, onCheckedChange = onChange)
    }
}
