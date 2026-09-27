package com.vaultmesh.app

import android.widget.Toast
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** 前台恢复时按 24 小时节流自动检查；不涉及 Vault 状态，锁定页同样可提示。 */
@Composable
internal fun AndroidUpdateAutoCheck() {
    val context = LocalContext.current
    val checker = remember { AndroidUpdateChecker(context.applicationContext) }
    if (!checker.available) return
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val scope = rememberCoroutineScope()
    var offer by remember { mutableStateOf<AndroidUpdateOffer?>(null) }
    var checking by remember { mutableStateOf(false) }
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME && !checking && offer == null && checker.autoCheckDue()) {
                checking = true
                scope.launch {
                    val result = withContext(Dispatchers.IO) { checker.check(manual = false) }
                    checking = false
                    if (result is AndroidUpdateResult.Available) offer = result.offer
                }
            }
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    offer?.let { current -> AndroidUpdateDialog(current, checker) { offer = null } }
}

@Composable
internal fun UpdateSettingsCard() {
    val context = LocalContext.current
    val checker = remember { AndroidUpdateChecker(context.applicationContext) }
    if (!checker.available) return
    val scope = rememberCoroutineScope()
    var autoCheck by remember { mutableStateOf(checker.autoCheckEnabled) }
    var checking by remember { mutableStateOf(false) }
    var offer by remember { mutableStateOf<AndroidUpdateOffer?>(null) }
    val installed = remember {
        runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull().orEmpty()
    }
    HomeActionRow(
        title = "检查更新",
        description = if (checking) "正在检查…" else "当前版本 $installed",
        action = "检查",
        icon = R.drawable.ic_lan_refresh,
        enabled = !checking,
        onClick = {
            checking = true
            scope.launch {
                val result = withContext(Dispatchers.IO) { checker.check(manual = true) }
                checking = false
                when (result) {
                    is AndroidUpdateResult.Available -> offer = result.offer
                    AndroidUpdateResult.Current -> Toast.makeText(context, "已是最新版本。", Toast.LENGTH_SHORT).show()
                    AndroidUpdateResult.Failed -> Toast.makeText(context, "检查更新失败，请检查网络后重试。", Toast.LENGTH_LONG).show()
                }
            }
        },
    )
    HomeActionRow(
        title = "自动检查更新",
        description = if (autoCheck) "已开启 · 打开应用时每天最多检查一次" else "已关闭",
        action = if (autoCheck) "关闭" else "开启",
        icon = R.drawable.ic_nav_settings,
        enabled = true,
        onClick = {
            autoCheck = !autoCheck
            checker.autoCheckEnabled = autoCheck
        },
    )
    offer?.let { current -> AndroidUpdateDialog(current, checker) { offer = null } }
}

@Composable
private fun AndroidUpdateDialog(offer: AndroidUpdateOffer, checker: AndroidUpdateChecker, onClose: () -> Unit) {
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("发现新版本 ${offer.version}") },
        text = {
            Column {
                if (offer.notes.isNotBlank()) {
                    Text(offer.notes, modifier = Modifier.padding(bottom = 12.dp))
                }
                Text("将在浏览器中下载 ${offer.asset.variant} 安装包（${offer.asset.size / (1024 * 1024)} MB），下载后按系统提示覆盖安装，保险库数据会保留。")
                Text("SHA-256：${offer.asset.sha256}", style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 8.dp))
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (!checker.openDownload(offer)) {
                    Toast.makeText(context, "无法打开浏览器，请稍后重试。", Toast.LENGTH_LONG).show()
                }
                onClose()
            }) { Text("下载") }
        },
        dismissButton = {
            Column {
                TextButton(onClick = onClose) { Text("稍后") }
                TextButton(onClick = { checker.skip(offer.versionCode); onClose() }) { Text("跳过此版本") }
            }
        },
    )
}
