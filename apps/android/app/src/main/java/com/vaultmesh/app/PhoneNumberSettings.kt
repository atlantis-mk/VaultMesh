package com.vaultmesh.app

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun PhoneNumberSettingsCard() {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val scope = rememberCoroutineScope()
    var open by remember { mutableStateOf(false) }
    var ready by remember { mutableStateOf(false) }
    var sim by remember { mutableStateOf<String?>(null) }
    var manual by remember { mutableStateOf<String?>(null) }
    var draft by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    fun refresh() {
        scope.launch {
            val numbers = withContext(Dispatchers.IO) {
                val source = LocalPhoneNumber(context)
                source.simNumber() to source.manualNumber()
            }
            sim = numbers.first
            manual = numbers.second
            ready = sim != null || manual != null
        }
    }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (!granted) error = "未授予号码权限，可手动设置备用号码。"
        refresh()
    }
    LaunchedEffect(Unit) { refresh() }
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_RESUME) refresh() }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    HomeActionRow(
        title = "本机号码填充",
        description = if (ready) "已就绪 · 仅填充用户名栏" else "读取 SIM 号码或手动设置备用号码",
        action = "管理号码",
        icon = R.drawable.ic_nav_settings,
        enabled = true,
        onClick = {
            error = null
            scope.launch {
                val numbers = withContext(Dispatchers.IO) {
                    val source = LocalPhoneNumber(context)
                    source.simNumber() to source.manualNumber()
                }
                sim = numbers.first
                manual = numbers.second
                ready = sim != null || manual != null
                draft = manual.orEmpty()
                open = true
            }
        },
    )
    if (open) AlertDialog(
        onDismissRequest = { open = false; draft = ""; sim = null; manual = null },
        title = { Text("本机号码填充") },
        text = {
            Column {
                Text("号码会显示在系统填充建议中，点选后仅填入用户名栏。SIM 号码可用时优先使用。")
                Text("SIM 号码：${sim ?: "不可用或未授权"}", modifier = Modifier.padding(top = 12.dp))
                TextButton(onClick = {
                    if (context.checkSelfPermission(Manifest.permission.READ_PHONE_NUMBERS) == PackageManager.PERMISSION_GRANTED) refresh()
                    else permission.launch(Manifest.permission.READ_PHONE_NUMBERS)
                }) { Text("读取 SIM 号码") }
                OutlinedTextField(draft, { draft = it.take(64) }, label = { Text("备用号码") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                if (manual != null) TextButton(onClick = {
                    scope.launch {
                        val cleared = withContext(Dispatchers.IO) { LocalPhoneNumber(context).clearManualNumber() }
                        if (cleared) { draft = ""; refresh() } else error = "删除失败，请重试。"
                    }
                }) { Text("删除备用号码") }
                error?.let { Text(it) }
            }
        },
        confirmButton = { TextButton(onClick = {
            scope.launch {
                val saved = withContext(Dispatchers.IO) { LocalPhoneNumber(context).saveManualNumber(draft) }
                if (saved) { error = null; refresh(); open = false; draft = "" }
                else error = "号码格式无效或保存失败。"
            }
        }) { Text("保存备用号码") } },
        dismissButton = { TextButton(onClick = { open = false; draft = ""; sim = null; manual = null }) { Text("关闭") } },
    )
}
