package com.vaultmesh.app

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import android.widget.Toast
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner

@Composable
internal fun AutofillSettingsCard() {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    fun enabled() = context.getSystemService(AutofillManager::class.java)?.hasEnabledAutofillServices() == true
    var active by remember { mutableStateOf(enabled()) }
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_RESUME) active = enabled() }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    HomeActionRow(
        title = "系统自动填充",
        description = if (active) "已启用 · 可在其他应用填充与保存登录" else "在其他应用中填充与保存登录",
        action = if (active) "管理" else "去设置",
        icon = R.drawable.ic_nav_settings,
        enabled = true,
        primary = !active,
        onClick = {
                val opened = runCatching {
                    context.startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:${context.packageName}")))
                }.isSuccess
                if (!opened) Toast.makeText(context, "此设备未提供自动填充设置，请在系统设置中选择服务。", Toast.LENGTH_LONG).show()
        },
    )
}
