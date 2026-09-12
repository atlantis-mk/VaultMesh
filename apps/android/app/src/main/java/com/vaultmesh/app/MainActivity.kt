package com.vaultmesh.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

class MainActivity : ComponentActivity() {
    private val viewModel: VaultViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        check(VaultNativeBridge.initialize(filesDir.absolutePath) == "ok")
        viewModel.refresh()
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    VaultScreen(viewModel)
                }
            }
        }
    }

    override fun onStop() {
        viewModel.markLocked()
        VaultNativeBridge.lock()
        super.onStop()
    }
}

@Composable
private fun VaultScreen(viewModel: VaultViewModel) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    Box(modifier = Modifier.fillMaxSize()) {
        if (state.status == "unlocked") {
            UnlockedVaultScreen(state, viewModel)
        } else {
            LockedVaultScreen(state, viewModel)
        }
        state.editor?.let { draft ->
            LoginEditorDialog(draft, state.busy, viewModel)
        }
        state.deleteCandidate?.let { item ->
            AlertDialog(
                onDismissRequest = viewModel::cancelDeleteLogin,
                title = { Text("删除登录项？") },
                text = { Text("“${item.title}”将进入加密回收站。") },
                confirmButton = {
                    TextButton(onClick = viewModel::confirmDeleteLogin) { Text("删除") }
                },
                dismissButton = {
                    TextButton(onClick = viewModel::cancelDeleteLogin) { Text("取消") }
                },
            )
        }
        state.purgeCandidate?.let { item ->
            AlertDialog(
                onDismissRequest = viewModel::cancelPurgeLogin,
                title = { Text("永久删除？") },
                text = { Text("“${item.title}”及其历史版本将无法恢复。") },
                confirmButton = {
                    TextButton(onClick = viewModel::confirmPurgeLogin) { Text("永久删除") }
                },
                dismissButton = {
                    TextButton(onClick = viewModel::cancelPurgeLogin) { Text("取消") }
                },
            )
        }
        if (state.confirmEmptyTrash) {
            AlertDialog(
                onDismissRequest = viewModel::cancelEmptyTrash,
                title = { Text("清空回收站？") },
                text = { Text("所有回收站登录项及其历史版本都将永久删除。") },
                confirmButton = {
                    TextButton(onClick = viewModel::confirmEmptyTrash) { Text("清空") }
                },
                dismissButton = {
                    TextButton(onClick = viewModel::cancelEmptyTrash) { Text("取消") }
                },
            )
        }
    }
}

@Composable
private fun LockedVaultScreen(state: VaultUiState, viewModel: VaultViewModel) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp, vertical = 40.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("VaultMesh", style = MaterialTheme.typography.headlineLarge)
        Spacer(Modifier.height(12.dp))
        Text(statusLabel(state.status), style = MaterialTheme.typography.bodyLarge)
        Spacer(Modifier.height(28.dp))

        OutlinedTextField(
            value = state.password,
            onValueChange = viewModel::updatePassword,
            modifier = Modifier.fillMaxWidth(),
            enabled = !state.busy,
            label = { Text(if (state.status == "missing") "设置主密码" else "主密码") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            visualTransformation = PasswordVisualTransformation(),
        )
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = if (state.status == "missing") viewModel::create else viewModel::unlock,
            enabled = state.password.isNotEmpty() && !state.busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (state.busy) {
                CircularProgressIndicator(modifier = Modifier.height(20.dp))
            } else {
                Text(if (state.status == "missing") "创建保险库" else "解锁")
            }
        }

        state.error?.let {
            Spacer(Modifier.height(16.dp))
            Text(errorLabel(it), color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun UnlockedVaultScreen(state: VaultUiState, viewModel: VaultViewModel) {
    val visibleLogins = state.logins.filter { item ->
        state.query.isBlank() ||
            item.title.contains(state.query, ignoreCase = true) ||
            item.username.contains(state.query, ignoreCase = true) ||
            item.url.orEmpty().contains(state.query, ignoreCase = true)
    }
    val visibleTrash = state.trash.filter { item ->
        state.query.isBlank() ||
            item.title.contains(state.query, ignoreCase = true) ||
            item.username.contains(state.query, ignoreCase = true)
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 28.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    if (state.section == VaultSection.Logins) "保险库" else "回收站",
                    style = MaterialTheme.typography.headlineMedium,
                )
                Text(
                    if (state.section == VaultSection.Logins) {
                        "${state.logins.size} 个登录项"
                    } else {
                        "${state.trash.size} 个已删除项"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            TextButton(onClick = viewModel::lock) { Text("锁定") }
        }
        Row(modifier = Modifier.fillMaxWidth()) {
            TextButton(onClick = viewModel::showLogins, modifier = Modifier.weight(1f)) {
                Text(if (state.section == VaultSection.Logins) "登录项 ·" else "登录项")
            }
            TextButton(onClick = viewModel::showTrash, modifier = Modifier.weight(1f)) {
                Text(if (state.section == VaultSection.Trash) "回收站 ·" else "回收站")
            }
        }
        OutlinedTextField(
            value = state.query,
            onValueChange = viewModel::updateQuery,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("搜索标题、用户名或网址") },
            singleLine = true,
        )
        Spacer(Modifier.height(16.dp))
        if (state.section == VaultSection.Logins) {
            Button(
                onClick = viewModel::beginCreateLogin,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("新增登录项")
            }
        } else {
            Button(
                onClick = viewModel::requestEmptyTrash,
                enabled = state.trash.isNotEmpty() && !state.busy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("清空回收站")
            }
        }
        Spacer(Modifier.height(16.dp))
        if (state.busy) {
            CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
        } else if (state.section == VaultSection.Logins && visibleLogins.isEmpty()) {
            Text(if (state.query.isBlank()) "还没有登录项。" else "没有匹配的登录项。")
        } else if (state.section == VaultSection.Trash && visibleTrash.isEmpty()) {
            Text(if (state.query.isBlank()) "回收站为空。" else "回收站中没有匹配项。")
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                if (state.section == VaultSection.Logins) {
                    items(visibleLogins, key = LoginSummary::id) { item ->
                        LoginRow(item, viewModel)
                    }
                } else {
                    items(visibleTrash, key = TrashSummary::trashId) { item ->
                        TrashRow(item, viewModel)
                    }
                }
            }
        }
        state.error?.let {
            Spacer(Modifier.height(12.dp))
            Text(errorLabel(it), color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun TrashRow(item: TrashSummary, viewModel: VaultViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(item.title, style = MaterialTheme.typography.titleMedium)
            if (item.username.isNotEmpty()) Text(item.username)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = { viewModel.restoreLogin(item) }) { Text("恢复") }
                TextButton(onClick = { viewModel.requestPurgeLogin(item) }) { Text("永久删除") }
            }
        }
    }
}

@Composable
private fun LoginRow(item: LoginSummary, viewModel: VaultViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(item.title, style = MaterialTheme.typography.titleMedium)
            if (item.username.isNotEmpty()) Text(item.username)
            item.url?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = { viewModel.beginEditLogin(item) }) { Text("编辑") }
                TextButton(onClick = { viewModel.requestDeleteLogin(item) }) { Text("删除") }
            }
        }
    }
}

@Composable
private fun LoginEditorDialog(draft: LoginDraft, busy: Boolean, viewModel: VaultViewModel) {
    AlertDialog(
        onDismissRequest = viewModel::cancelLoginEditor,
        title = { Text(if (draft.id == null) "新增登录项" else "编辑登录项") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = draft.title,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(title = value) } },
                    label = { Text("标题") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = draft.username,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(username = value) } },
                    label = { Text("用户名") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = draft.password,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(password = value) } },
                    label = { Text(if (draft.id == null) "密码" else "新密码（留空则保留）") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    visualTransformation = PasswordVisualTransformation(),
                )
                OutlinedTextField(
                    value = draft.url,
                    onValueChange = { value -> viewModel.updateLoginDraft { it.copy(url = value) } },
                    label = { Text("网址") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = viewModel::saveLogin,
                enabled = draft.title.isNotBlank() && !busy,
            ) { Text("保存") }
        },
        dismissButton = {
            TextButton(onClick = viewModel::cancelLoginEditor, enabled = !busy) { Text("取消") }
        },
    )
}

private fun statusLabel(status: String): String = when (status) {
    "missing" -> "尚未创建本地保险库"
    "locked" -> "保险库已锁定"
    "unlocked" -> "保险库已解锁"
    else -> "保险库不可用"
}

private fun errorLabel(code: String): String = when (code) {
    "already_exists" -> "本地保险库已存在"
    "unlock_failed" -> "主密码错误或保险库已被修改"
    "invalid_vault" -> "保险库格式无效"
    "invalid_input" -> "请输入有效的标题和网址"
    "item_not_found" -> "登录项已不存在"
    "trash_item_not_found" -> "回收站条目已不存在"
    "locked" -> "保险库已锁定"
    "missing" -> "找不到本地保险库"
    else -> "操作失败"
}
