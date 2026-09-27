package com.vaultmesh.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

internal enum class HomeDestination(val label: String, val icon: Int) {
    Vault("保险库", R.drawable.ic_nav_vault),
    Tools("工具", R.drawable.ic_nav_tools),
    Devices("设备", R.drawable.ic_nav_devices),
    Settings("设置", R.drawable.ic_nav_settings),
}

private data class OverviewEntry(
    val section: VaultSection,
    val id: String,
    val title: String,
    val subtitle: String,
)

private const val VAULT_PAGE_SIZE = 30

internal fun sectionName(section: VaultSection): String = when (section) {
    VaultSection.Logins -> "登录"
    VaultSection.Cards -> "卡片"
    VaultSection.Identities -> "身份"
    VaultSection.Ssh -> "SSH"
    VaultSection.Secrets -> "密钥"
    VaultSection.Trash -> "回收站"
}

private fun overviewEntries(state: VaultUiState): List<OverviewEntry> = buildList {
    state.logins.forEach { add(OverviewEntry(VaultSection.Logins, it.id, it.title,
        listOfNotNull("登录项", it.username.takeIf(String::isNotBlank), it.url).joinToString(" · "))) }
    state.cards.forEach { add(OverviewEntry(VaultSection.Cards, it.id, it.title,
        listOf("卡片", it.maskedNumber).filter(String::isNotBlank).joinToString(" · "))) }
    state.identities.forEach { add(OverviewEntry(VaultSection.Identities, it.id, it.title,
        listOfNotNull("身份资料", it.displayName).filter(String::isNotBlank).joinToString(" · "))) }
    state.ssh.forEach { add(OverviewEntry(VaultSection.Ssh, it.id, it.title,
        listOfNotNull("SSH 凭据", it.host).filter(String::isNotBlank).joinToString(" · "))) }
    state.secrets.forEach { add(OverviewEntry(VaultSection.Secrets, it.id, it.title,
        listOfNotNull("服务密钥", it.provider).filter(String::isNotBlank).joinToString(" · "))) }
}

@Composable
fun UnlockedVaultScreen(
    state: VaultUiState,
    viewModel: VaultViewModel,
    onBackup: () -> Unit,
    onRestore: () -> Unit,
    biometricEnabled: Boolean,
    onEnableBiometric: () -> Unit,
    onDisableBiometric: () -> Unit,
    pinEnabled: Boolean,
    onEnablePin: (String) -> Unit,
    onDisablePin: () -> Unit,
    onNearby: () -> Unit,
    onLeaveNearby: () -> Unit,
    nearbyContent: @Composable (Modifier) -> Unit,
) {
    var destination by remember { mutableStateOf(HomeDestination.Vault) }
    var selectedCategory by remember { mutableStateOf<VaultSection?>(null) }
    var showCreatePicker by remember { mutableStateOf(false) }
    var showPinSetup by remember { mutableStateOf(false) }
    var setupPin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }

    fun selectCategory(section: VaultSection?) {
        selectedCategory = section
        viewModel.showSection(section ?: VaultSection.Logins)
    }

    fun createItem(section: VaultSection) {
        showCreatePicker = false
        selectCategory(section)
        when (section) {
            VaultSection.Logins -> viewModel.beginCreateLogin()
            VaultSection.Cards -> viewModel.beginCard()
            VaultSection.Identities -> viewModel.beginIdentity()
            VaultSection.Ssh -> viewModel.beginSsh()
            VaultSection.Secrets -> viewModel.beginSecret()
            VaultSection.Trash -> Unit
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            UnlockedHomeTopBar(destination, viewModel::lock)
        },
        bottomBar = {
            HomeNavigationBar(destination) { item ->
                if (destination != item) {
                    viewModel.showSection(selectedCategory ?: VaultSection.Logins)
                    destination = item
                }
            }
        },
        floatingActionButton = {
            if (destination == HomeDestination.Vault && state.section != VaultSection.Trash && !state.busy) {
                FloatingActionButton(onClick = {
                    if (selectedCategory == null) showCreatePicker = true
                    else createItem(selectedCategory!!)
                }) { Icon(painterResource(R.drawable.ic_add), contentDescription = "新增条目") }
            }
        },
    ) { padding ->
        when (destination) {
            HomeDestination.Vault -> VaultHomePage(state, viewModel, selectedCategory, ::selectCategory,
                Modifier.padding(padding))
            HomeDestination.Tools -> HomeActionPage("工具", state.error, Modifier.padding(padding)) {
                HomeActionRow("凭据生成器", "生成密码、用户名或邮箱别名", "生成",
                    R.drawable.ic_nav_tools, viewModel::beginGenerator, !state.busy, primary = true)
                HomeActionRow("密码健康", "检查弱密码、重复使用与过期登录项", "查看报告",
                    R.drawable.ic_nav_vault, viewModel::requestPasswordHealth, !state.busy)
                HomeGroupTitle("备份与恢复")
                HomeActionRow("加密备份", "导出当前保险库的加密备份", "创建备份",
                    R.drawable.ic_lock, onBackup, !state.busy)
                HomeActionRow("从备份恢复", "选择加密备份并确认替换本机保险库", "选择文件",
                    R.drawable.ic_lan_refresh, onRestore, !state.busy)
            }
            HomeDestination.Devices -> {
                DisposableEffect(Unit) {
                    onNearby()
                    onDispose { onLeaveNearby() }
                }
                nearbyContent(Modifier.padding(padding))
            }
            HomeDestination.Settings -> HomeActionPage("设置", state.error, Modifier.padding(padding)) {
                HomeGroupTitle("自动填充")
                AutofillSettingsCard()
                PhoneNumberSettingsCard()
                HomeGroupTitle("解锁与安全")
                HomeActionRow("主密码", "更改当前保险库的主密码", "修改",
                    R.drawable.ic_lock, viewModel::beginPasswordRotation, !state.busy)
                HomeActionRow("生物识别快捷解锁",
                    if (biometricEnabled) "已启用" else "未启用",
                    if (biometricEnabled) "关闭" else "启用", R.drawable.ic_lock,
                    if (biometricEnabled) onDisableBiometric else onEnableBiometric, !state.busy,
                    primary = !biometricEnabled)
                HomeActionRow("PIN 快捷解锁",
                    if (pinEnabled) "已启用" else "未启用 · 使用 6 位 PIN",
                    if (pinEnabled) "关闭" else "设置", R.drawable.ic_lock,
                    if (pinEnabled) onDisablePin else ({ showPinSetup = true }), !state.busy)
            }
        }
    }

    if (showCreatePicker) {
        AlertDialog(
            onDismissRequest = { showCreatePicker = false },
            title = { Text("新增条目") },
            text = {
                Column {
                    listOf(VaultSection.Logins, VaultSection.Cards, VaultSection.Identities,
                        VaultSection.Ssh, VaultSection.Secrets).forEach { section ->
                        TextButton(onClick = { createItem(section) }, modifier = Modifier.fillMaxWidth()) {
                            Text(sectionName(section))
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { showCreatePicker = false }) { Text("取消") } },
        )
    }
    if (showPinSetup) {
        AlertDialog(
            onDismissRequest = { setupPin = ""; confirmPin = ""; showPinSetup = false },
            title = { Text("设置 6 位 PIN") },
            text = {
                Column {
                    OutlinedTextField(
                        value = setupPin,
                        onValueChange = { setupPin = it.filter(Char::isDigit).take(6) },
                        label = { Text("PIN") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        visualTransformation = PasswordVisualTransformation(),
                    )
                    OutlinedTextField(
                        value = confirmPin,
                        onValueChange = { confirmPin = it.filter(Char::isDigit).take(6) },
                        label = { Text("再次输入 PIN") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        visualTransformation = PasswordVisualTransformation(),
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val pin = setupPin
                    setupPin = ""
                    confirmPin = ""
                    showPinSetup = false
                    onEnablePin(pin)
                }, enabled = !state.busy && setupPin.length == 6 && setupPin == confirmPin) {
                    Text("启用")
                }
            },
            dismissButton = {
                TextButton(onClick = { setupPin = ""; confirmPin = ""; showPinSetup = false }) {
                    Text("取消")
                }
            },
        )
    }
}

@Composable
private fun VaultHomePage(
    state: VaultUiState,
    viewModel: VaultViewModel,
    selectedCategory: VaultSection?,
    onCategory: (VaultSection?) -> Unit,
    modifier: Modifier,
) {
    val inTrash = selectedCategory != null && state.section == VaultSection.Trash
    val currentType = selectedCategory ?: VaultSection.Logins
    var visibleCount by remember(selectedCategory, state.section, state.query) {
        mutableIntStateOf(VAULT_PAGE_SIZE)
    }
    val listState = remember(selectedCategory, state.section, state.query) { LazyListState() }
    var selected by remember { mutableStateOf<Set<VaultSelection>>(emptySet()) }
    var confirmBatchDelete by remember { mutableStateOf(false) }
    LaunchedEffect(selectedCategory, state.section, state.query) {
        selected = emptySet()
        confirmBatchDelete = false
    }
    val overview = remember(state.logins, state.cards, state.identities, state.ssh, state.secrets) {
        overviewEntries(state)
    }.filter { entry ->
        state.query.isBlank() || entry.title.contains(state.query, true) ||
            entry.subtitle.contains(state.query, true)
    }
    val filteredTotal = when {
        selectedCategory == null -> overview.size
        inTrash && currentType == VaultSection.Logins -> state.trash.count {
            state.query.isBlank() || it.title.contains(state.query, true) ||
                it.username.contains(state.query, true)
        }
        inTrash -> state.otherTrash[currentType].orEmpty().count {
            it.title.contains(state.query, true) || it.subtitle.contains(state.query, true)
        }
        currentType == VaultSection.Logins -> state.logins.count {
            state.query.isBlank() || it.title.contains(state.query, true) ||
                it.username.contains(state.query, true) || it.url.orEmpty().contains(state.query, true)
        }
        currentType == VaultSection.Cards -> state.cards.count {
            it.title.contains(state.query, true) || it.cardholderName.contains(state.query, true) ||
                it.maskedNumber.contains(state.query, true)
        }
        currentType == VaultSection.Ssh -> state.ssh.count {
            it.title.contains(state.query, true) || it.username.contains(state.query, true) ||
                it.host.orEmpty().contains(state.query, true)
        }
        currentType == VaultSection.Identities -> state.identities.count {
            it.title.contains(state.query, true) || it.displayName.orEmpty().contains(state.query, true) ||
                it.organization.orEmpty().contains(state.query, true)
        }
        currentType == VaultSection.Secrets -> state.secrets.count {
            it.title.contains(state.query, true) || it.provider.orEmpty().contains(state.query, true) ||
                it.account.orEmpty().contains(state.query, true)
        }
        else -> 0
    }
    LaunchedEffect(listState, filteredTotal, visibleCount, state.busy) {
        snapshotFlow { listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: -1 }
            .collect { lastVisible ->
                if (!state.busy && filteredTotal > visibleCount && lastVisible >= visibleCount - 5) {
                    visibleCount = (visibleCount + VAULT_PAGE_SIZE).coerceAtMost(filteredTotal)
                }
            }
    }
    val selectable = if (inTrash) emptySet() else when (selectedCategory) {
        null -> overview.take(visibleCount).filter { entry -> entry.section != VaultSection.Ssh ||
            state.ssh.none { it.id == entry.id && it.managed } }
            .map { VaultSelection(it.section, it.id) }.toSet()
        VaultSection.Logins -> state.logins.filter { state.query.isBlank() ||
            it.title.contains(state.query, true) || it.username.contains(state.query, true) ||
            it.url.orEmpty().contains(state.query, true) }
            .take(visibleCount)
            .map { VaultSelection(VaultSection.Logins, it.id) }.toSet()
        VaultSection.Cards -> state.cards.filter { state.query.isBlank() ||
            it.title.contains(state.query, true) || it.cardholderName.contains(state.query, true) ||
            it.maskedNumber.contains(state.query, true) }
            .take(visibleCount)
            .map { VaultSelection(VaultSection.Cards, it.id) }.toSet()
        VaultSection.Ssh -> state.ssh.filter { state.query.isBlank() ||
            it.title.contains(state.query, true) || it.username.contains(state.query, true) ||
            it.host.orEmpty().contains(state.query, true) }
            .take(visibleCount)
            .filterNot(SshSummary::managed)
            .map { VaultSelection(VaultSection.Ssh, it.id) }.toSet()
        VaultSection.Identities -> state.identities.filter { state.query.isBlank() ||
            it.title.contains(state.query, true) || it.displayName.orEmpty().contains(state.query, true) ||
            it.organization.orEmpty().contains(state.query, true) }
            .take(visibleCount)
            .map { VaultSelection(VaultSection.Identities, it.id) }.toSet()
        VaultSection.Secrets -> state.secrets.filter { state.query.isBlank() ||
            it.title.contains(state.query, true) || it.provider.orEmpty().contains(state.query, true) ||
            it.account.orEmpty().contains(state.query, true) }
            .take(visibleCount)
            .map { VaultSelection(VaultSection.Secrets, it.id) }.toSet()
        VaultSection.Trash -> emptySet()
    }
    LaunchedEffect(selectable) { selected = selected.intersect(selectable) }
    fun toggle(key: VaultSelection) {
        selected = if (key in selected) selected - key else selected + key
    }
    Column(modifier = modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Text("保险库", style = MaterialTheme.typography.headlineLarge,
            modifier = Modifier.padding(top = 20.dp, bottom = 16.dp))
        OutlinedTextField(
            value = state.query,
            onValueChange = viewModel::updateQuery,
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("搜索保险库") },
            leadingIcon = { Icon(painterResource(R.drawable.ic_search), contentDescription = null) },
            singleLine = true,
            shape = RoundedCornerShape(28.dp),
        )
        Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())
                .padding(top = 14.dp, bottom = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            val categories: List<Pair<VaultSection?, String>> = listOf(
                null to "全部", VaultSection.Logins to "登录", VaultSection.Cards to "卡片",
                VaultSection.Identities to "身份", VaultSection.Ssh to "SSH",
                VaultSection.Secrets to "密钥",
            )
            categories.forEach { (section, label) ->
                FilterChip(selected = selectedCategory == section, onClick = { onCategory(section) },
                    label = { Text(label) })
            }
        }
        if (selectedCategory != null && selectedCategory != VaultSection.Secrets) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = !inTrash, onClick = { viewModel.showSection(currentType) },
                    label = { Text("条目") })
                FilterChip(selected = inTrash, onClick = { viewModel.showTrashFor(currentType) },
                    label = { Text("回收站") })
            }
        }
        Row(modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
            verticalAlignment = Alignment.CenterVertically) {
            Text(
                when {
                    selectedCategory == null -> "全部条目"
                    inTrash -> "${sectionName(currentType)}回收站"
                    else -> "${sectionName(currentType)}条目"
                },
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            if (!inTrash && selectable.isNotEmpty()) {
                TextButton(onClick = {
                    selected = if (selectable.all { it in selected }) selected - selectable
                        else selected + selectable
                }, enabled = !state.busy) {
                    Text(if (selectable.all { it in selected }) "取消本页" else "全选本页")
                }
            }
            if (inTrash) {
                val hasTrash = if (currentType == VaultSection.Logins) state.trash.isNotEmpty()
                    else state.otherTrash[currentType].orEmpty().isNotEmpty()
                TextButton(
                    onClick = if (currentType == VaultSection.Logins) viewModel::requestEmptyTrash
                        else viewModel::requestOtherEmptyTrash,
                    enabled = hasTrash && !state.busy,
                ) { Text("清空") }
            }
        }
        if (selected.isNotEmpty() && !inTrash) {
            Row(modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Text("已选择 ${selected.size} 项", modifier = Modifier.weight(1f))
                TextButton(onClick = { confirmBatchDelete = true }, enabled = !state.busy) { Text("删除") }
                TextButton(onClick = { selected = emptySet() }) { Text("取消选择") }
            }
        }
        state.batchDeleteNotice?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
        when {
            state.busy -> CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
            selectedCategory == null -> {
                if (overview.isEmpty()) {
                    Text(if (state.query.isBlank()) "还没有条目。点击右下角新增。" else "没有匹配的条目。")
                } else {
                    LazyColumn(modifier = Modifier.weight(1f), state = listState,
                        contentPadding = PaddingValues(bottom = 88.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        items(overview.take(visibleCount), key = { "${it.section}-${it.id}" }) { entry ->
                            OverviewRow(entry, state, viewModel,
                                VaultSelection(entry.section, entry.id) in selected,
                                if (VaultSelection(entry.section, entry.id) in selectable)
                                    ({ toggle(VaultSelection(entry.section, entry.id)) }) else null)
                        }
                        if (filteredTotal > visibleCount) item { VaultLoadMoreFooter() }
                    }
                }
                state.error?.let { Text(errorLabel(it), color = MaterialTheme.colorScheme.error) }
            }
            currentType == VaultSection.Logins -> LoginItemsPage(state, viewModel, Modifier.weight(1f),
                selected, ::toggle, visibleCount, listState)
            else -> OtherItemsScreen(state, viewModel, Modifier.weight(1f), selected, ::toggle,
                visibleCount, listState)
        }
    }
    if (confirmBatchDelete && selected.isNotEmpty()) {
        val targets = selected.intersect(selectable).toList()
        val includesSecret = targets.any { it.section == VaultSection.Secrets }
        AlertDialog(onDismissRequest = { confirmBatchDelete = false },
            title = { Text("删除选中的 ${targets.size} 项？") },
            text = { Text(if (includesSecret)
                "密钥会永久删除；其他类型会进入加密回收站。批量操作可能部分完成，请在失败后检查列表。"
                else "选中条目将进入加密回收站。批量操作可能部分完成，请在失败后检查列表。") },
            confirmButton = { TextButton(onClick = {
                confirmBatchDelete = false
                selected = emptySet()
                viewModel.deleteSelectedItems(targets)
            }, enabled = targets.isNotEmpty() && !state.busy) { Text("删除") } },
            dismissButton = { TextButton(onClick = { confirmBatchDelete = false }) { Text("取消") } })
    }
}

@Composable
private fun OverviewRow(entry: OverviewEntry, state: VaultUiState, viewModel: VaultViewModel,
    selected: Boolean, onToggle: (() -> Unit)?) {
    when (entry.section) {
        VaultSection.Logins -> state.logins.firstOrNull { it.id == entry.id }?.let {
            LoginRow(it, viewModel, selected, onToggle)
        }
        VaultSection.Cards -> state.cards.firstOrNull { it.id == entry.id }?.let { item ->
            OtherRow(VaultSection.Cards, item.id, item.title, item.maskedNumber,
                summaryCopy = item.cardholderName.takeIf(String::isNotBlank),
                onCopySummary = { viewModel.copySummaryText(VaultSection.Cards, item.id, item.cardholderName) },
                selected = selected, onToggle = onToggle?.let { { _: VaultSelection -> it() } },
                onEdit = { viewModel.beginCard(item) },
                onDelete = { viewModel.requestOtherDelete(OtherTarget(VaultSection.Cards, item.id, item.title)) },
                onHistory = { viewModel.requestHistory(HistoryTarget(VaultSection.Cards, item.id, item.title)) },
                copyFields = buildList {
                    add(ProtectedCopyField.CardNumber)
                    if (item.hasSecurityCode) add(ProtectedCopyField.CardSecurityCode)
                    if (item.hasPin) add(ProtectedCopyField.CardPin)
                },
                onCopy = { field -> viewModel.requestProtectedCopy(ProtectedCopyTarget(item.id, item.title, field)) },
                onReveal = { field -> viewModel.requestProtectedReveal(ProtectedCopyTarget(item.id, item.title, field)) })
        }
        VaultSection.Ssh -> state.ssh.firstOrNull { it.id == entry.id }?.let { item ->
            OtherRow(VaultSection.Ssh, item.id, item.title, "${item.username}@${item.host.orEmpty()}",
                summaryCopy = item.username.takeIf(String::isNotBlank),
                onCopySummary = { viewModel.copySummaryText(VaultSection.Ssh, item.id, item.username) },
                selected = selected, onToggle = onToggle?.let { { _: VaultSelection -> it() } },
                onEdit = if (item.managed) null else ({ viewModel.beginSsh(item) }),
                onDelete = if (item.managed) null else ({ viewModel.requestOtherDelete(OtherTarget(VaultSection.Ssh, item.id, item.title)) }),
                onHistory = if (item.managed) null else ({ viewModel.requestHistory(HistoryTarget(VaultSection.Ssh, item.id, item.title)) }),
                note = if (item.managed) "由桌面管理，Android 不编辑" else null,
                copyFields = buildList {
                    if (item.hasPassword) add(ProtectedCopyField.SshPassword)
                    if (item.hasPublicKey) add(ProtectedCopyField.SshPublicKey)
                    if (item.hasPrivateKey) add(ProtectedCopyField.SshPrivateKey)
                    if (item.hasKeyPassphrase) add(ProtectedCopyField.SshKeyPassphrase)
                },
                onCopy = { field -> viewModel.requestProtectedCopy(ProtectedCopyTarget(item.id, item.title, field)) },
                onReveal = { field -> viewModel.requestProtectedReveal(ProtectedCopyTarget(item.id, item.title, field)) })
        }
        VaultSection.Identities -> state.identities.firstOrNull { it.id == entry.id }?.let { item ->
            OtherRow(VaultSection.Identities, item.id, item.title, item.displayName.orEmpty(),
                summaryCopy = item.displayName?.takeIf(String::isNotBlank),
                onCopySummary = { viewModel.copySummaryText(VaultSection.Identities, item.id, item.displayName.orEmpty()) },
                selected = selected, onToggle = onToggle?.let { { _: VaultSelection -> it() } },
                onEdit = { viewModel.beginIdentity(item) },
                onDelete = { viewModel.requestOtherDelete(OtherTarget(VaultSection.Identities, item.id, item.title)) },
                onHistory = { viewModel.requestHistory(HistoryTarget(VaultSection.Identities, item.id, item.title)) })
        }
        VaultSection.Secrets -> state.secrets.firstOrNull { it.id == entry.id }?.let { item ->
            OtherRow(VaultSection.Secrets, item.id, item.title, "${item.kind} · ${item.provider.orEmpty()}",
                summaryCopy = item.account?.takeIf(String::isNotBlank),
                onCopySummary = { viewModel.copySummaryText(VaultSection.Secrets, item.id, item.account.orEmpty()) },
                selected = selected, onToggle = onToggle?.let { { _: VaultSelection -> it() } },
                onEdit = { viewModel.beginSecret(item) },
                onDelete = { viewModel.requestOtherDelete(OtherTarget(VaultSection.Secrets, item.id, item.title)) },
                copyFields = listOf(ProtectedCopyField.SecretValue),
                onCopy = { field -> viewModel.requestProtectedCopy(ProtectedCopyTarget(item.id, item.title, field)) },
                onReveal = { field -> viewModel.requestProtectedReveal(ProtectedCopyTarget(item.id, item.title, field)) })
        }
        VaultSection.Trash -> Unit
    }
}

@Composable
private fun LoginItemsPage(state: VaultUiState, viewModel: VaultViewModel, modifier: Modifier,
    selected: Set<VaultSelection>, onToggle: (VaultSelection) -> Unit,
    visibleCount: Int, listState: LazyListState) {
    val inTrash = state.section == VaultSection.Trash
    val logins = state.logins.filter {
        state.query.isBlank() || it.title.contains(state.query, true) ||
            it.username.contains(state.query, true) || it.url.orEmpty().contains(state.query, true)
    }
    val trash = state.trash.filter {
        state.query.isBlank() || it.title.contains(state.query, true) || it.username.contains(state.query, true)
    }
    Column(modifier = modifier) {
        if ((!inTrash && logins.isEmpty()) || (inTrash && trash.isEmpty())) {
            Text(if (state.query.isNotBlank()) "没有匹配的条目。"
                else if (inTrash) "回收站为空。" else "还没有登录项。")
        } else {
            LazyColumn(modifier = Modifier.weight(1f), state = listState,
                contentPadding = PaddingValues(bottom = 88.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (inTrash) items(trash.take(visibleCount), key = { it.trashId }) { TrashRow(it, viewModel) }
                else items(logins.take(visibleCount), key = { it.id }) {
                    val key = VaultSelection(VaultSection.Logins, it.id)
                    LoginRow(it, viewModel, key in selected) { onToggle(key) }
                }
                if ((if (inTrash) trash.size else logins.size) > visibleCount) {
                    item { VaultLoadMoreFooter() }
                }
            }
        }
        state.error?.let { Text(errorLabel(it), color = MaterialTheme.colorScheme.error) }
    }
}

@Composable
internal fun VaultLoadMoreFooter() {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp),
        horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
        Spacer(Modifier.width(10.dp))
        Text("加载更多…", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun HomeActionPage(
    title: String,
    error: String?,
    modifier: Modifier,
    content: @Composable () -> Unit,
) {
    LazyColumn(modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item { Text(title, style = MaterialTheme.typography.headlineLarge,
            modifier = Modifier.padding(bottom = 8.dp)) }
        item { Column(verticalArrangement = Arrangement.spacedBy(12.dp)) { content() } }
        if (error != null) item { Text(errorLabel(error), color = MaterialTheme.colorScheme.error) }
    }
}

@Composable
private fun HomeGroupTitle(title: String) {
    Text(title, style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(top = 20.dp, bottom = 2.dp))
}

@Composable
internal fun HomeActionRow(title: String, description: String, action: String,
    icon: Int, onClick: () -> Unit, enabled: Boolean, primary: Boolean = false) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)) {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Box(modifier = Modifier.size(44.dp).background(MaterialTheme.colorScheme.surfaceVariant,
                RoundedCornerShape(12.dp)), contentAlignment = Alignment.Center) {
                Icon(painterResource(icon), contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurface)
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(description, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (primary) androidx.compose.material3.Button(onClick = onClick, enabled = enabled) {
                Text(action)
            } else androidx.compose.material3.OutlinedButton(onClick = onClick, enabled = enabled) {
                Text(action)
            }
        }
    }
}

@Composable
internal fun UnlockedHomeTopBar(destination: HomeDestination, onLock: () -> Unit) {
    Row(
        modifier = Modifier.statusBarsPadding().fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (destination != HomeDestination.Devices) Box(
            modifier = Modifier.size(36.dp).background(MaterialTheme.colorScheme.primary,
                RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center,
        ) { Text("V", color = Color.White, style = MaterialTheme.typography.titleMedium) }
        Text(if (destination == HomeDestination.Devices) "设备" else "VaultMesh",
            modifier = Modifier.weight(1f).padding(start = if (destination == HomeDestination.Devices) 0.dp else 12.dp),
            style = MaterialTheme.typography.titleLarge)
        IconButton(onClick = onLock) {
            Icon(painterResource(R.drawable.ic_lock), contentDescription = "锁定保险库")
        }
    }
}

@Composable
internal fun HomeNavigationBar(destination: HomeDestination, onSelect: (HomeDestination) -> Unit) {
    NavigationBar(containerColor = Color.White) {
        HomeDestination.entries.forEach { item ->
            NavigationBarItem(
                selected = destination == item,
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = MaterialTheme.colorScheme.primary,
                    selectedTextColor = MaterialTheme.colorScheme.primary,
                    indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                    unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
                onClick = { onSelect(item) },
                icon = { Icon(painterResource(item.icon), contentDescription = null) },
                label = { Text(item.label) },
                alwaysShowLabel = true,
            )
        }
    }
}
