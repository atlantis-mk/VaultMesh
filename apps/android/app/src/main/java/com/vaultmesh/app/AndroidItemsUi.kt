package com.vaultmesh.app

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

@Composable
fun OtherItemsScreen(state: VaultUiState, viewModel: VaultViewModel, modifier: Modifier,
    selected: Set<VaultSelection>, onToggle: ((VaultSelection) -> Unit)?,
    visibleCount: Int, listState: LazyListState) {
    val type = if (state.section == VaultSection.Trash) state.trashType else state.section
    val inTrash = state.section == VaultSection.Trash
    val query = state.query
    val cards = state.cards.filter {
        it.title.contains(query, true) || it.cardholderName.contains(query, true) ||
            it.maskedNumber.contains(query, true)
    }
    val ssh = state.ssh.filter {
        it.title.contains(query, true) || it.username.contains(query, true) ||
            it.host.orEmpty().contains(query, true)
    }
    val identities = state.identities.filter {
        it.title.contains(query, true) || it.displayName.orEmpty().contains(query, true) ||
            it.organization.orEmpty().contains(query, true)
    }
    val secrets = state.secrets.filter {
        it.title.contains(query, true) || it.provider.orEmpty().contains(query, true) ||
            it.account.orEmpty().contains(query, true)
    }
    val trash = state.otherTrash[type].orEmpty().filter {
        it.title.contains(query, true) || it.subtitle.contains(query, true)
    }
    Column(modifier = modifier.fillMaxSize()) {
        if (state.busy) {
            CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
        } else if (when {
            inTrash -> trash.isEmpty()
            type == VaultSection.Cards -> cards.isEmpty()
            type == VaultSection.Ssh -> ssh.isEmpty()
            type == VaultSection.Identities -> identities.isEmpty()
            type == VaultSection.Secrets -> secrets.isEmpty()
            else -> true
        }) {
            Text(if (query.isNotBlank()) "没有匹配的条目。"
                else if (inTrash) "回收站为空。" else "还没有${when (type) {
                    VaultSection.Cards -> "卡片"
                    VaultSection.Ssh -> "SSH 凭据"
                    VaultSection.Identities -> "身份资料"
                    VaultSection.Secrets -> "服务密钥"
                    else -> "条目"
                }}。")
        } else {
            LazyColumn(modifier = Modifier.weight(1f), state = listState,
                contentPadding = PaddingValues(bottom = 88.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (inTrash) {
                    items(trash.take(visibleCount), key = OtherTrashSummary::trashId) { item ->
                        OtherTrashRow(type, item, viewModel)
                    }
                } else when (type) {
                    VaultSection.Cards -> items(cards.take(visibleCount), key = CardSummary::id) { item ->
                        OtherRow(type, item.id, item.title, "${item.cardholderName} · ${item.maskedNumber}",
                            summaryCopy = item.cardholderName.takeIf(String::isNotBlank),
                            onCopySummary = { viewModel.copySummaryText(type, item.id, item.cardholderName) },
                            selected = VaultSelection(type, item.id) in selected,
                            onToggle = onToggle,
                            onEdit = { viewModel.beginCard(item) },
                            onDelete = { viewModel.requestOtherDelete(OtherTarget(type, item.id, item.title)) },
                            onHistory = { viewModel.requestHistory(HistoryTarget(type, item.id, item.title)) },
                            copyFields = buildList {
                                add(ProtectedCopyField.CardNumber)
                                if (item.hasSecurityCode) add(ProtectedCopyField.CardSecurityCode)
                                if (item.hasPin) add(ProtectedCopyField.CardPin)
                            },
                            onCopy = { field -> viewModel.requestProtectedCopy(ProtectedCopyTarget(item.id, item.title, field)) },
                            onReveal = { field -> viewModel.requestProtectedReveal(ProtectedCopyTarget(item.id, item.title, field)) })
                    }
                    VaultSection.Ssh -> items(ssh.take(visibleCount), key = SshSummary::id) { item ->
                        OtherRow(type, item.id, item.title, "${item.username}@${item.host.orEmpty()}",
                            summaryCopy = item.username.takeIf(String::isNotBlank),
                            onCopySummary = { viewModel.copySummaryText(type, item.id, item.username) },
                            selected = VaultSelection(type, item.id) in selected,
                            onToggle = if (item.managed) null else onToggle,
                            onEdit = if (item.managed) null else ({ viewModel.beginSsh(item) }),
                            onDelete = if (item.managed) null else ({ viewModel.requestOtherDelete(OtherTarget(type, item.id, item.title)) }),
                            onHistory = if (item.managed) null else ({ viewModel.requestHistory(HistoryTarget(type, item.id, item.title)) }),
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
                    VaultSection.Identities -> items(identities.take(visibleCount), key = IdentitySummary::id) { item ->
                        OtherRow(type, item.id, item.title, item.displayName.orEmpty(),
                            summaryCopy = item.displayName?.takeIf(String::isNotBlank),
                            onCopySummary = { viewModel.copySummaryText(type, item.id, item.displayName.orEmpty()) },
                            selected = VaultSelection(type, item.id) in selected,
                            onToggle = onToggle,
                            onEdit = { viewModel.beginIdentity(item) },
                            onDelete = { viewModel.requestOtherDelete(OtherTarget(type, item.id, item.title)) },
                            onHistory = { viewModel.requestHistory(HistoryTarget(type, item.id, item.title)) })
                    }
                    VaultSection.Secrets -> items(secrets.take(visibleCount), key = SecretSummary::id) { item ->
                        OtherRow(type, item.id, item.title, "${item.kind} · ${item.provider.orEmpty()}",
                            summaryCopy = item.account?.takeIf(String::isNotBlank),
                            onCopySummary = { viewModel.copySummaryText(type, item.id, item.account.orEmpty()) },
                            selected = VaultSelection(type, item.id) in selected,
                            onToggle = onToggle,
                            onEdit = { viewModel.beginSecret(item) },
                            onDelete = { viewModel.requestOtherDelete(OtherTarget(type, item.id, item.title)) },
                            copyFields = listOf(ProtectedCopyField.SecretValue),
                            onCopy = { field -> viewModel.requestProtectedCopy(ProtectedCopyTarget(item.id, item.title, field)) },
                            onReveal = { field -> viewModel.requestProtectedReveal(ProtectedCopyTarget(item.id, item.title, field)) })
                    }
                    else -> Unit
                }
                val total = when {
                    inTrash -> trash.size
                    type == VaultSection.Cards -> cards.size
                    type == VaultSection.Ssh -> ssh.size
                    type == VaultSection.Identities -> identities.size
                    type == VaultSection.Secrets -> secrets.size
                    else -> 0
                }
                if (total > visibleCount) item { VaultLoadMoreFooter() }
            }
        }
        state.error?.let { Text(errorLabel(it), color = MaterialTheme.colorScheme.error) }
    }
}

@Composable
internal fun OtherRow(
    section: VaultSection,
    id: String,
    title: String,
    subtitle: String,
    summaryCopy: String? = null,
    onCopySummary: (() -> Unit)? = null,
    selected: Boolean = false,
    onToggle: ((VaultSelection) -> Unit)? = null,
    onEdit: (() -> Unit)?,
    onDelete: (() -> Unit)?,
    onHistory: (() -> Unit)? = null,
    note: String? = null,
    copyFields: List<ProtectedCopyField> = emptyList(),
    onCopy: ((ProtectedCopyField) -> Unit)? = null,
    onReveal: ((ProtectedCopyField) -> Unit)? = null,
) {
    val copy = buildList {
        if (summaryCopy != null) add(VaultRowAction(when (section) {
            VaultSection.Cards -> "持卡人"
            VaultSection.Ssh -> "用户名"
            VaultSection.Identities -> "姓名"
            VaultSection.Secrets -> "账号"
            else -> "信息"
        }) { onCopySummary?.invoke() })
        copyFields.forEach { field -> add(VaultRowAction(field.label) { onCopy?.invoke(field) }) }
    }
    val more = buildList {
        onEdit?.let { add(VaultRowAction("编辑", it)) }
        copyFields.forEach { field ->
            if (field != ProtectedCopyField.LoginTotpCode) add(VaultRowAction("查看${field.label}") {
                onReveal?.invoke(field)
            })
        }
        onHistory?.let { add(VaultRowAction("历史", it)) }
        onDelete?.let { add(VaultRowAction(if (section == VaultSection.Secrets) "永久删除" else "删除", it)) }
    }
    VaultEntryRow(section, title, note ?: subtitle, selected,
        onToggle?.let { { it(VaultSelection(section, id)) } }, onEdit, copy, more)
}

@Composable
private fun OtherTrashRow(type: VaultSection, item: OtherTrashSummary, viewModel: VaultViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(item.title, style = MaterialTheme.typography.titleMedium)
            if (item.subtitle.isNotBlank()) Text(item.subtitle)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = { viewModel.restoreOther(OtherTrashTarget(type, item)) }) { Text("恢复") }
                TextButton(onClick = { viewModel.requestOtherPurge(OtherTrashTarget(type, item)) }) {
                    Text("永久删除")
                }
            }
        }
    }
}

@Composable
private fun EditorField(
    value: String,
    label: String,
    onChange: (String) -> Unit,
    secret: Boolean = false,
    numeric: Boolean = false,
    multiline: Boolean = false,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        modifier = Modifier.fillMaxWidth(),
        label = { Text(label) },
        singleLine = !multiline,
        maxLines = if (multiline) 8 else 1,
        keyboardOptions = KeyboardOptions(keyboardType = when {
            secret -> KeyboardType.Password
            numeric -> KeyboardType.Number
            else -> KeyboardType.Text
        }),
        visualTransformation = if (secret) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
    )
}

@Composable
private fun ClearField(label: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChecked)
        Text(label)
    }
}

@Composable
private fun IdentityContactsEditor(
    title: String,
    entries: List<IdentityContactDraft>,
    onChange: (List<IdentityContactDraft>) -> Unit,
) {
    Text(title, style = MaterialTheme.typography.titleSmall)
    entries.forEachIndexed { index, entry ->
        Text("$title ${index + 1}")
        EditorField(entry.label, "标签", { value ->
            onChange(entries.map { if (it.id == entry.id) it.copy(label = value) else it })
        })
        EditorField(entry.value, "值", { value ->
            onChange(entries.map { if (it.id == entry.id) it.copy(value = value) else it })
        })
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = entry.preferred, onCheckedChange = { checked ->
                onChange(entries.map { it.copy(preferred = checked && it.id == entry.id) })
            })
            Text("首选")
            TextButton(onClick = { onChange(entries.filterNot { it.id == entry.id }) }) { Text("移除") }
        }
    }
    if (entries.size < 20) TextButton(onClick = { onChange(entries + IdentityContactDraft()) }) {
        Text("添加$title")
    }
}

@Composable
private fun IdentityAddressesEditor(
    entries: List<IdentityAddressDraft>,
    onChange: (List<IdentityAddressDraft>) -> Unit,
) {
    Text("地址", style = MaterialTheme.typography.titleSmall)
    entries.forEachIndexed { index, entry ->
        Text("地址 ${index + 1}")
        fun update(transform: (IdentityAddressDraft) -> IdentityAddressDraft) {
            onChange(entries.map { if (it.id == entry.id) transform(it) else it })
        }
        EditorField(entry.label, "标签", { value -> update { it.copy(label = value) } })
        EditorField(entry.addressLine1, "地址第一行", { value -> update { it.copy(addressLine1 = value) } })
        EditorField(entry.addressLine2, "地址第二行", { value -> update { it.copy(addressLine2 = value) } })
        EditorField(entry.city, "城市", { value -> update { it.copy(city = value) } })
        EditorField(entry.region, "省州或地区", { value -> update { it.copy(region = value) } })
        EditorField(entry.postalCode, "邮编", { value -> update { it.copy(postalCode = value) } })
        EditorField(entry.countryCode, "国家代码（CN）", { value -> update { it.copy(countryCode = value.uppercase()) } })
        EditorField(entry.country, "国家或地区名称", { value -> update { it.copy(country = value) } })
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = entry.preferred, onCheckedChange = { checked ->
                onChange(entries.map { it.copy(preferred = checked && it.id == entry.id) })
            })
            Text("首选")
            TextButton(onClick = { onChange(entries.filterNot { it.id == entry.id }) }) { Text("移除") }
        }
    }
    if (entries.size < 20) TextButton(onClick = { onChange(entries + IdentityAddressDraft()) }) {
        Text("添加地址")
    }
}

@Composable
fun OtherEditorDialog(draft: OtherDraft, busy: Boolean, viewModel: VaultViewModel) {
    val canSave = draft.title.isNotBlank() && !busy && when (draft) {
        is OtherDraft.Card -> draft.month.toIntOrNull() != null && draft.year.toIntOrNull() != null &&
            (draft.id != null || draft.number.isNotBlank())
        is OtherDraft.Ssh -> draft.port.toIntOrNull() != null
        is OtherDraft.Secret -> draft.id != null || draft.value.isNotBlank()
        is OtherDraft.Identity -> true
    }
    AlertDialog(
        onDismissRequest = viewModel::cancelOtherEditor,
        title = { Text(if (draft.id == null) "新增条目" else "编辑条目") },
        text = {
            Column(
                modifier = Modifier.heightIn(max = 500.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                when (draft) {
                    is OtherDraft.Card -> {
                        EditorField(draft.title, "标题", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(title = value) } })
                        EditorField(draft.holder, "持卡人", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(holder = value) } })
                        EditorField(draft.number, if (draft.id == null) "卡号" else "新卡号（留空保留）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(number = value) } }, secret = true)
                        EditorField(draft.month, "到期月份", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(month = value) } }, numeric = true)
                        EditorField(draft.year, "到期年份", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(year = value) } }, numeric = true)
                        EditorField(draft.securityCode, "安全码（留空保留）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(securityCode = value, clearSecurityCode = false) } }, secret = true)
                        if (draft.id != null) ClearField("清除现有安全码", draft.clearSecurityCode, { checked -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(clearSecurityCode = checked, securityCode = if (checked) "" else it.securityCode) } })
                        EditorField(draft.pin, "PIN（留空保留）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(pin = value, clearPin = false) } }, secret = true)
                        if (draft.id != null) ClearField("清除现有 PIN", draft.clearPin, { checked -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(clearPin = checked, pin = if (checked) "" else it.pin) } })
                        EditorField(draft.issuer, "发卡机构", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(issuer = value) } })
                        EditorField(draft.network, "卡组织", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(network = value) } })
                        EditorField(draft.billingAddress, "账单地址", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(billingAddress = value) } }, multiline = true)
                        EditorField(draft.notes, "备注", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(notes = value) } }, multiline = true)
                        EditorField(draft.folder, "文件夹", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(folder = value) } })
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = draft.favorite, onCheckedChange = { checked ->
                                viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(favorite = checked) }
                            })
                            Text("收藏")
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = draft.masterPasswordReprompt, onCheckedChange = { checked ->
                                viewModel.updateOtherDraft { (it as OtherDraft.Card).copy(masterPasswordReprompt = checked) }
                            })
                            Text("使用时要求主密码")
                        }
                    }
                    is OtherDraft.Ssh -> {
                        EditorField(draft.title, "标题", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(title = value) } })
                        EditorField(draft.host, "主机", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(host = value) } })
                        EditorField(draft.port, "端口", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(port = value) } }, numeric = true)
                        EditorField(draft.username, "用户名", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(username = value) } })
                        EditorField(draft.password, "密码（留空保留）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(password = value, clearPassword = false) } }, secret = true)
                        if (draft.id != null) ClearField("清除密码", draft.clearPassword, { checked -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(clearPassword = checked, password = if (checked) "" else it.password) } })
                        EditorField(draft.publicKey, "公钥（留空保留）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(publicKey = value, clearPublicKey = false) } }, multiline = true)
                        if (draft.id != null) ClearField("清除公钥", draft.clearPublicKey, { checked -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(clearPublicKey = checked, publicKey = if (checked) "" else it.publicKey) } })
                        EditorField(draft.privateKey, "私钥（留空保留）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(privateKey = value, clearPrivateKey = false) } }, secret = true, multiline = true)
                        if (draft.id != null) ClearField("清除私钥", draft.clearPrivateKey, { checked -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(clearPrivateKey = checked, privateKey = if (checked) "" else it.privateKey) } })
                        EditorField(draft.passphrase, "密钥口令（留空保留）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(passphrase = value, clearPassphrase = false) } }, secret = true)
                        if (draft.id != null) ClearField("清除口令", draft.clearPassphrase, { checked -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(clearPassphrase = checked, passphrase = if (checked) "" else it.passphrase) } })
                        EditorField(draft.notes, "备注", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(notes = value) } }, multiline = true)
                        EditorField(draft.folder, "文件夹", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(folder = value) } })
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = draft.favorite, onCheckedChange = { checked ->
                                viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(favorite = checked) }
                            })
                            Text("收藏")
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = draft.masterPasswordReprompt, onCheckedChange = { checked ->
                                viewModel.updateOtherDraft { (it as OtherDraft.Ssh).copy(masterPasswordReprompt = checked) }
                            })
                            Text("使用时要求主密码")
                        }
                    }
                    is OtherDraft.Identity -> {
                        EditorField(draft.title, "标题", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(title = value) } })
                        EditorField(draft.firstName, "名", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(firstName = value) } })
                        EditorField(draft.middleName, "中间名", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(middleName = value) } })
                        EditorField(draft.lastName, "姓", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(lastName = value) } })
                        EditorField(draft.birthDate, "出生日期（YYYY-MM-DD）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(birthDate = value) } })
                        IdentityContactsEditor("电子邮件", draft.emails) { entries ->
                            viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(emails = entries) }
                        }
                        IdentityContactsEditor("电话号码", draft.phones) { entries ->
                            viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(phones = entries) }
                        }
                        IdentityAddressesEditor(draft.addresses) { entries ->
                            viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(addresses = entries) }
                        }
                        EditorField(draft.organization, "组织", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(organization = value) } })
                        EditorField(draft.department, "部门", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(department = value) } })
                        EditorField(draft.jobTitle, "职位", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(jobTitle = value) } })
                        EditorField(draft.website, "网站 URL", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(website = value) } })
                        EditorField(draft.notes, "备注", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(notes = value) } }, multiline = true)
                        EditorField(draft.folder, "文件夹", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(folder = value) } })
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = draft.favorite, onCheckedChange = { checked ->
                                viewModel.updateOtherDraft { (it as OtherDraft.Identity).copy(favorite = checked) }
                            })
                            Text("收藏")
                        }
                    }
                    is OtherDraft.Secret -> {
                        EditorField(draft.title, "标题", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(title = value) } })
                        if (draft.id == null) EditorField(draft.kind, "类型（如 api-key）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(kind = value) } })
                        else Text("类型：${draft.kind}")
                        EditorField(draft.provider, "服务商", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(provider = value) } })
                        EditorField(draft.account, "账号", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(account = value) } })
                        EditorField(draft.value, if (draft.id == null) "密钥值" else "新值（留空保留）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(value = value) } }, secret = true)
                        EditorField(draft.environment, "环境", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(environment = value) } })
                        EditorField(draft.scopes, "Scopes（每行一个）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(scopes = value) } }, multiline = true)
                        EditorField(draft.expiresAt, "到期日（YYYY-MM-DD）", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(expiresAt = value) } })
                        EditorField(draft.website, "网站 URL", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(website = value) } })
                        EditorField(draft.notes, "备注", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(notes = value) } }, multiline = true)
                        EditorField(draft.folder, "文件夹", { value -> viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(folder = value) } })
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = draft.favorite, onCheckedChange = { checked ->
                                viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(favorite = checked) }
                            })
                            Text("收藏")
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = draft.masterPasswordReprompt, onCheckedChange = { checked ->
                                viewModel.updateOtherDraft { (it as OtherDraft.Secret).copy(masterPasswordReprompt = checked) }
                            })
                            Text("使用时要求主密码")
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = viewModel::saveOther, enabled = canSave) { Text("保存") } },
        dismissButton = { TextButton(onClick = viewModel::cancelOtherEditor, enabled = !busy) { Text("取消") } },
    )
}
