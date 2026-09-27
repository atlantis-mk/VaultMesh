package com.vaultmesh.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

internal data class VaultRowAction(val label: String, val onClick: () -> Unit)
data class VaultSelection(val section: VaultSection, val id: String)

@Composable
internal fun VaultEntryRow(
    section: VaultSection,
    title: String,
    subtitle: String,
    selected: Boolean,
    onSelect: (() -> Unit)?,
    onOpen: (() -> Unit)?,
    copyActions: List<VaultRowAction>,
    moreActions: List<VaultRowAction>,
) {
    var copyExpanded by remember(section, title) { mutableStateOf(false) }
    var moreExpanded by remember(section, title) { mutableStateOf(false) }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            if (onSelect != null) {
                Checkbox(checked = selected, onCheckedChange = { onSelect() },
                    modifier = Modifier.size(44.dp).semantics { contentDescription = "选择 $title" })
            }
            Box(
                modifier = Modifier.size(36.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(sectionName(section).take(1), color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.titleMedium)
            }
            Column(
                modifier = Modifier.weight(1f).then(if (onOpen == null) Modifier else Modifier.clickable(onClick = onOpen))
                    .padding(horizontal = 4.dp, vertical = 6.dp),
            ) {
                Text(title, style = MaterialTheme.typography.titleMedium, maxLines = 1,
                    overflow = TextOverflow.Ellipsis)
                if (subtitle.isNotBlank()) Text(subtitle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1,
                    overflow = TextOverflow.Ellipsis)
            }
            if (copyActions.isNotEmpty()) Box {
                IconButton(onClick = { copyExpanded = true }, modifier = Modifier.size(40.dp)) {
                    Icon(painterResource(R.drawable.ic_copy), contentDescription = "复制 $title")
                }
                DropdownMenu(expanded = copyExpanded, onDismissRequest = { copyExpanded = false }) {
                    copyActions.forEach { action ->
                        DropdownMenuItem(text = { Text(action.label) }, onClick = {
                            copyExpanded = false
                            action.onClick()
                        })
                    }
                }
            }
            Box {
                IconButton(onClick = { moreExpanded = true }, modifier = Modifier.size(40.dp)) {
                    Icon(painterResource(R.drawable.ic_lan_more_vert), contentDescription = "$title 的更多操作")
                }
                DropdownMenu(expanded = moreExpanded, onDismissRequest = { moreExpanded = false }) {
                    if (moreActions.isEmpty()) DropdownMenuItem(
                        text = { Text("由桌面管理") }, onClick = {}, enabled = false)
                    moreActions.forEach { action ->
                        DropdownMenuItem(text = { Text(action.label) }, onClick = {
                            moreExpanded = false
                            action.onClick()
                        })
                    }
                }
            }
        }
    }
}
