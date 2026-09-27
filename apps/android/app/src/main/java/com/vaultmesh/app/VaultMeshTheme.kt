package com.vaultmesh.app

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

@Composable
internal fun VaultMeshTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = lightColorScheme(
        primary = Color(0xFF365BD8), onPrimary = Color.White,
        primaryContainer = Color(0xFFDCE4FF), onPrimaryContainer = Color(0xFF18346F),
        background = Color(0xFFF8FAFF), surface = Color(0xFFF8FAFF),
        surfaceVariant = Color(0xFFE9EEF9), onSurface = Color(0xFF151C2F),
        onSurfaceVariant = Color(0xFF59647D), outlineVariant = Color(0xFFD8DFED),
    ), content = content)
}
