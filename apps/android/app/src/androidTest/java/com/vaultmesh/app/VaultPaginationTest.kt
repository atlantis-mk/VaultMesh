package com.vaultmesh.app

import android.app.Application
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToIndex
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VaultPaginationTest {
    @get:Rule val compose = createComposeRule()

    @Test
    fun overviewAppendsThirtyRowsPerScrollBatch() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = VaultViewModel(app)
        val state = VaultUiState(
            status = "unlocked",
            busy = false,
            logins = (1..65).map { index ->
                LoginSummary("synthetic-$index", "Page $index", "", null, false, false, false)
            },
        )
        compose.setContent {
            VaultMeshTheme {
                UnlockedVaultScreen(
                    state = state,
                    viewModel = viewModel,
                    onBackup = {},
                    onRestore = {},
                    biometricEnabled = false,
                    onEnableBiometric = {},
                    onDisableBiometric = {},
                    pinEnabled = false,
                    onEnablePin = {},
                    onDisablePin = {},
                    onNearby = {},
                    onLeaveNearby = {},
                    nearbyContent = {},
                )
            }
        }

        compose.onNodeWithText("Page 31").assertDoesNotExist()
        compose.onNodeWithText("Page 61").assertDoesNotExist()
        compose.onNode(hasScrollToIndexAction()).performScrollToIndex(29)
        compose.waitForIdle()
        compose.onNode(hasScrollToIndexAction()).performScrollToIndex(30)
        compose.onNodeWithText("Page 31").assertExists()
        compose.onNodeWithText("Page 61").assertDoesNotExist()
        compose.onNode(hasScrollToIndexAction()).performScrollToIndex(59)
        compose.waitForIdle()
        compose.onNode(hasScrollToIndexAction()).performScrollToIndex(60)
        compose.onNodeWithText("Page 61").assertExists()

        compose.onNodeWithText("登录").performClick()
        compose.onNodeWithText("Page 31").assertDoesNotExist()
        compose.onNode(hasScrollToIndexAction()).performScrollToIndex(29)
        compose.waitForIdle()
        compose.onNode(hasScrollToIndexAction()).performScrollToIndex(30)
        compose.onNodeWithText("Page 31").assertExists()
    }
}
