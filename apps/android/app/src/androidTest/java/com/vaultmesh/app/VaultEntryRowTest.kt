package com.vaultmesh.app

import android.app.Application
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** CT-ANDROID-HOME-001: row actions stay reachable without opening an item. */
@RunWith(AndroidJUnit4::class)
class VaultEntryRowTest {
    @get:Rule val compose = createComposeRule()

    @Test fun copyMoreAndSelectionAreIndependent() {
        var copies = 0
        var edits = 0
        var selections = 0
        compose.setContent {
            VaultMeshTheme {
                VaultEntryRow(VaultSection.Logins, "Example login", "alice", false,
                    { selections += 1 }, { edits += 1 },
                    listOf(VaultRowAction("用户名") { copies += 1 }),
                    listOf(VaultRowAction("编辑") { edits += 1 }))
            }
        }
        compose.onNodeWithContentDescription("复制 Example login").performClick()
        compose.onNodeWithText("用户名").assertIsDisplayed().performClick()
        assertEquals(1, copies)
        assertEquals(0, edits)
        compose.onNodeWithContentDescription("Example login 的更多操作").performClick()
        compose.onNodeWithText("编辑").assertIsDisplayed().performClick()
        assertEquals(1, edits)
        compose.onNodeWithContentDescription("选择 Example login").performClick()
        assertEquals(1, selections)
    }

    @Test fun visibleSelectionAndSecretDeletionRequireConfirmation() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = VaultViewModel(app)
        val state = VaultUiState(status = "unlocked", busy = false,
            secrets = listOf(SecretSummary("synthetic-id", "Synthetic secret", "api", null, null)))
        compose.setContent {
            VaultMeshTheme {
                UnlockedVaultScreen(state, viewModel, {}, {}, false, {}, {}, false, {}, {},
                    {}, {}) { }
            }
        }
        compose.onNodeWithText("全选本页").performClick()
        compose.onNodeWithText("已选择 1 项").assertIsDisplayed()
        compose.onNodeWithText("删除").performClick()
        compose.onNodeWithText("密钥会永久删除；其他类型会进入加密回收站。批量操作可能部分完成，请在失败后检查列表。")
            .assertIsDisplayed()
        compose.onNodeWithText("取消").performClick()
        compose.onNodeWithText("已选择 1 项").assertIsDisplayed()
        compose.onNodeWithText("取消选择").performClick()
        compose.onNodeWithText("全选本页").assertIsDisplayed()
    }

    @Test fun toolsAndSettingsShowDesignedGroups() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = VaultViewModel(app)
        compose.setContent {
            VaultMeshTheme {
                UnlockedVaultScreen(VaultUiState(status = "unlocked", busy = false), viewModel,
                    {}, {}, false, {}, {}, false, {}, {}, {}, {}) { }
            }
        }
        compose.onNodeWithText("工具").performClick()
        compose.onNodeWithText("凭据生成器").assertExists()
        compose.onNodeWithText("密码健康").assertExists()
        compose.onNodeWithText("备份与恢复").assertExists()
        compose.onNodeWithText("设置").performClick()
        compose.onNodeWithText("自动填充").assertExists()
        compose.onNodeWithText("解锁与安全").assertExists()
        compose.onNodeWithText("主密码").assertExists()
    }
}
