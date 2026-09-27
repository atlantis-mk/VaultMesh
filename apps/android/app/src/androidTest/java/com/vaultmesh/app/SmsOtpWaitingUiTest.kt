package com.vaultmesh.app

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.click
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.math.abs

@RunWith(AndroidJUnit4::class)
class SmsOtpWaitingUiTest {
    @get:Rule val compose = createComposeRule()

    @Test fun waitingCardIsCenteredOpaqueAndBothCancelPathsWork() {
        var cancels = 0
        compose.setContent { SmsOtpWaitingContent { cancels++ } }
        val root = compose.onRoot().fetchSemanticsNode().boundsInRoot
        val cardNode = compose.onNodeWithTag("smsOtpWaitingCard", useUnmergedTree = true)
        val card = cardNode.fetchSemanticsNode().boundsInRoot
        assertTrue(abs(card.center.y - root.center.y) < root.height * 0.1f)
        val image = cardNode.captureToImage().toPixelMap()
        assertEquals(1f, image[image.width / 2, image.height / 2].alpha, 0.01f)
        compose.onNodeWithText("等待短信验证码").assertExists()
        compose.onNodeWithText("取消").performClick()
        compose.runOnIdle { assertEquals(1, cancels) }
        compose.onRoot().performTouchInput { click(Offset(4f, 4f)) }
        compose.runOnIdle { assertEquals(2, cancels) }
    }
}
