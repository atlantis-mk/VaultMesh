package com.vaultmesh.app

import org.junit.Assert.*
import org.junit.Test

class LanPairingStateTest {
    private val ref = "lan-peer-0123456789abcdef0123456789abcdef"
    private fun status(peerStatus: String = "unverified", trusted: Boolean = false, open: Boolean = true) =
        LanStatus(open, 10000, "123456", listOf(LanNearby(ref, peerStatus)),
            if (trusted) listOf(LanTrusted(ref, "Desktop", 2)) else emptyList())

    @Test fun pairingCompletesOnlyWhenTrustAppearsAndNotifiesOnce() {
        val submitted = LanPanelState(status = status(), pairingRef = ref, pairingPending = true)
        val connecting = submitted.withStatus(status("connecting"))
        assertTrue(connecting.pairingPending)
        assertEquals(ref, connecting.pairingRef)
        assertNull(connecting.notice)
        val connectedWithoutTrust = connecting.withStatus(status("connected"))
        assertNull(connectedWithoutTrust.notice)
        val done = connecting.withStatus(status("connected", trusted = true))
        assertNull(done.pairingRef)
        assertFalse(done.pairingPending)
        assertEquals("", done.codeInput)
        assertEquals(1, done.noticeId)
        assertEquals(done.noticeId, done.withStatus(status("connected", trusted = true)).noticeId)
    }

    @Test fun initialTrustDoesNotAnnounceNewPairingButIncomingTrustDoes() {
        val initial = LanPanelState().withStatus(status(trusted = true))
        assertNull(initial.notice)
        val incoming = LanPanelState(status = status()).withStatus(status(trusted = true))
        assertEquals(1, incoming.noticeId)
    }

    @Test fun failureCanRetryButExhaustedConnectingAndInvalidCodesCannot() {
        val failed = LanPanelState(status = status(), pairingRef = ref, pairingPending = true)
            .withStatus(status("code-rejected"))
        assertFalse(failed.pairingPending)
        assertNotNull(failed.error)
        assertTrue(failed.copy(codeInput = "123456").canBeginPairing())
        for (value in listOf("", "12345", "1234567", "１２３４５６", "12345x")) {
            assertFalse(failed.copy(codeInput = value).canBeginPairing())
        }
        for (state in listOf("code-attempts-exhausted", "connecting", "connected", "identity-changed", "peer-identity-rejected")) {
            assertFalse(failed.withStatus(status(state)).copy(codeInput = "123456").canBeginPairing())
        }
        assertFalse(failed.copy(codeInput = "123456", busy = true).canBeginPairing())
    }

    @Test fun expiryAndDisappearanceClearTransientInput() {
        val draft = LanPanelState(status = status(), pairingRef = ref, codeInput = "123456", pairingPending = true)
        for (next in listOf(status(open = false), status().copy(nearby = emptyList()))) {
            val cleared = draft.withStatus(next)
            assertNull(cleared.pairingRef)
            assertEquals("", cleared.codeInput)
            assertFalse(cleared.pairingPending)
        }
        val cleared = draft.copy(renameRef = ref, revokeRef = ref, labelInput = "draft", error = "old error").clearAction()
        assertNull(cleared.renameRef)
        assertNull(cleared.revokeRef)
        assertEquals("", cleared.labelInput)
        assertNull(cleared.error)
    }
}
