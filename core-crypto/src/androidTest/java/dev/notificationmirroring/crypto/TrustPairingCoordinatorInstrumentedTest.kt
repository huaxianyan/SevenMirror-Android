package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TrustPairingCoordinatorInstrumentedTest {
    private val now = 1_800_000_000_000L

    @Test
    fun durableRolesPinOnlyAfterEachExplicitMatchingConfirmation() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val suffix = UUID.randomUUID().toString()
        val offerSessions = AndroidTrustPairingSessionStore(context, "offer-$suffix")
        val approvalSessions = AndroidTrustPairingSessionStore(context, "approval-$suffix")
        val offerPeers = AndroidTrustedPeerStore(context, "offer-$suffix")
        val approvalPeers = AndroidTrustedPeerStore(context, "approval-$suffix")
        val offerer = identity(1, 2)
        val approver = identity(1, 3)
        try {
            val offerView = coordinator(offerSessions, offerPeers, 0x41).createOffer(offerer, now)
            assertThrows(IllegalStateException::class.java) {
                coordinator(offerSessions, offerPeers, 0x42).createOffer(offerer, now + 1)
            }
            val approvalView = coordinator(approvalSessions, approvalPeers, 0x52).acceptOffer(
                offerView.offerQr,
                approver,
                now + 1_000,
            )
            assertNotNull(approvalView.approvalQr)
            val offerCompare = coordinator(offerSessions, offerPeers, 0x63).acceptApproval(
                checkNotNull(approvalView.approvalQr),
                offerer,
                now + 2_000,
            )
            assertEquals(approvalView.safetyCode, offerCompare.safetyCode)

            val resumedOffer = coordinator(offerSessions, offerPeers, 0x64).resume(offerer, now + 3_000)
            val resumedApproval = coordinator(approvalSessions, approvalPeers, 0x65)
                .resume(approver, now + 3_000)
            assertEquals(TrustPairingRole.OFFERER, (resumedOffer as TrustPairingView.CompareSafetyCode).role)
            assertEquals(
                TrustPairingRole.APPROVER,
                (resumedApproval as TrustPairingView.CompareSafetyCode).role,
            )

            assertThrows(IllegalStateException::class.java) {
                coordinator(offerSessions, offerPeers, 0x66).confirmSafetyCode(
                    "0000-0000-0000",
                    offerer,
                    now + 4_000,
                )
            }
            assertNull(
                offerPeers.findApproved(
                    offerer.workspaceId,
                    approver.deviceId,
                    sha256(approver.publicKey),
                ),
            )
            assertNotNull(offerSessions.load())

            assertEquals(
                AndroidTrustedPeerStore.PinResult.PINNED,
                coordinator(offerSessions, offerPeers, 0x67).confirmSafetyCode(
                    offerCompare.safetyCode,
                    offerer,
                    now + 4_000,
                ),
            )
            assertArrayEquals(
                approver.publicKey,
                offerPeers.findApproved(
                    offerer.workspaceId,
                    approver.deviceId,
                    sha256(approver.publicKey),
                ),
            )
            assertNull(offerSessions.load())

            assertEquals(
                AndroidTrustedPeerStore.PinResult.PINNED,
                coordinator(approvalSessions, approvalPeers, 0x68).confirmSafetyCode(
                    approvalView.safetyCode,
                    approver,
                    now + 5_000,
                ),
            )
            assertArrayEquals(
                offerer.publicKey,
                approvalPeers.findApproved(
                    approver.workspaceId,
                    offerer.deviceId,
                    sha256(offerer.publicKey),
                ),
            )
            assertNull(approvalSessions.load())
        } finally {
            offerSessions.clear()
            approvalSessions.clear()
            offerPeers.clear()
            approvalPeers.clear()
        }
    }

    @Test
    fun crossWorkspaceAndExpiredOffersNeverCreateApproverSession() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val suffix = UUID.randomUUID().toString()
        val offerSessions = AndroidTrustPairingSessionStore(context, "offer-reject-$suffix")
        val approvalSessions = AndroidTrustPairingSessionStore(context, "approval-reject-$suffix")
        val offerPeers = AndroidTrustedPeerStore(context, "offer-reject-$suffix")
        val approvalPeers = AndroidTrustedPeerStore(context, "approval-reject-$suffix")
        val offerer = identity(1, 2)
        val otherWorkspace = identity(9, 3)
        try {
            val offer = coordinator(offerSessions, offerPeers, 0x21).createOffer(offerer, now)
            assertThrows(IllegalArgumentException::class.java) {
                coordinator(approvalSessions, approvalPeers, 0x22).acceptOffer(
                    offer.offerQr,
                    otherWorkspace,
                    now + 1,
                )
            }
            assertNull(approvalSessions.load())
            assertThrows(IllegalArgumentException::class.java) {
                coordinator(approvalSessions, approvalPeers, 0x23).acceptOffer(
                    offer.offerQr,
                    otherWorkspace.copy(workspaceId = offerer.workspaceId),
                    now + 600_000,
                )
            }
            assertNull(approvalSessions.load())
        } finally {
            offerSessions.clear()
            approvalSessions.clear()
            offerPeers.clear()
            approvalPeers.clear()
        }
    }

    private fun coordinator(
        sessions: AndroidTrustPairingSessionStore,
        peers: AndroidTrustedPeerStore,
        randomByte: Int,
    ) = TrustPairingCoordinator(sessions, peers) { size -> ByteArray(size) { randomByte.toByte() } }

    private fun identity(workspaceByte: Int, deviceByte: Int): LocalTrustIdentity = LocalTrustIdentity(
        workspaceId = ByteArray(16) { workspaceByte.toByte() },
        deviceId = ByteArray(16) { deviceByte.toByte() },
        publicKey = AuthenticatedHpke.generateKeyPair().publicKey,
    )

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
