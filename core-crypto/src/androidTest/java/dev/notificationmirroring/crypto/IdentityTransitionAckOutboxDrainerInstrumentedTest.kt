package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransition
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IdentityTransitionAckOutboxDrainerInstrumentedTest {
    @Test
    fun restoresExactAckIntentAndUsesFreshEnvelopeTuples() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val storeName = "transition-ack-${UUID.randomUUID()}"
        var peers = AndroidTrustedPeerStore(context, storeName)
        val workspaceId = ByteArray(16) { 1 }
        val localDeviceId = ByteArray(16) { 2 }
        val peerDeviceId = ByteArray(16) { 3 }
        val localIdentity = AuthenticatedHpke.generateKeyPair()
        val peerOldIdentity = AuthenticatedHpke.generateKeyPair()
        val peerNewIdentity = AuthenticatedHpke.generateKeyPair()
        val transitionId = ByteArray(16) { 4 }
        val previousKeyId = sha256(peerOldIdentity.publicKey)
        val newKeyId = sha256(peerNewIdentity.publicKey)
        val canonicalTransition = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                .setIdentityKeyTransition(
                    IdentityKeyTransition.newBuilder()
                        .setTransitionId(ByteString.copyFrom(transitionId))
                        .setPreviousKeyId(ByteString.copyFrom(previousKeyId))
                        .setNewPublicKey(ByteString.copyFrom(peerNewIdentity.publicKey))
                        .setNewKeyId(ByteString.copyFrom(newKeyId)),
                )
                .build(),
        )
        val now = 1_800_000_000_000L
        val attempted = mutableListOf<ByteArray>()
        val sent = mutableListOf<ByteArray>()
        var socketAccepted = false
        val random = object : SecureRandom() {
            private var next = 6
            override fun nextBytes(bytes: ByteArray) {
                bytes.fill(next++.toByte())
            }
        }
        fun drainer() = IdentityTransitionAckOutboxDrainer(
            workspaceId,
            localDeviceId,
            localIdentity,
            sha256(localIdentity.publicKey),
            peers,
            random,
        )
        val firstReplay = AndroidReplayLedger(context, "transition-ack-first-${UUID.randomUUID()}")
        val secondReplay = AndroidReplayLedger(context, "transition-ack-second-${UUID.randomUUID()}")
        try {
            peers.pinApproved(workspaceId, peerDeviceId, peerOldIdentity.publicKey)
            val accepted = peers.acceptIdentityTransition(
                workspaceId,
                peerDeviceId,
                canonicalTransition,
                now,
            )
            assertEquals(
                IdentityTransitionAckOutboxDrainer.DrainResult(0, 1, null),
                drainer().drainDue(now) { frame ->
                    attempted += frame.copyOf()
                    socketAccepted
                },
            )
            assertEquals(
                0,
                peers.loadIdentityTransition(workspaceId, peerDeviceId, now)!!.ackAttemptCount,
            )

            peers.close()
            peers = AndroidTrustedPeerStore(context, storeName)
            socketAccepted = true
            assertEquals(
                IdentityTransitionAckOutboxDrainer.DrainResult(1, 1, 1_000),
                drainer().drainDue(now) { frame ->
                    attempted += frame.copyOf()
                    sent += frame.copyOf()
                    socketAccepted
                },
            )
            val binding = PendingIdentityAckBinding(
                senderDeviceId = localDeviceId,
                transitionId = transitionId,
                previousKeyId = previousKeyId,
                newKeyId = newKeyId,
                transitionSha256 = accepted.state.transitionSha256,
            )
            val recipientContext = EnvelopeRecipientContext(
                workspaceId,
                peerDeviceId,
                peerNewIdentity,
                localIdentity.publicKey,
            )
            val refused = AuthenticatedEnvelopeReceiver.openPendingIdentityAckOnce(
                attempted[0],
                recipientContext,
                binding,
                firstReplay,
                now,
            )
            val delivered = AuthenticatedEnvelopeReceiver.openPendingIdentityAckOnce(
                sent[0],
                recipientContext,
                binding,
                secondReplay,
                now,
            )
            assertArrayEquals(accepted.state.canonicalAck, refused.canonicalPayload)
            assertArrayEquals(accepted.state.canonicalAck, delivered.canonicalPayload)
            assertNotEquals(refused.header.messageId.toList(), delivered.header.messageId.toList())
            assertEquals(1L, refused.header.sequence)
            assertEquals(2L, delivered.header.sequence)
            assertEquals(
                1,
                peers.loadIdentityTransition(workspaceId, peerDeviceId, now)!!.ackAttemptCount,
            )
        } finally {
            firstReplay.clear()
            secondReplay.clear()
            peers.clear()
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
