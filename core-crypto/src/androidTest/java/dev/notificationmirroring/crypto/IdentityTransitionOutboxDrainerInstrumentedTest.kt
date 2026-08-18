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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IdentityTransitionOutboxDrainerInstrumentedTest {
    @Test
    fun retriesExactTransitionWithFreshEnvelopeAndDoesNotAdvanceOnSendFalse() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val localName = "transition-outbox-${UUID.randomUUID()}"
        var local = AndroidLocalIdentityTransitionStore(context, localName)
        val senderPeers = AndroidTrustedPeerStore(context, "transition-sender-${UUID.randomUUID()}")
        val receiverPeers = AndroidTrustedPeerStore(context, "transition-receiver-${UUID.randomUUID()}")
        val replay = AndroidReplayLedger(context, "transition-replay-${UUID.randomUUID()}")
        val current = AuthenticatedHpke.generateKeyPair()
        val pending = AuthenticatedHpke.generateKeyPair()
        val peer = AuthenticatedHpke.generateKeyPair()
        val workspaceId = ByteArray(16) { 1 }
        val senderDeviceId = ByteArray(16) { 2 }
        val peerDeviceId = ByteArray(16) { 3 }
        val transitionId = ByteArray(16) { 4 }
        val currentKeyId = sha256(current.publicKey)
        val peerKeyId = sha256(peer.publicKey)
        val canonicalTransition = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                .setIdentityKeyTransition(
                    IdentityKeyTransition.newBuilder()
                        .setTransitionId(ByteString.copyFrom(transitionId))
                        .setPreviousKeyId(ByteString.copyFrom(currentKeyId))
                        .setNewPublicKey(ByteString.copyFrom(pending.publicKey))
                        .setNewKeyId(ByteString.copyFrom(sha256(pending.publicKey))),
                )
                .build(),
        )
        val now = 1_800_000_000_000L
        val attempted = mutableListOf<ByteArray>()
        val random = object : SecureRandom() {
            private var next = 6
            override fun nextBytes(bytes: ByteArray) = bytes.fill(next++.toByte())
        }
        fun drainer() = IdentityTransitionOutboxDrainer(
            workspaceId,
            senderDeviceId,
            current,
            pending,
            currentKeyId,
            local,
            senderPeers,
            random,
        )
        try {
            senderPeers.pinApproved(workspaceId, peerDeviceId, peer.publicKey)
            receiverPeers.pinApproved(workspaceId, senderDeviceId, current.publicKey)
            local.create(
                workspaceId,
                senderDeviceId,
                canonicalTransition,
                listOf(AndroidLocalIdentityTransitionStore.PeerSnapshot(peerDeviceId, peerKeyId)),
                now,
            )
            assertEquals(
                IdentityTransitionOutboxDrainer.DrainResult(0, 1, null),
                drainer().drainDue(now) { frame ->
                    attempted += frame.copyOf()
                    false
                },
            )
            assertEquals(0, local.loadPeer(peerDeviceId, now)!!.commitAttemptCount)

            local.close()
            local = AndroidLocalIdentityTransitionStore(context, localName)
            assertEquals(
                IdentityTransitionOutboxDrainer.DrainResult(1, 1, 1_000),
                drainer().drainDue(now) { frame ->
                    attempted += frame.copyOf()
                    true
                },
            )
            assertNotEquals(attempted[0].toList(), attempted[1].toList())
            val received = AuthenticatedEnvelopeReceiver.receiveIdentityTransitionOnce(
                attempted[1],
                EnvelopeRecipientContext(
                    workspaceId,
                    peerDeviceId,
                    peer,
                    current.publicKey,
                ),
                receiverPeers,
                replay,
                now,
            )
            assertEquals(
                canonicalTransition.toList(),
                received.accepted.state.canonicalTransition.toList(),
            )
            assertEquals(1, local.loadPeer(peerDeviceId, now)!!.commitAttemptCount)
        } finally {
            current.privateKey.fill(0)
            pending.privateKey.fill(0)
            peer.privateKey.fill(0)
            replay.clear()
            receiverPeers.clear()
            senderPeers.clear()
            local.clear()
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
