package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedEnvelopePartsV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransition
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionAck
import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidLocalIdentityTransitionStoreInstrumentedTest {
    @Test
    fun exactAckAndCommitSurviveStoreReconstruction() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val storeName = "local-${UUID.randomUUID()}"
        val fixture = fixture()
        val store = AndroidLocalIdentityTransitionStore(context, storeName)
        var reconstructed: AndroidLocalIdentityTransitionStore? = null
        try {
            store.create(
                fixture.workspaceId,
                fixture.localDeviceId,
                fixture.canonicalTransition,
                listOf(AndroidLocalIdentityTransitionStore.PeerSnapshot(
                    fixture.peerDeviceId,
                    fixture.peerKeyId,
                )),
                fixture.now,
            )
            val accepted = store.acceptAck(
                fixture.peerDeviceId,
                fixture.peerKeyId,
                fixture.canonicalAck,
                fixture.now + 1,
            )
            assertEquals(AndroidLocalIdentityTransitionStore.AcceptResult.ACCEPTED, accepted.result)
            assertArrayEquals(fixture.canonicalAck, accepted.peer.canonicalAck)
            val commit = EncryptedPayloadCodecV1.decode(accepted.peer.canonicalCommit!!)
            assertEquals(EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_COMMIT, commit.bodyCase)
            assertArrayEquals(
                sha256(fixture.canonicalAck),
                commit.identityKeyTransitionCommit.ackSha256.toByteArray(),
            )

            store.close()
            val recovered = AndroidLocalIdentityTransitionStore(context, storeName)
            reconstructed = recovered
            val duplicate = recovered.acceptAck(
                fixture.peerDeviceId,
                fixture.peerKeyId,
                fixture.canonicalAck,
                fixture.now + 2,
            )
            assertEquals(
                AndroidLocalIdentityTransitionStore.AcceptResult.ALREADY_ACCEPTED,
                duplicate.result,
            )
            assertArrayEquals(accepted.peer.canonicalCommit, duplicate.peer.canonicalCommit)

            val wrongAck = canonicalAck(fixture, ByteArray(32) { 9 })
            assertThrows(IllegalStateException::class.java) {
                recovered.acceptAck(
                    fixture.peerDeviceId,
                    fixture.peerKeyId,
                    wrongAck,
                    fixture.now + 3,
                )
            }
            assertArrayEquals(
                accepted.peer.canonicalCommit,
                recovered.loadPeer(fixture.peerDeviceId, fixture.now + 4)!!.canonicalCommit,
            )
        } finally {
            reconstructed?.close()
            store.clear()
        }
    }

    @Test
    fun persistsAckAndCommitBeforeReplayConsumption() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val fixture = fixture()
        val store = AndroidLocalIdentityTransitionStore(context, "local-${UUID.randomUUID()}")
        val fullLedger = AndroidReplayLedger(context, "local-full-${UUID.randomUUID()}", maxEntries = 1)
        val recoveredLedger = AndroidReplayLedger(context, "local-recovered-${UUID.randomUUID()}")
        try {
            store.create(
                fixture.workspaceId,
                fixture.localDeviceId,
                fixture.canonicalTransition,
                listOf(AndroidLocalIdentityTransitionStore.PeerSnapshot(
                    fixture.peerDeviceId,
                    fixture.peerKeyId,
                )),
                fixture.now,
            )
            assertEquals(
                AndroidReplayLedger.Decision.ACCEPTED,
                fullLedger.checkAndRecord(
                    sha256(byteArrayOf(9)),
                    ByteArray(16) { 9 },
                    fixture.now + 60_000,
                    fixture.now,
                ),
            )
            val replayFailure = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.receivePendingIdentityAckOnce(
                    ackFrame(fixture, ByteArray(16) { 6 }),
                    fixture.recipientContext,
                    store,
                    fullLedger,
                    fixture.now + 1,
                )
            }
            assertEquals(
                EnvelopeRejectedException.Code.REPLAY_CAPACITY_EXCEEDED,
                replayFailure.code,
            )
            val durable = store.loadPeer(fixture.peerDeviceId, fixture.now + 2)!!
            assertArrayEquals(fixture.canonicalAck, durable.canonicalAck)
            assertNotNull(durable.canonicalCommit)

            val recovered = AuthenticatedEnvelopeReceiver.receivePendingIdentityAckOnce(
                ackFrame(fixture, ByteArray(16) { 7 }),
                fixture.recipientContext,
                store,
                recoveredLedger,
                fixture.now + 2,
            )
            assertEquals(
                AndroidLocalIdentityTransitionStore.AcceptResult.ALREADY_ACCEPTED,
                recovered.accepted.result,
            )
            assertArrayEquals(durable.canonicalCommit, recovered.accepted.peer.canonicalCommit)
        } finally {
            fullLedger.clear()
            recoveredLedger.clear()
            store.clear()
        }
    }

    @Test
    fun expiryBlocksAckWithoutGeneratingCommit() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val fixture = fixture()
        val store = AndroidLocalIdentityTransitionStore(context, "local-${UUID.randomUUID()}")
        try {
            val session = store.create(
                fixture.workspaceId,
                fixture.localDeviceId,
                fixture.canonicalTransition,
                listOf(AndroidLocalIdentityTransitionStore.PeerSnapshot(
                    fixture.peerDeviceId,
                    fixture.peerKeyId,
                )),
                fixture.now,
            )
            assertThrows(IllegalStateException::class.java) {
                store.acceptAck(
                    fixture.peerDeviceId,
                    fixture.peerKeyId,
                    fixture.canonicalAck,
                    session.expiresAtUnixMs,
                )
            }
            assertEquals(
                AndroidLocalIdentityTransitionStore.PeerPhase.AWAITING_ACK,
                store.loadPeer(fixture.peerDeviceId, session.expiresAtUnixMs + 1)!!.phase,
            )
        } finally {
            store.clear()
        }
    }

    private fun fixture(): Fixture {
        val current = AuthenticatedHpke.generateKeyPair()
        val pending = AuthenticatedHpke.generateKeyPair()
        val peer = AuthenticatedHpke.generateKeyPair()
        val previousKeyId = sha256(current.publicKey)
        val newKeyId = sha256(pending.publicKey)
        val transitionId = ByteArray(16) { 4 }
        val canonicalTransition = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                .setIdentityKeyTransition(
                    IdentityKeyTransition.newBuilder()
                        .setTransitionId(ByteString.copyFrom(transitionId))
                        .setPreviousKeyId(ByteString.copyFrom(previousKeyId))
                        .setNewPublicKey(ByteString.copyFrom(pending.publicKey))
                        .setNewKeyId(ByteString.copyFrom(newKeyId)),
                )
                .build(),
        )
        val transitionSha256 = sha256(canonicalTransition)
        return Fixture(
            now = 1_800_000_000_000L,
            workspaceId = ByteArray(16) { 1 },
            localDeviceId = ByteArray(16) { 2 },
            peerDeviceId = ByteArray(16) { 3 },
            peer = peer,
            peerKeyId = sha256(peer.publicKey),
            pending = pending,
            transitionId = transitionId,
            previousKeyId = previousKeyId,
            newKeyId = newKeyId,
            transitionSha256 = transitionSha256,
            canonicalTransition = canonicalTransition,
            canonicalAck = canonicalAck(
                transitionId,
                previousKeyId,
                newKeyId,
                transitionSha256,
            ),
        )
    }

    private fun canonicalAck(fixture: Fixture, digest: ByteArray): ByteArray = canonicalAck(
        fixture.transitionId,
        fixture.previousKeyId,
        fixture.newKeyId,
        digest,
    )

    private fun canonicalAck(
        transitionId: ByteArray,
        previousKeyId: ByteArray,
        newKeyId: ByteArray,
        digest: ByteArray,
    ): ByteArray = EncryptedPayloadCodecV1.encode(
        EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
            .setIdentityKeyTransitionAck(
                IdentityKeyTransitionAck.newBuilder()
                    .setTransitionId(ByteString.copyFrom(transitionId))
                    .setPreviousKeyId(ByteString.copyFrom(previousKeyId))
                    .setNewKeyId(ByteString.copyFrom(newKeyId))
                    .setTransitionSha256(ByteString.copyFrom(digest)),
            )
            .build(),
    )

    private fun ackFrame(fixture: Fixture, messageId: ByteArray): ByteArray {
        val header = RoutingHeaderCodecV1.encode(
            RoutingHeaderV1(
                workspaceId = fixture.workspaceId,
                senderDeviceId = fixture.peerDeviceId,
                recipientDeviceId = fixture.localDeviceId,
                senderKeyId = fixture.peerKeyId,
                recipientKeyId = fixture.newKeyId,
                messageId = messageId,
                sequence = messageId[0].toLong(),
                createdAtUnixMs = fixture.now,
                expiresAtUnixMs = fixture.now + 60_000,
            ),
        )
        val encrypted = AuthenticatedHpke.seal(
            fixture.pending.publicKey,
            fixture.peer,
            fixture.canonicalAck,
            header,
        )
        return EncryptedEnvelopeCodecV1.encode(
            EncryptedEnvelopePartsV1(header, encrypted.encapsulatedKey, encrypted.ciphertext),
        )
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private data class Fixture(
        val now: Long,
        val workspaceId: ByteArray,
        val localDeviceId: ByteArray,
        val peerDeviceId: ByteArray,
        val peer: AuthenticatedHpke.KeyPair,
        val peerKeyId: ByteArray,
        val pending: AuthenticatedHpke.KeyPair,
        val transitionId: ByteArray,
        val previousKeyId: ByteArray,
        val newKeyId: ByteArray,
        val transitionSha256: ByteArray,
        val canonicalTransition: ByteArray,
        val canonicalAck: ByteArray,
    ) {
        val recipientContext: EnvelopeRecipientContext
            get() = EnvelopeRecipientContext(
                workspaceId,
                localDeviceId,
                pending,
                peer.publicKey,
            )
    }
}
