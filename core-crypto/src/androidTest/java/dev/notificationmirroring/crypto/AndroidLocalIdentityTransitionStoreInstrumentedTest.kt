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
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionCommit
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
    fun commitDeliveryPromotesPeerBeforeReplayAndDuplicateUsesTombstone() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val fixture = fixture()
        val local = AndroidLocalIdentityTransitionStore(context, "local-${UUID.randomUUID()}")
        val receiverPeers = AndroidTrustedPeerStore(context, "receiver-${UUID.randomUUID()}")
        val senderPeers = AndroidTrustedPeerStore(context, "sender-${UUID.randomUUID()}")
        val fullLedger = AndroidReplayLedger(context, "commit-full-${UUID.randomUUID()}", maxEntries = 1)
        val recoveredLedger = AndroidReplayLedger(context, "commit-recovered-${UUID.randomUUID()}")
        try {
            receiverPeers.pinApproved(
                fixture.workspaceId,
                fixture.localDeviceId,
                fixture.current.publicKey,
            )
            val acceptedTransition = receiverPeers.acceptIdentityTransition(
                fixture.workspaceId,
                fixture.localDeviceId,
                fixture.canonicalTransition,
                fixture.now,
            )
            val wrongCommit = EncryptedPayloadCodecV1.encode(
                EncryptedPayload.newBuilder()
                    .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                    .setIdentityKeyTransitionCommit(
                        IdentityKeyTransitionCommit.newBuilder()
                            .setTransitionId(ByteString.copyFrom(fixture.transitionId))
                            .setPreviousKeyId(ByteString.copyFrom(fixture.previousKeyId))
                            .setNewKeyId(ByteString.copyFrom(fixture.newKeyId))
                            .setTransitionSha256(ByteString.copyFrom(fixture.transitionSha256))
                            .setAckSha256(ByteString.copyFrom(ByteArray(32) { 9 })),
                    )
                    .build(),
            )
            assertThrows(IllegalStateException::class.java) {
                receiverPeers.commitIdentityTransition(
                    fixture.workspaceId,
                    fixture.localDeviceId,
                    fixture.newKeyId,
                    wrongCommit,
                    fixture.now + 1,
                )
            }
            assertArrayEquals(
                fixture.current.publicKey,
                receiverPeers.findApproved(
                    fixture.workspaceId,
                    fixture.localDeviceId,
                    fixture.previousKeyId,
                ),
            )

            senderPeers.pinApproved(
                fixture.workspaceId,
                fixture.peerDeviceId,
                fixture.peer.publicKey,
            )
            local.create(
                fixture.workspaceId,
                fixture.localDeviceId,
                fixture.canonicalTransition,
                listOf(AndroidLocalIdentityTransitionStore.PeerSnapshot(
                    fixture.peerDeviceId,
                    fixture.peerKeyId,
                )),
                fixture.now,
            )
            local.acceptAck(
                fixture.peerDeviceId,
                fixture.peerKeyId,
                acceptedTransition.state.canonicalAck,
                fixture.now + 1,
            )
            val frames = mutableListOf<ByteArray>()
            val drainer = IdentityTransitionCommitOutboxDrainer(
                workspaceId = fixture.workspaceId,
                senderDeviceId = fixture.localDeviceId,
                currentIdentity = fixture.current,
                pendingIdentity = fixture.pending,
                transportIdentityKeyId = fixture.previousKeyId,
                localTransitions = local,
                trustedPeers = senderPeers,
                random = java.security.SecureRandom(byteArrayOf(1, 2, 3)),
            )
            assertEquals(0, drainer.drainDue(fixture.now + 2) { false }.acceptedSends)
            assertEquals(
                0,
                local.loadPeer(fixture.peerDeviceId, fixture.now + 2)!!.commitAttemptCount,
            )
            assertEquals(1, drainer.drainDue(fixture.now + 2) {
                frames += it.copyOf()
                true
            }.acceptedSends)
            assertEquals(
                AndroidReplayLedger.Decision.ACCEPTED,
                fullLedger.checkAndRecord(
                    sha256(byteArrayOf(8)),
                    ByteArray(16) { 8 },
                    fixture.now + 60_000,
                    fixture.now,
                ),
            )
            val replayFailure = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.receiveIdentityTransitionCommitOnce(
                    frameBytes = frames.single(),
                    workspaceId = fixture.workspaceId,
                    recipientDeviceId = fixture.peerDeviceId,
                    recipientIdentity = fixture.peer,
                    trustedPeers = receiverPeers,
                    replayLedger = fullLedger,
                    nowUnixMs = fixture.now + 3,
                )
            }
            assertEquals(
                EnvelopeRejectedException.Code.REPLAY_CAPACITY_EXCEEDED,
                replayFailure.code,
            )
            assertEquals(
                null,
                receiverPeers.findApproved(
                    fixture.workspaceId,
                    fixture.localDeviceId,
                    fixture.previousKeyId,
                ),
            )
            assertArrayEquals(
                fixture.pending.publicKey,
                receiverPeers.findApproved(
                    fixture.workspaceId,
                    fixture.localDeviceId,
                    fixture.newKeyId,
                ),
            )

            local.acceptAck(
                fixture.peerDeviceId,
                fixture.peerKeyId,
                acceptedTransition.state.canonicalAck,
                fixture.now + 4,
            )
            assertEquals(1, drainer.drainDue(fixture.now + 5) {
                frames += it.copyOf()
                true
            }.acceptedSends)
            val duplicate = AuthenticatedEnvelopeReceiver.receiveIdentityTransitionCommitOnce(
                frameBytes = frames.last(),
                workspaceId = fixture.workspaceId,
                recipientDeviceId = fixture.peerDeviceId,
                recipientIdentity = fixture.peer,
                trustedPeers = receiverPeers,
                replayLedger = recoveredLedger,
                nowUnixMs = fixture.now + 6,
            )
            assertEquals(
                AndroidTrustedPeerStore.CommitResult.ALREADY_COMMITTED,
                duplicate.committed.result,
            )
        } finally {
            fullLedger.clear()
            recoveredLedger.clear()
            senderPeers.clear()
            receiverPeers.clear()
            local.clear()
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
            current = current,
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
        val current: AuthenticatedHpke.KeyPair,
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
