package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.EncryptedEnvelopePartsV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransition
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionAck
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionCommit
import org.bouncycastle.crypto.InvalidCipherTextException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

@RunWith(AndroidJUnit4::class)
class AuthenticatedEnvelopeReceiverInstrumentedTest {
    @Test
    fun authenticatesBeforePersistentlyConsumingReplayTuple() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val ledger = AndroidReplayLedger(context, "receiver-${System.nanoTime()}")
        val now = 1_800_000_000_000L
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val workspaceId = ByteArray(16) { 1 }
        val recipientDeviceId = ByteArray(16) { 3 }
        val routingHeader = RoutingHeaderCodecV1.encode(
            RoutingHeaderV1(
                workspaceId = workspaceId,
                senderDeviceId = ByteArray(16) { 2 },
                recipientDeviceId = recipientDeviceId,
                senderKeyId = sha256(sender.publicKey),
                recipientKeyId = sha256(recipient.publicKey),
                messageId = ByteArray(16) { 4 },
                sequence = 1,
                createdAtUnixMs = now,
                expiresAtUnixMs = now + 60_000,
            ),
        )
        val plaintext = "mark as read".encodeToByteArray()
        val encrypted = AuthenticatedHpke.seal(
            recipient.publicKey,
            sender,
            plaintext,
            routingHeader,
        )
        val frame = EncryptedEnvelopeCodecV1.encode(
            EncryptedEnvelopePartsV1(
                routingHeader,
                encrypted.encapsulatedKey,
                encrypted.ciphertext,
            ),
        )
        val recipientContext = EnvelopeRecipientContext(
            workspaceId,
            recipientDeviceId,
            recipient,
            sender.publicKey,
        )

        try {
            val tampered = frame.copyOf().apply {
                this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
            }
            assertThrows(InvalidCipherTextException::class.java) {
                AuthenticatedEnvelopeReceiver.openOnce(tampered, recipientContext, ledger, now)
            }

            val opened = AuthenticatedEnvelopeReceiver.openOnce(
                frame,
                recipientContext,
                ledger,
                now,
            )
            assertArrayEquals(plaintext, opened.plaintext)

            val duplicate = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.openOnce(frame, recipientContext, ledger, now)
            }
            assertEquals(EnvelopeRejectedException.Code.DUPLICATE, duplicate.code)
        } finally {
            ledger.clear()
        }
    }

    @Test
    fun identityTransitionPersistsAckIntentBeforeReplayConsumption() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val suffix = System.nanoTime().toString()
        val trustedPeers = AndroidTrustedPeerStore(context, "transition-$suffix")
        val fullLedger = AndroidReplayLedger(context, "transition-full-$suffix", maxEntries = 1)
        val recoveredLedger = AndroidReplayLedger(context, "transition-recovered-$suffix")
        val now = 1_800_000_000_000L
        val workspaceId = ByteArray(16) { 1 }
        val senderDeviceId = ByteArray(16) { 2 }
        val recipientDeviceId = ByteArray(16) { 3 }
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val successor = AuthenticatedHpke.generateKeyPair()
        val canonicalTransition = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                .setIdentityKeyTransition(
                    IdentityKeyTransition.newBuilder()
                        .setTransitionId(ByteString.copyFrom(ByteArray(16) { 4 }))
                        .setPreviousKeyId(ByteString.copyFrom(sha256(sender.publicKey)))
                        .setNewPublicKey(ByteString.copyFrom(successor.publicKey))
                        .setNewKeyId(ByteString.copyFrom(sha256(successor.publicKey))),
                )
                .build(),
        )
        val recipientContext = EnvelopeRecipientContext(
            workspaceId,
            recipientDeviceId,
            recipient,
            sender.publicKey,
        )
        fun frame(messageId: ByteArray): ByteArray {
            val header = RoutingHeaderCodecV1.encode(
                RoutingHeaderV1(
                    workspaceId = workspaceId,
                    senderDeviceId = senderDeviceId,
                    recipientDeviceId = recipientDeviceId,
                    senderKeyId = sha256(sender.publicKey),
                    recipientKeyId = sha256(recipient.publicKey),
                    messageId = messageId,
                    sequence = messageId[0].toLong(),
                    createdAtUnixMs = now,
                    expiresAtUnixMs = now + 60_000,
                ),
            )
            val encrypted = AuthenticatedHpke.seal(
                recipient.publicKey,
                sender,
                canonicalTransition,
                header,
            )
            return EncryptedEnvelopeCodecV1.encode(
                EncryptedEnvelopePartsV1(
                    header,
                    encrypted.encapsulatedKey,
                    encrypted.ciphertext,
                ),
            )
        }
        try {
            trustedPeers.pinApproved(workspaceId, senderDeviceId, sender.publicKey)
            assertEquals(
                AndroidReplayLedger.Decision.ACCEPTED,
                fullLedger.checkAndRecord(
                    sha256(ByteArray(1) { 9 }),
                    ByteArray(16) { 9 },
                    now + 60_000,
                    now,
                ),
            )
            val replayFailure = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.receiveIdentityTransitionOnce(
                    frame(ByteArray(16) { 6 }),
                    recipientContext,
                    trustedPeers,
                    fullLedger,
                    now,
                )
            }
            assertEquals(
                EnvelopeRejectedException.Code.REPLAY_CAPACITY_EXCEEDED,
                replayFailure.code,
            )
            val durable = trustedPeers.loadIdentityTransition(
                workspaceId,
                senderDeviceId,
                now + 1,
            )!!
            assertArrayEquals(canonicalTransition, durable.canonicalTransition)
            val recovered = AuthenticatedEnvelopeReceiver.receiveIdentityTransitionOnce(
                frame(ByteArray(16) { 7 }),
                recipientContext,
                trustedPeers,
                recoveredLedger,
                now + 1,
            )
            assertEquals(
                AndroidTrustedPeerStore.TransitionResult.ALREADY_ACCEPTED,
                recovered.accepted.result,
            )
            assertArrayEquals(durable.canonicalAck, recovered.accepted.state.canonicalAck)
        } finally {
            fullLedger.clear()
            recoveredLedger.clear()
            trustedPeers.clear()
        }
    }

    @Test
    fun pendingIdentityOpensOnlyExactBoundAcknowledgement() {
        val fixture = pendingAckFixture()
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val ledger = AndroidReplayLedger(context, "pending-ack-${System.nanoTime()}")
        val canonicalAck = canonicalAck(fixture)
        val frame = encryptedFrame(fixture, canonicalAck, ByteArray(16) { 6 })
        try {
            val opened = AuthenticatedEnvelopeReceiver.openPendingIdentityAckOnce(
                frame,
                fixture.context,
                fixture.binding,
                ledger,
                fixture.now,
            )
            assertArrayEquals(fixture.transitionId, opened.acknowledgement.transitionId.toByteArray())
            assertArrayEquals(canonicalAck, opened.canonicalPayload)

            val duplicate = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.openPendingIdentityAckOnce(
                    frame,
                    fixture.context,
                    fixture.binding,
                    ledger,
                    fixture.now,
                )
            }
            assertEquals(EnvelopeRejectedException.Code.DUPLICATE, duplicate.code)
        } finally {
            ledger.clear()
        }
    }

    @Test
    fun pendingIdentityRejectsBusinessPayloadWithoutConsumingReplayTuple() {
        val fixture = pendingAckFixture()
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val ledger = AndroidReplayLedger(context, "pending-business-${System.nanoTime()}")
        val businessPayload = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
                .setActionResult(
                    ActionResult.newBuilder()
                        .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { 7 }))
                        .setStatus(ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED),
                )
                .build(),
        )
        val messageId = ByteArray(16) { 8 }
        val frame = encryptedFrame(fixture, businessPayload, messageId)
        try {
            val rejected = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.openPendingIdentityAckOnce(
                    frame,
                    fixture.context,
                    fixture.binding,
                    ledger,
                    fixture.now,
                )
            }
            assertEquals(
                EnvelopeRejectedException.Code.PENDING_IDENTITY_PAYLOAD_MISMATCH,
                rejected.code,
            )
            assertEquals(
                AndroidReplayLedger.Decision.ACCEPTED,
                ledger.checkAndRecord(
                    sha256(fixture.sender.publicKey),
                    messageId,
                    fixture.now + 60_000,
                    fixture.now,
                ),
            )

            val commitPayload = EncryptedPayloadCodecV1.encode(
                EncryptedPayload.newBuilder()
                    .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                    .setIdentityKeyTransitionCommit(
                        IdentityKeyTransitionCommit.newBuilder()
                            .setTransitionId(ByteString.copyFrom(fixture.transitionId))
                            .setPreviousKeyId(ByteString.copyFrom(fixture.previousKeyId))
                            .setNewKeyId(ByteString.copyFrom(fixture.newKeyId))
                            .setTransitionSha256(ByteString.copyFrom(fixture.transitionSha256))
                            .setAckSha256(ByteString.copyFrom(ByteArray(32) { 12 })),
                    )
                    .build(),
            )
            val commitMessageId = ByteArray(16) { 13 }
            val commitRejected = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.openPendingIdentityAckOnce(
                    encryptedFrame(fixture, commitPayload, commitMessageId),
                    fixture.context,
                    fixture.binding,
                    ledger,
                    fixture.now,
                )
            }
            assertEquals(
                EnvelopeRejectedException.Code.PENDING_IDENTITY_PAYLOAD_MISMATCH,
                commitRejected.code,
            )
            assertEquals(
                AndroidReplayLedger.Decision.ACCEPTED,
                ledger.checkAndRecord(
                    sha256(fixture.sender.publicKey),
                    commitMessageId,
                    fixture.now + 60_000,
                    fixture.now,
                ),
            )
        } finally {
            ledger.clear()
        }
    }

    @Test
    fun pendingIdentityRejectsWrongTransitionBindingAndPeerDevice() {
        val fixture = pendingAckFixture()
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val canonicalAck = canonicalAck(fixture)
        val frame = encryptedFrame(fixture, canonicalAck, ByteArray(16) { 9 })
        val digestLedger = AndroidReplayLedger(context, "pending-digest-${System.nanoTime()}")
        val senderLedger = AndroidReplayLedger(context, "pending-sender-${System.nanoTime()}")
        try {
            val wrongDigest = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.openPendingIdentityAckOnce(
                    frame,
                    fixture.context,
                    fixture.binding.copy(transitionSha256 = ByteArray(32) { 10 }),
                    digestLedger,
                    fixture.now,
                )
            }
            assertEquals(
                EnvelopeRejectedException.Code.TRANSITION_BINDING_MISMATCH,
                wrongDigest.code,
            )
            val wrongSender = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.openPendingIdentityAckOnce(
                    frame,
                    fixture.context,
                    fixture.binding.copy(senderDeviceId = ByteArray(16) { 11 }),
                    senderLedger,
                    fixture.now,
                )
            }
            assertEquals(EnvelopeRejectedException.Code.WRONG_SENDER, wrongSender.code)
        } finally {
            digestLedger.clear()
            senderLedger.clear()
        }
    }

    private fun pendingAckFixture(): PendingAckFixture {
        val now = 1_800_000_000_000L
        val sender = AuthenticatedHpke.generateKeyPair()
        val current = AuthenticatedHpke.generateKeyPair()
        val pending = AuthenticatedHpke.generateKeyPair()
        val previousKeyId = sha256(current.publicKey)
        val newKeyId = sha256(pending.publicKey)
        val transitionId = ByteArray(16) { 4 }
        val transitionSha256 = ByteArray(32) { 5 }
        val senderDeviceId = ByteArray(16) { 2 }
        return PendingAckFixture(
            now = now,
            sender = sender,
            pending = pending,
            transitionId = transitionId,
            previousKeyId = previousKeyId,
            newKeyId = newKeyId,
            transitionSha256 = transitionSha256,
            context = EnvelopeRecipientContext(
                workspaceId = ByteArray(16) { 1 },
                recipientDeviceId = ByteArray(16) { 3 },
                recipientIdentity = pending,
                pinnedSenderPublicKey = sender.publicKey,
            ),
            binding = PendingIdentityAckBinding(
                senderDeviceId = senderDeviceId,
                transitionId = transitionId,
                previousKeyId = previousKeyId,
                newKeyId = newKeyId,
                transitionSha256 = transitionSha256,
            ),
        )
    }

    private fun canonicalAck(fixture: PendingAckFixture): ByteArray =
        EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                .setIdentityKeyTransitionAck(
                    IdentityKeyTransitionAck.newBuilder()
                        .setTransitionId(ByteString.copyFrom(fixture.transitionId))
                        .setPreviousKeyId(ByteString.copyFrom(fixture.previousKeyId))
                        .setNewKeyId(ByteString.copyFrom(fixture.newKeyId))
                        .setTransitionSha256(ByteString.copyFrom(fixture.transitionSha256)),
                )
                .build(),
        )

    private fun encryptedFrame(
        fixture: PendingAckFixture,
        plaintext: ByteArray,
        messageId: ByteArray,
    ): ByteArray {
        val routingHeader = RoutingHeaderCodecV1.encode(
            RoutingHeaderV1(
                workspaceId = fixture.context.workspaceId,
                senderDeviceId = fixture.binding.senderDeviceId,
                recipientDeviceId = fixture.context.recipientDeviceId,
                senderKeyId = sha256(fixture.sender.publicKey),
                recipientKeyId = fixture.newKeyId,
                messageId = messageId,
                sequence = messageId[0].toLong(),
                createdAtUnixMs = fixture.now,
                expiresAtUnixMs = fixture.now + 60_000,
            ),
        )
        val encrypted = AuthenticatedHpke.seal(
            fixture.pending.publicKey,
            fixture.sender,
            plaintext,
            routingHeader,
        )
        return EncryptedEnvelopeCodecV1.encode(
            EncryptedEnvelopePartsV1(
                routingHeader,
                encrypted.encapsulatedKey,
                encrypted.ciphertext,
            ),
        )
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private data class PendingAckFixture(
        val now: Long,
        val sender: AuthenticatedHpke.KeyPair,
        val pending: AuthenticatedHpke.KeyPair,
        val transitionId: ByteArray,
        val previousKeyId: ByteArray,
        val newKeyId: ByteArray,
        val transitionSha256: ByteArray,
        val context: EnvelopeRecipientContext,
        val binding: PendingIdentityAckBinding,
    )
}
