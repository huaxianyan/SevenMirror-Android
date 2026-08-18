package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionAck
import java.security.MessageDigest

class EnvelopeRejectedException(val code: Code) : Exception(code.name) {
    enum class Code {
        WRONG_WORKSPACE,
        WRONG_RECIPIENT,
        WRONG_SENDER,
        RECIPIENT_KEY_MISMATCH,
        SENDER_KEY_MISMATCH,
        PENDING_IDENTITY_PAYLOAD_MISMATCH,
        IDENTITY_TRANSITION_PAYLOAD_MISMATCH,
        TRANSITION_BINDING_MISMATCH,
        DUPLICATE,
        EXPIRED,
        REPLAY_CAPACITY_EXCEEDED,
    }
}

data class EnvelopeRecipientContext(
    val workspaceId: ByteArray,
    val recipientDeviceId: ByteArray,
    val recipientIdentity: AuthenticatedHpke.KeyPair,
    val pinnedSenderPublicKey: ByteArray,
)

data class OpenedEnvelope(
    val header: RoutingHeaderV1,
    val plaintext: ByteArray,
)

data class PendingIdentityAckBinding(
    val senderDeviceId: ByteArray,
    val transitionId: ByteArray,
    val previousKeyId: ByteArray,
    val newKeyId: ByteArray,
    val transitionSha256: ByteArray,
)

data class OpenedPendingIdentityAck(
    val header: RoutingHeaderV1,
    val acknowledgement: IdentityKeyTransitionAck,
    val canonicalPayload: ByteArray,
)

data class AcceptedPeerIdentityTransitionEnvelope(
    val header: RoutingHeaderV1,
    val accepted: AndroidTrustedPeerStore.AcceptedPeerIdentityTransition,
)

data class AcceptedLocalIdentityAckEnvelope(
    val header: RoutingHeaderV1,
    val accepted: AndroidLocalIdentityTransitionStore.AcceptedAck,
)

data class AcceptedPeerIdentityCommitEnvelope(
    val header: RoutingHeaderV1,
    val committed: AndroidTrustedPeerStore.CommittedPeerIdentityTransition,
)

/**
 * Returns plaintext only after HPKE authentication and an atomic accepted
 * replay-ledger write, so callers cannot apply a side effect in the wrong order.
 */
object AuthenticatedEnvelopeReceiver {
    fun openOnce(
        frameBytes: ByteArray,
        context: EnvelopeRecipientContext,
        replayLedger: AndroidReplayLedger,
        nowUnixMs: Long,
    ): OpenedEnvelope {
        val opened = authenticateAndOpen(frameBytes, context, nowUnixMs)
        consumeReplay(opened.header, replayLedger, nowUnixMs)
        return OpenedEnvelope(opened.header, opened.plaintext)
    }

    /**
     * Persists the successor and exact ACK intent before replay consumption.
     * A crash or replay failure therefore cannot lose an authenticated transition.
     */
    fun receiveIdentityTransitionOnce(
        frameBytes: ByteArray,
        context: EnvelopeRecipientContext,
        trustedPeers: AndroidTrustedPeerStore,
        replayLedger: AndroidReplayLedger,
        nowUnixMs: Long,
    ): AcceptedPeerIdentityTransitionEnvelope {
        val opened = authenticateAndOpen(frameBytes, context, nowUnixMs)
        val payload = try {
            EncryptedPayloadCodecV1.decode(opened.plaintext)
        } catch (_: Exception) {
            reject(EnvelopeRejectedException.Code.IDENTITY_TRANSITION_PAYLOAD_MISMATCH)
        }
        rejectUnless(
            payload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION,
            EnvelopeRejectedException.Code.IDENTITY_TRANSITION_PAYLOAD_MISMATCH,
        )
        rejectUnless(
            constantTimeEquals(
                payload.identityKeyTransition.previousKeyId.toByteArray(),
                opened.header.senderKeyId,
            ),
            EnvelopeRejectedException.Code.TRANSITION_BINDING_MISMATCH,
        )
        val accepted = trustedPeers.acceptIdentityTransition(
            workspaceId = opened.header.workspaceId,
            peerDeviceId = opened.header.senderDeviceId,
            canonicalTransition = opened.plaintext,
            nowUnixMs = nowUnixMs,
        )
        consumeReplay(opened.header, replayLedger, nowUnixMs)
        return AcceptedPeerIdentityTransitionEnvelope(opened.header, accepted)
    }

    /** Persists the exact ACK and derived commit before replay consumption. */
    fun receivePendingIdentityAckOnce(
        frameBytes: ByteArray,
        context: EnvelopeRecipientContext,
        localTransitions: AndroidLocalIdentityTransitionStore,
        replayLedger: AndroidReplayLedger,
        nowUnixMs: Long,
    ): AcceptedLocalIdentityAckEnvelope {
        val opened = authenticateAndOpen(frameBytes, context, nowUnixMs)
        val binding = localTransitions.expectedAckBinding(
            opened.header.senderDeviceId,
            nowUnixMs,
        ) ?: reject(EnvelopeRejectedException.Code.TRANSITION_BINDING_MISMATCH)
        rejectUnless(
            constantTimeEquals(binding.workspaceId, opened.header.workspaceId) &&
                constantTimeEquals(binding.localDeviceId, opened.header.recipientDeviceId) &&
                constantTimeEquals(binding.senderKeyId, opened.header.senderKeyId) &&
                constantTimeEquals(binding.newKeyId, opened.header.recipientKeyId),
            EnvelopeRejectedException.Code.TRANSITION_BINDING_MISMATCH,
        )
        val payload = try {
            EncryptedPayloadCodecV1.decode(opened.plaintext)
        } catch (_: Exception) {
            reject(EnvelopeRejectedException.Code.PENDING_IDENTITY_PAYLOAD_MISMATCH)
        }
        rejectUnless(
            payload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_ACK,
            EnvelopeRejectedException.Code.PENDING_IDENTITY_PAYLOAD_MISMATCH,
        )
        val ack = payload.identityKeyTransitionAck
        rejectUnless(
            constantTimeEquals(ack.transitionId.toByteArray(), binding.transitionId) &&
                constantTimeEquals(ack.previousKeyId.toByteArray(), binding.previousKeyId) &&
                constantTimeEquals(ack.newKeyId.toByteArray(), binding.newKeyId) &&
                constantTimeEquals(ack.transitionSha256.toByteArray(), binding.transitionSha256),
            EnvelopeRejectedException.Code.TRANSITION_BINDING_MISMATCH,
        )
        val accepted = localTransitions.acceptAck(
            opened.header.senderDeviceId,
            opened.header.senderKeyId,
            opened.plaintext,
            nowUnixMs,
        )
        consumeReplay(opened.header, replayLedger, nowUnixMs)
        return AcceptedLocalIdentityAckEnvelope(opened.header, accepted)
    }

    /** Accepts a pending successor only for its exact commit and promotes before replay. */
    fun receiveIdentityTransitionCommitOnce(
        frameBytes: ByteArray,
        workspaceId: ByteArray,
        recipientDeviceId: ByteArray,
        recipientIdentity: AuthenticatedHpke.KeyPair,
        trustedPeers: AndroidTrustedPeerStore,
        replayLedger: AndroidReplayLedger,
        nowUnixMs: Long,
    ): AcceptedPeerIdentityCommitEnvelope {
        val envelope = EncryptedEnvelopeCodecV1.decode(frameBytes)
        rejectUnless(
            constantTimeEquals(envelope.routingHeader.workspaceId, workspaceId),
            EnvelopeRejectedException.Code.WRONG_WORKSPACE,
        )
        rejectUnless(
            constantTimeEquals(envelope.routingHeader.recipientDeviceId, recipientDeviceId),
            EnvelopeRejectedException.Code.WRONG_RECIPIENT,
        )
        val binding = trustedPeers.resolveIdentityCommitSender(
            envelope.routingHeader.workspaceId,
            envelope.routingHeader.senderDeviceId,
            envelope.routingHeader.senderKeyId,
            nowUnixMs,
        ) ?: reject(EnvelopeRejectedException.Code.WRONG_SENDER)
        val opened = authenticateAndOpen(
            frameBytes,
            EnvelopeRecipientContext(
                workspaceId = workspaceId,
                recipientDeviceId = recipientDeviceId,
                recipientIdentity = recipientIdentity,
                pinnedSenderPublicKey = binding.senderPublicKey,
            ),
            nowUnixMs,
        )
        val payload = try {
            EncryptedPayloadCodecV1.decode(opened.plaintext)
        } catch (_: Exception) {
            reject(EnvelopeRejectedException.Code.IDENTITY_TRANSITION_PAYLOAD_MISMATCH)
        }
        rejectUnless(
            payload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_COMMIT,
            EnvelopeRejectedException.Code.IDENTITY_TRANSITION_PAYLOAD_MISMATCH,
        )
        val commit = payload.identityKeyTransitionCommit
        rejectUnless(
            constantTimeEquals(commit.transitionId.toByteArray(), binding.transitionId) &&
                constantTimeEquals(commit.previousKeyId.toByteArray(), binding.previousKeyId) &&
                constantTimeEquals(commit.newKeyId.toByteArray(), binding.newKeyId) &&
                constantTimeEquals(commit.transitionSha256.toByteArray(), binding.transitionSha256) &&
                constantTimeEquals(commit.ackSha256.toByteArray(), binding.ackSha256),
            EnvelopeRejectedException.Code.TRANSITION_BINDING_MISMATCH,
        )
        val committed = trustedPeers.commitIdentityTransition(
            opened.header.workspaceId,
            opened.header.senderDeviceId,
            opened.header.senderKeyId,
            opened.plaintext,
            nowUnixMs,
        )
        consumeReplay(opened.header, replayLedger, nowUnixMs)
        return AcceptedPeerIdentityCommitEnvelope(opened.header, committed)
    }

    /**
     * The proposed local identity is not an active business recipient. It may
     * only open the exact peer acknowledgement bound to caller-validated state.
     */
    fun openPendingIdentityAckOnce(
        frameBytes: ByteArray,
        context: EnvelopeRecipientContext,
        binding: PendingIdentityAckBinding,
        replayLedger: AndroidReplayLedger,
        nowUnixMs: Long,
    ): OpenedPendingIdentityAck {
        val opened = authenticateAndOpen(frameBytes, context, nowUnixMs)
        rejectUnless(
            constantTimeEquals(opened.header.senderDeviceId, binding.senderDeviceId),
            EnvelopeRejectedException.Code.WRONG_SENDER,
        )
        rejectUnless(
            constantTimeEquals(opened.header.recipientKeyId, binding.newKeyId),
            EnvelopeRejectedException.Code.TRANSITION_BINDING_MISMATCH,
        )
        val payload = try {
            EncryptedPayloadCodecV1.decode(opened.plaintext)
        } catch (_: Exception) {
            reject(EnvelopeRejectedException.Code.PENDING_IDENTITY_PAYLOAD_MISMATCH)
        }
        rejectUnless(
            payload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_ACK,
            EnvelopeRejectedException.Code.PENDING_IDENTITY_PAYLOAD_MISMATCH,
        )
        val ack = payload.identityKeyTransitionAck
        rejectUnless(
            constantTimeEquals(ack.transitionId.toByteArray(), binding.transitionId) &&
                constantTimeEquals(ack.previousKeyId.toByteArray(), binding.previousKeyId) &&
                constantTimeEquals(ack.newKeyId.toByteArray(), binding.newKeyId) &&
                constantTimeEquals(ack.transitionSha256.toByteArray(), binding.transitionSha256),
            EnvelopeRejectedException.Code.TRANSITION_BINDING_MISMATCH,
        )
        consumeReplay(opened.header, replayLedger, nowUnixMs)
        return OpenedPendingIdentityAck(opened.header, ack, opened.plaintext)
    }

    private fun authenticateAndOpen(
        frameBytes: ByteArray,
        context: EnvelopeRecipientContext,
        nowUnixMs: Long,
    ): OpenedEnvelope {
        val envelope = EncryptedEnvelopeCodecV1.decode(frameBytes)
        val header = envelope.routingHeader
        rejectUnless(
            constantTimeEquals(header.workspaceId, context.workspaceId),
            EnvelopeRejectedException.Code.WRONG_WORKSPACE,
        )
        rejectUnless(
            constantTimeEquals(header.recipientDeviceId, context.recipientDeviceId),
            EnvelopeRejectedException.Code.WRONG_RECIPIENT,
        )
        rejectUnless(
            header.expiresAtUnixMs > nowUnixMs,
            EnvelopeRejectedException.Code.EXPIRED,
        )
        rejectUnless(
            constantTimeEquals(header.recipientKeyId, sha256(context.recipientIdentity.publicKey)),
            EnvelopeRejectedException.Code.RECIPIENT_KEY_MISMATCH,
        )
        rejectUnless(
            constantTimeEquals(header.senderKeyId, sha256(context.pinnedSenderPublicKey)),
            EnvelopeRejectedException.Code.SENDER_KEY_MISMATCH,
        )

        val plaintext = AuthenticatedHpke.open(
            recipient = context.recipientIdentity,
            senderPublicKey = context.pinnedSenderPublicKey,
            encrypted = AuthenticatedHpke.Ciphertext(
                encapsulatedKey = envelope.encapsulatedKey,
                ciphertext = envelope.ciphertext,
            ),
            aad = envelope.routingHeaderBytes,
        )
        return OpenedEnvelope(header, plaintext)
    }

    private fun consumeReplay(
        header: RoutingHeaderV1,
        replayLedger: AndroidReplayLedger,
        nowUnixMs: Long,
    ) {
        when (
            replayLedger.checkAndRecord(
                senderKeyId = header.senderKeyId,
                messageId = header.messageId,
                expiresAtUnixMs = header.expiresAtUnixMs,
                nowUnixMs = nowUnixMs,
            )
        ) {
            AndroidReplayLedger.Decision.ACCEPTED -> Unit
            AndroidReplayLedger.Decision.DUPLICATE -> reject(
                EnvelopeRejectedException.Code.DUPLICATE,
            )
            AndroidReplayLedger.Decision.EXPIRED -> reject(
                EnvelopeRejectedException.Code.EXPIRED,
            )
            AndroidReplayLedger.Decision.CAPACITY_EXCEEDED -> reject(
                EnvelopeRejectedException.Code.REPLAY_CAPACITY_EXCEEDED,
            )
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean =
        MessageDigest.isEqual(left, right)

    private fun rejectUnless(condition: Boolean, code: EnvelopeRejectedException.Code) {
        if (!condition) reject(code)
    }

    private fun reject(code: EnvelopeRejectedException.Code): Nothing =
        throw EnvelopeRejectedException(code)
}
