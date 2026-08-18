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
