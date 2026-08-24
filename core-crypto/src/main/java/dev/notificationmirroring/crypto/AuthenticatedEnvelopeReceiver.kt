package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import java.security.MessageDigest

class EnvelopeRejectedException(val code: Code) : Exception(code.name) {
    enum class Code {
        WRONG_WORKSPACE,
        WRONG_RECIPIENT,
        RECIPIENT_KEY_MISMATCH,
        SENDER_KEY_MISMATCH,
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
        return opened
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
        rejectUnless(header.expiresAtUnixMs > nowUnixMs, EnvelopeRejectedException.Code.EXPIRED)
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
