package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.security.MessageDigest

class ActionResultAckRejectedException(val code: Code) : Exception(code.name) {
    enum class Code {
        UNKNOWN_OPERATION,
        OPERATION_NOT_COMPLETED,
        RESULT_DIGEST_MISMATCH,
        RESULT_OUTBOX_UNKNOWN,
    }
}

/** Authenticated boundary that removes a durable result only after exact ACK verification. */
object AuthenticatedActionResultAckReceiver {
    fun receiveOnce(
        frameBytes: ByteArray,
        context: EnvelopeRecipientContext,
        replayLedger: AndroidReplayLedger,
        operationLedger: AndroidOperationLedger,
        resultOutbox: AndroidActionResultOutbox,
        nowUnixMs: Long,
    ): AndroidActionResultOutbox.AcknowledgeResult {
        val opened = AuthenticatedEnvelopeReceiver.openOnce(
            frameBytes = frameBytes,
            context = context,
            replayLedger = replayLedger,
            nowUnixMs = nowUnixMs,
        )
        val (idempotencyKey, resultSha256) = try {
            val payload = EncryptedPayloadCodecV1.decode(opened.plaintext)
            require(payload.bodyCase == EncryptedPayload.BodyCase.ACTION_RESULT_ACK) {
                "Expected action_result_ack payload"
            }
            Pair(
                payload.actionResultAck.idempotencyKey.toByteArray(),
                payload.actionResultAck.resultSha256.toByteArray(),
            )
        } finally {
            opened.plaintext.fill(0)
        }
        val durableResult = when (
            val operation = operationLedger.lookup(
                senderKeyId = opened.header.senderKeyId,
                idempotencyKey = idempotencyKey,
                nowUnixMs = nowUnixMs,
            )
        ) {
            AndroidOperationLedger.LookupResult.Unknown -> reject(
                ActionResultAckRejectedException.Code.UNKNOWN_OPERATION,
            )
            AndroidOperationLedger.LookupResult.Pending -> reject(
                ActionResultAckRejectedException.Code.OPERATION_NOT_COMPLETED,
            )
            is AndroidOperationLedger.LookupResult.Completed -> operation.resultPayload
        }
        rejectUnless(
            MessageDigest.isEqual(sha256(durableResult), resultSha256),
            ActionResultAckRejectedException.Code.RESULT_DIGEST_MISMATCH,
        )
        return resultOutbox.acknowledge(
            recipientDeviceId = opened.header.senderDeviceId,
            recipientKeyId = opened.header.senderKeyId,
            idempotencyKey = idempotencyKey,
            resultSha256 = resultSha256,
            nowUnixMs = nowUnixMs,
        ).also {
            rejectUnless(
                it != AndroidActionResultOutbox.AcknowledgeResult.UNKNOWN,
                ActionResultAckRejectedException.Code.RESULT_OUTBOX_UNKNOWN,
            )
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private fun rejectUnless(condition: Boolean, code: ActionResultAckRejectedException.Code) {
        if (!condition) reject(code)
    }

    private fun reject(code: ActionResultAckRejectedException.Code): Nothing =
        throw ActionResultAckRejectedException(code)
}
