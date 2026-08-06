package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.ActionInvoke

class ActionRejectedException(val code: Code) : Exception(code.name) {
    enum class Code { DUPLICATE_OPERATION, OPERATION_CAPACITY_EXCEEDED }
}

/**
 * Complete receive boundary for action.invoke. Replay acceptance and operation
 * idempotency are durably committed before [execute] can observe the action.
 */
object AuthenticatedActionReceiver {
    fun <T> receiveOnce(
        frameBytes: ByteArray,
        context: EnvelopeRecipientContext,
        replayLedger: AndroidReplayLedger,
        operationLedger: AndroidOperationLedger,
        nowUnixMs: Long,
        execute: (ActionInvoke) -> T,
    ): T {
        val opened = AuthenticatedEnvelopeReceiver.openOnce(
            frameBytes,
            context,
            replayLedger,
            nowUnixMs,
        )
        val payload = EncryptedPayloadCodecV1.decode(opened.plaintext)
        val action = payload.actionInvoke
        return when (
            operationLedger.checkAndRecord(
                senderKeyId = opened.header.senderKeyId,
                idempotencyKey = action.idempotencyKey.toByteArray(),
                nowUnixMs = nowUnixMs,
            )
        ) {
            AndroidOperationLedger.Decision.ACCEPTED -> execute(action)
            AndroidOperationLedger.Decision.DUPLICATE -> throw ActionRejectedException(
                ActionRejectedException.Code.DUPLICATE_OPERATION,
            )
            AndroidOperationLedger.Decision.CAPACITY_EXCEEDED -> throw ActionRejectedException(
                ActionRejectedException.Code.OPERATION_CAPACITY_EXCEEDED,
            )
        }
    }
}
