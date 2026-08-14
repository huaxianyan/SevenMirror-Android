package dev.notificationmirroring.crypto

import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.ActionInvoke
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload

class ActionRejectedException(val code: Code) : Exception(code.name) {
    enum class Code { OPERATION_CAPACITY_EXCEEDED, RESULT_OUTBOX_CAPACITY_EXCEEDED }
}

data class ActionReceipt(
    val result: ActionResult,
    /** Canonical payload bytes persisted by the operation ledger and ready to encrypt. */
    val resultPayload: ByteArray,
    val recovered: Boolean,
)

/**
 * Complete receive boundary for action.invoke. Replay acceptance and operation
 * reservation are durably committed before [execute] can observe the action.
 */
object AuthenticatedActionReceiver {
    fun receiveOnce(
        frameBytes: ByteArray,
        context: EnvelopeRecipientContext,
        replayLedger: AndroidReplayLedger,
        operationLedger: AndroidOperationLedger,
        nowUnixMs: Long,
        execute: (ActionInvoke) -> ActionResult,
    ): ActionReceipt {
        val opened = AuthenticatedEnvelopeReceiver.openOnce(
            frameBytes,
            context,
            replayLedger,
            nowUnixMs,
        )
        return finishOpened(
            opened = opened,
            operationLedger = operationLedger,
            nowUnixMs = nowUnixMs,
            beforeOperation = { _, _ -> },
            execute = execute,
        )
    }

    /**
     * Production receive boundary. Durable result capacity is reserved before [execute], and the
     * exact result is completed into that reservation before this method returns.
     */
    fun receiveAndQueueOnce(
        frameBytes: ByteArray,
        context: EnvelopeRecipientContext,
        replayLedger: AndroidReplayLedger,
        operationLedger: AndroidOperationLedger,
        resultOutbox: AndroidActionResultOutbox,
        nowUnixMs: Long,
        execute: (ActionInvoke) -> ActionResult,
    ): ActionReceipt {
        val opened = AuthenticatedEnvelopeReceiver.openOnce(
            frameBytes,
            context,
            replayLedger,
            nowUnixMs,
        )
        val payload = EncryptedPayloadCodecV1.decode(opened.plaintext)
        return receiveDecodedAndQueue(
            opened = opened,
            payload = payload,
            operationLedger = operationLedger,
            resultOutbox = resultOutbox,
            nowUnixMs = nowUnixMs,
            execute = execute,
        )
    }

    /** Continues after one shared HPKE open/replay commit and one canonical payload decode. */
    fun receiveDecodedAndQueue(
        opened: OpenedEnvelope,
        payload: EncryptedPayload,
        operationLedger: AndroidOperationLedger,
        resultOutbox: AndroidActionResultOutbox,
        nowUnixMs: Long,
        execute: (ActionInvoke) -> ActionResult,
    ): ActionReceipt {
        require(payload.bodyCase == EncryptedPayload.BodyCase.ACTION_INVOKE) {
            "Expected action.invoke payload"
        }
        val receipt = finishDecoded(
            opened = opened,
            action = payload.actionInvoke,
            operationLedger = operationLedger,
            nowUnixMs = nowUnixMs,
            beforeOperation = { envelope, action ->
                when (
                    resultOutbox.reserve(
                        recipientDeviceId = envelope.header.senderDeviceId,
                        recipientKeyId = envelope.header.senderKeyId,
                        idempotencyKey = action.idempotencyKey.toByteArray(),
                        nowUnixMs = nowUnixMs,
                    )
                ) {
                    AndroidActionResultOutbox.ReserveResult.CAPACITY_EXCEEDED ->
                        throw ActionRejectedException(
                            ActionRejectedException.Code.RESULT_OUTBOX_CAPACITY_EXCEEDED,
                        )
                    AndroidActionResultOutbox.ReserveResult.RESERVED,
                    AndroidActionResultOutbox.ReserveResult.ALREADY_RESERVED,
                    -> Unit
                }
            },
            execute = execute,
        )
        resultOutbox.complete(
            recipientDeviceId = opened.header.senderDeviceId,
            recipientKeyId = opened.header.senderKeyId,
            canonicalResultPayload = receipt.resultPayload,
            nowUnixMs = nowUnixMs,
        )
        return receipt
    }

    private fun finishOpened(
        opened: OpenedEnvelope,
        operationLedger: AndroidOperationLedger,
        nowUnixMs: Long,
        beforeOperation: (OpenedEnvelope, ActionInvoke) -> Unit,
        execute: (ActionInvoke) -> ActionResult,
    ): ActionReceipt {
        val payload = EncryptedPayloadCodecV1.decode(opened.plaintext)
        require(payload.bodyCase == EncryptedPayload.BodyCase.ACTION_INVOKE) {
            "Expected action.invoke payload"
        }
        return finishDecoded(
            opened,
            payload.actionInvoke,
            operationLedger,
            nowUnixMs,
            beforeOperation,
            execute,
        )
    }

    private fun finishDecoded(
        opened: OpenedEnvelope,
        action: ActionInvoke,
        operationLedger: AndroidOperationLedger,
        nowUnixMs: Long,
        beforeOperation: (OpenedEnvelope, ActionInvoke) -> Unit,
        execute: (ActionInvoke) -> ActionResult,
    ): ActionReceipt {
        val idempotencyKey = action.idempotencyKey.toByteArray()
        beforeOperation(opened, action)
        return when (
            val decision = operationLedger.beginOrRecover(
                senderKeyId = opened.header.senderKeyId,
                idempotencyKey = idempotencyKey,
                nowUnixMs = nowUnixMs,
            )
        ) {
            AndroidOperationLedger.BeginResult.Accepted -> {
                val result = execute(action)
                require(result.idempotencyKey.toByteArray().contentEquals(idempotencyKey)) {
                    "Action result idempotency key does not match request"
                }
                val encodedResult = EncryptedPayloadCodecV1.encode(
                    EncryptedPayload.newBuilder()
                        .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
                        .setActionResult(result)
                        .build(),
                )
                operationLedger.complete(
                    opened.header.senderKeyId,
                    idempotencyKey,
                    encodedResult,
                )
                ActionReceipt(result, encodedResult, recovered = false)
            }
            is AndroidOperationLedger.BeginResult.DuplicateCompleted -> {
                val recovered = EncryptedPayloadCodecV1.decode(decision.resultPayload)
                require(recovered.bodyCase == EncryptedPayload.BodyCase.ACTION_RESULT) {
                    "Stored operation result has the wrong payload type"
                }
                ActionReceipt(
                    recovered.actionResult,
                    decision.resultPayload.copyOf(),
                    recovered = true,
                )
            }
            AndroidOperationLedger.BeginResult.DuplicatePending -> {
                val result = ActionResult.newBuilder()
                    .setIdempotencyKey(ByteString.copyFrom(idempotencyKey))
                    .setStatus(ActionResultStatus.ACTION_RESULT_STATUS_OUTCOME_UNKNOWN)
                    .build()
                val encodedResult = EncryptedPayloadCodecV1.encode(
                    EncryptedPayload.newBuilder()
                        .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
                        .setActionResult(result)
                        .build(),
                )
                ActionReceipt(result, encodedResult, recovered = true)
            }
            AndroidOperationLedger.BeginResult.CapacityExceeded -> throw ActionRejectedException(
                ActionRejectedException.Code.OPERATION_CAPACITY_EXCEEDED,
            )
        }
    }
}
