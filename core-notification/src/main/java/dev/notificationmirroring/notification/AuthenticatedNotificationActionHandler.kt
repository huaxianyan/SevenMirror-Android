package dev.notificationmirroring.notification

import android.content.Context
import dev.notificationmirroring.crypto.ActionReceipt
import dev.notificationmirroring.crypto.AndroidActionResultOutbox
import dev.notificationmirroring.crypto.AndroidOperationLedger
import dev.notificationmirroring.crypto.AndroidReplayLedger
import dev.notificationmirroring.crypto.AuthenticatedActionReceiver
import dev.notificationmirroring.crypto.EnvelopeRecipientContext
import dev.notificationmirroring.crypto.OpenedEnvelope
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus

/** Bridges an authenticated encrypted action to Android's process-local capability table. */
object AuthenticatedNotificationActionHandler {
    fun receiveOnce(
        androidContext: Context,
        frameBytes: ByteArray,
        recipientContext: EnvelopeRecipientContext,
        replayLedger: AndroidReplayLedger,
        operationLedger: AndroidOperationLedger,
        nowUnixMs: Long,
    ): ActionReceipt = AuthenticatedActionReceiver.receiveOnce(
        frameBytes,
        recipientContext,
        replayLedger,
        operationLedger,
        nowUnixMs,
    ) { request -> execute(androidContext, request) }

    /** Production boundary that reserves and completes durable result delivery around execution. */
    fun receiveAndQueueOnce(
        androidContext: Context,
        frameBytes: ByteArray,
        recipientContext: EnvelopeRecipientContext,
        replayLedger: AndroidReplayLedger,
        operationLedger: AndroidOperationLedger,
        resultOutbox: AndroidActionResultOutbox,
        nowUnixMs: Long,
    ): ActionReceipt = AuthenticatedActionReceiver.receiveAndQueueOnce(
        frameBytes,
        recipientContext,
        replayLedger,
        operationLedger,
        resultOutbox,
        nowUnixMs,
    ) { request -> execute(androidContext, request) }

    /** Continues production dispatch after the shared authenticated envelope boundary. */
    fun receiveDecodedAndQueue(
        androidContext: Context,
        opened: OpenedEnvelope,
        payload: EncryptedPayload,
        operationLedger: AndroidOperationLedger,
        resultOutbox: AndroidActionResultOutbox,
        nowUnixMs: Long,
    ): ActionReceipt = AuthenticatedActionReceiver.receiveDecodedAndQueue(
        opened,
        payload,
        operationLedger,
        resultOutbox,
        nowUnixMs,
    ) { request -> execute(androidContext, request) }

    private fun execute(
        androidContext: Context,
        request: dev.notificationmirroring.protocol.generated.v1.ActionInvoke,
    ): ActionResult {
        val localResult = if (request.dismissNotification) {
            LocalNotificationController.dismiss(
                notificationKey = request.notificationId,
                notificationRevision = request.notificationRevision,
            )
        } else {
            LocalNotificationController.invoke(
                androidContext,
                NotificationActionToken(
                    notificationKey = request.notificationId,
                    notificationRevision = request.notificationRevision,
                    actionId = NotificationActionId.fromBytes(request.actionId.toByteArray()),
                ),
                replyText = request.replyText.takeIf { request.hasReplyText() },
            )
        }
        return ActionResult.newBuilder()
            .setIdempotencyKey(request.idempotencyKey)
            .setStatus(localResult.status.toProtocolStatus())
            .apply {
                localResult.detail
                    ?.takeIf { it.isNotEmpty() && it.toByteArray().size <= 256 }
                    ?.let(::setDetail)
            }
            .build()
    }

    private fun ActionExecutionStatus.toProtocolStatus(): ActionResultStatus = when (this) {
        ActionExecutionStatus.SUCCEEDED -> ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED
        ActionExecutionStatus.NOTIFICATION_NOT_FOUND ->
            ActionResultStatus.ACTION_RESULT_STATUS_NOTIFICATION_NOT_FOUND
        ActionExecutionStatus.STALE_NOTIFICATION_VERSION ->
            ActionResultStatus.ACTION_RESULT_STATUS_STALE_NOTIFICATION_VERSION
        ActionExecutionStatus.ACTION_NOT_FOUND ->
            ActionResultStatus.ACTION_RESULT_STATUS_ACTION_NOT_FOUND
        ActionExecutionStatus.TEXT_REQUIRED -> ActionResultStatus.ACTION_RESULT_STATUS_TEXT_REQUIRED
        ActionExecutionStatus.TEXT_NOT_SUPPORTED ->
            ActionResultStatus.ACTION_RESULT_STATUS_TEXT_NOT_SUPPORTED
        ActionExecutionStatus.PENDING_INTENT_CANCELLED ->
            ActionResultStatus.ACTION_RESULT_STATUS_PENDING_INTENT_CANCELLED
        ActionExecutionStatus.INTERNAL_ERROR -> ActionResultStatus.ACTION_RESULT_STATUS_INTERNAL_ERROR
    }
}
