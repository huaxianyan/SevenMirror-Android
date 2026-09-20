package com.neko7ina.sevenmirror.notification

import android.content.Context
import com.neko7ina.sevenmirror.crypto.ActionReceipt
import com.neko7ina.sevenmirror.crypto.AndroidActionResultOutbox
import com.neko7ina.sevenmirror.crypto.AndroidOperationLedger
import com.neko7ina.sevenmirror.crypto.AndroidReplayLedger
import com.neko7ina.sevenmirror.crypto.AuthenticatedActionReceiver
import com.neko7ina.sevenmirror.crypto.EnvelopeRecipientContext
import com.neko7ina.sevenmirror.crypto.OpenedEnvelope
import com.neko7ina.sevenmirror.protocol.generated.v1.EncryptedPayload
import com.neko7ina.sevenmirror.protocol.generated.v1.ActionResult
import com.neko7ina.sevenmirror.protocol.generated.v1.ActionResultStatus

/** Bridges an authenticated encrypted action to Android's process-local capability table. */
object AuthenticatedNotificationActionHandler {
    fun receiveOnce(
        androidContext: Context,
        frameBytes: ByteArray,
        recipientContext: EnvelopeRecipientContext,
        replayLedger: AndroidReplayLedger,
        operationLedger: AndroidOperationLedger,
        operationAuthorizer: RemoteOperationAuthorizer,
        nowUnixMs: Long,
    ): ActionReceipt = AuthenticatedActionReceiver.receiveOnce(
        frameBytes,
        recipientContext,
        replayLedger,
        operationLedger,
        nowUnixMs,
    ) { request -> execute(androidContext, request, operationAuthorizer) }

    /** Production boundary that reserves and completes durable result delivery around execution. */
    fun receiveAndQueueOnce(
        androidContext: Context,
        frameBytes: ByteArray,
        recipientContext: EnvelopeRecipientContext,
        replayLedger: AndroidReplayLedger,
        operationLedger: AndroidOperationLedger,
        resultOutbox: AndroidActionResultOutbox,
        operationAuthorizer: RemoteOperationAuthorizer,
        nowUnixMs: Long,
    ): ActionReceipt = AuthenticatedActionReceiver.receiveAndQueueOnce(
        frameBytes,
        recipientContext,
        replayLedger,
        operationLedger,
        resultOutbox,
        nowUnixMs,
    ) { request -> execute(androidContext, request, operationAuthorizer) }

    /** Continues production dispatch after the shared authenticated envelope boundary. */
    fun receiveDecodedAndQueue(
        androidContext: Context,
        opened: OpenedEnvelope,
        payload: EncryptedPayload,
        operationLedger: AndroidOperationLedger,
        resultOutbox: AndroidActionResultOutbox,
        operationAuthorizer: RemoteOperationAuthorizer,
        nowUnixMs: Long,
    ): ActionReceipt = AuthenticatedActionReceiver.receiveDecodedAndQueue(
        opened,
        payload,
        operationLedger,
        resultOutbox,
        nowUnixMs,
    ) { request -> execute(androidContext, request, operationAuthorizer) }

    private fun execute(
        androidContext: Context,
        request: com.neko7ina.sevenmirror.protocol.generated.v1.ActionInvoke,
        operationAuthorizer: RemoteOperationAuthorizer,
    ): ActionResult {
        val localResult = if (request.dismissNotification) {
            LocalNotificationController.dismiss(
                notificationKey = request.notificationId,
                notificationRevision = request.notificationRevision,
                operationAuthorizer = operationAuthorizer,
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
                operationAuthorizer = operationAuthorizer,
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
