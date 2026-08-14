package dev.notificationmirroring.notification

import android.content.Context
import dev.notificationmirroring.crypto.ActionReceipt
import dev.notificationmirroring.crypto.AndroidActionResultOutbox
import dev.notificationmirroring.crypto.AndroidOperationLedger
import dev.notificationmirroring.crypto.AndroidReplayLedger
import dev.notificationmirroring.crypto.AndroidTrustedPeerStore
import dev.notificationmirroring.crypto.AuthenticatedActionResultAckReceiver
import dev.notificationmirroring.crypto.AuthenticatedEnvelopeReceiver
import dev.notificationmirroring.crypto.AuthenticatedHpke
import dev.notificationmirroring.crypto.EnvelopeRecipientContext
import dev.notificationmirroring.crypto.EnvelopeRejectedException
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.security.MessageDigest

class ActionSenderNotApprovedException : Exception("ACTION_SENDER_NOT_APPROVED")

sealed interface AuthenticatedInboundReceipt {
    data class Action(val receipt: ActionReceipt) : AuthenticatedInboundReceipt
    data class ResultAck(
        val result: AndroidActionResultOutbox.AcknowledgeResult,
    ) : AuthenticatedInboundReceipt
}

/**
 * Serialized production boundary for inbound action.invoke envelopes.
 *
 * Routing is checked against the active local credential before the immutable approved-peer store
 * is queried. No server directory data can establish E2EE trust through this dispatcher.
 */
class AndroidActionInvokeDispatcher(
    context: Context,
    workspaceId: ByteArray,
    recipientDeviceId: ByteArray,
    recipientIdentity: AuthenticatedHpke.KeyPair,
    private val trustedPeers: AndroidTrustedPeerStore,
    private val replayLedger: AndroidReplayLedger,
    private val operationLedger: AndroidOperationLedger,
    private val resultOutbox: AndroidActionResultOutbox,
) {
    private val appContext = context.applicationContext
    private val workspaceId = workspaceId.copyOf()
    private val recipientDeviceId = recipientDeviceId.copyOf()
    private val recipientIdentity = AuthenticatedHpke.KeyPair(
        publicKey = recipientIdentity.publicKey.copyOf(),
        privateKey = recipientIdentity.privateKey.copyOf(),
    )

    init {
        require(workspaceId.size == 16 && workspaceId.any { it.toInt() != 0 }) {
            "workspaceId must be a non-zero 16-byte value"
        }
        require(recipientDeviceId.size == 16 && recipientDeviceId.any { it.toInt() != 0 }) {
            "recipientDeviceId must be a non-zero 16-byte value"
        }
        AuthenticatedHpke.requireValidPublicKey(recipientIdentity.publicKey)
    }

    @Synchronized
    fun receiveOnce(frameBytes: ByteArray, nowUnixMs: Long): ActionReceipt =
        when (val received = receiveAnyOnce(frameBytes, nowUnixMs)) {
            is AuthenticatedInboundReceipt.Action -> received.receipt
            is AuthenticatedInboundReceipt.ResultAck ->
                throw IllegalArgumentException("Expected action.invoke payload")
        }

    @Synchronized
    fun receiveAnyOnce(frameBytes: ByteArray, nowUnixMs: Long): AuthenticatedInboundReceipt {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val header = EncryptedEnvelopeCodecV1.decode(frameBytes).routingHeader
        rejectUnless(
            MessageDigest.isEqual(header.workspaceId, workspaceId),
            EnvelopeRejectedException.Code.WRONG_WORKSPACE,
        )
        rejectUnless(
            MessageDigest.isEqual(header.recipientDeviceId, recipientDeviceId),
            EnvelopeRejectedException.Code.WRONG_RECIPIENT,
        )
        rejectUnless(
            MessageDigest.isEqual(header.recipientKeyId, sha256(recipientIdentity.publicKey)),
            EnvelopeRejectedException.Code.RECIPIENT_KEY_MISMATCH,
        )
        val senderPublicKey = trustedPeers.findApproved(
            workspaceId = workspaceId,
            deviceId = header.senderDeviceId,
            keyId = header.senderKeyId,
        ) ?: throw ActionSenderNotApprovedException()

        val opened = try {
            AuthenticatedEnvelopeReceiver.openOnce(
                frameBytes = frameBytes,
                context = EnvelopeRecipientContext(
                    workspaceId = workspaceId.copyOf(),
                    recipientDeviceId = recipientDeviceId.copyOf(),
                    recipientIdentity = recipientIdentity,
                    pinnedSenderPublicKey = senderPublicKey,
                ),
                replayLedger = replayLedger,
                nowUnixMs = nowUnixMs,
            )
        } finally {
            senderPublicKey.fill(0)
        }
        return try {
            val payload = EncryptedPayloadCodecV1.decode(opened.plaintext)
            when (payload.bodyCase) {
                EncryptedPayload.BodyCase.ACTION_INVOKE -> AuthenticatedInboundReceipt.Action(
                    AuthenticatedNotificationActionHandler.receiveDecodedAndQueue(
                        androidContext = appContext,
                        opened = opened,
                        payload = payload,
                        operationLedger = operationLedger,
                        resultOutbox = resultOutbox,
                        nowUnixMs = nowUnixMs,
                    ),
                )
                EncryptedPayload.BodyCase.ACTION_RESULT_ACK -> AuthenticatedInboundReceipt.ResultAck(
                    AuthenticatedActionResultAckReceiver.receiveDecoded(
                        opened = opened,
                        payload = payload,
                        operationLedger = operationLedger,
                        resultOutbox = resultOutbox,
                        nowUnixMs = nowUnixMs,
                    ),
                )
                else -> throw IllegalArgumentException("Unsupported authenticated payload type")
            }
        } finally {
            opened.plaintext.fill(0)
        }
    }

    private fun rejectUnless(condition: Boolean, code: EnvelopeRejectedException.Code) {
        if (!condition) throw EnvelopeRejectedException(code)
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
