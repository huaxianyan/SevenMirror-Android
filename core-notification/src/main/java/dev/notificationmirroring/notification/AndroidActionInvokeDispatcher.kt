package dev.notificationmirroring.notification

import android.content.Context
import dev.notificationmirroring.crypto.ActionReceipt
import dev.notificationmirroring.crypto.AndroidActionResultOutbox
import dev.notificationmirroring.crypto.AndroidOperationLedger
import dev.notificationmirroring.crypto.AndroidReplayLedger
import dev.notificationmirroring.crypto.AndroidTrustedPeerStore
import dev.notificationmirroring.crypto.AuthenticatedHpke
import dev.notificationmirroring.crypto.EnvelopeRecipientContext
import dev.notificationmirroring.crypto.EnvelopeRejectedException
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import java.security.MessageDigest

class ActionSenderNotApprovedException : Exception("ACTION_SENDER_NOT_APPROVED")

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
    fun receiveOnce(frameBytes: ByteArray, nowUnixMs: Long): ActionReceipt {
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

        return AuthenticatedNotificationActionHandler.receiveAndQueueOnce(
            androidContext = appContext,
            frameBytes = frameBytes,
            recipientContext = EnvelopeRecipientContext(
                workspaceId = workspaceId.copyOf(),
                recipientDeviceId = recipientDeviceId.copyOf(),
                recipientIdentity = recipientIdentity,
                pinnedSenderPublicKey = senderPublicKey,
            ),
            replayLedger = replayLedger,
            operationLedger = operationLedger,
            resultOutbox = resultOutbox,
            nowUnixMs = nowUnixMs,
        )
    }

    private fun rejectUnless(condition: Boolean, code: EnvelopeRejectedException.Code) {
        if (!condition) throw EnvelopeRejectedException(code)
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
