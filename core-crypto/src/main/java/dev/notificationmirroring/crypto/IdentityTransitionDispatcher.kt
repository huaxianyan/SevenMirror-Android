package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import java.security.MessageDigest

enum class IdentityTransitionDispatchResult {
    PEER_TRANSITION,
    LOCAL_ACK,
    PEER_COMMIT,
    BUSINESS_FALLBACK,
}

/** Routes lifecycle frames while keeping a pending local identity ACK-only. */
class IdentityTransitionDispatcher(
    private val workspaceId: ByteArray,
    private val recipientDeviceId: ByteArray,
    currentIdentity: AuthenticatedHpke.KeyPair,
    pendingIdentity: AuthenticatedHpke.KeyPair?,
    private val trustedPeers: AndroidTrustedPeerStore,
    private val localTransitions: AndroidLocalIdentityTransitionStore,
    private val replayLedger: AndroidReplayLedger,
    private val businessFallback: (ByteArray, Long) -> Unit,
) {
    private val currentIdentity = currentIdentity.copyKeyPair()
    private val pendingIdentity = pendingIdentity?.copyKeyPair()
    private val currentKeyId = sha256(this.currentIdentity.publicKey)
    private val pendingKeyId = this.pendingIdentity?.let { sha256(it.publicKey) }

    fun receive(frameBytes: ByteArray, nowUnixMs: Long): IdentityTransitionDispatchResult {
        val envelope = EncryptedEnvelopeCodecV1.decode(frameBytes)
        val header = envelope.routingHeader
        requireTransportTuple(header)
        val pending = pendingIdentity
        if (pending != null && MessageDigest.isEqual(header.recipientKeyId, pendingKeyId)) {
            val senderPublicKey = requireApprovedSender(header)
            try {
                AuthenticatedEnvelopeReceiver.receivePendingIdentityAckOnce(
                    frameBytes,
                    EnvelopeRecipientContext(
                        workspaceId,
                        recipientDeviceId,
                        pending,
                        senderPublicKey,
                    ),
                    localTransitions,
                    replayLedger,
                    nowUnixMs,
                )
            } finally {
                senderPublicKey.fill(0)
            }
            return IdentityTransitionDispatchResult.LOCAL_ACK
        }
        if (!MessageDigest.isEqual(header.recipientKeyId, currentKeyId)) {
            throw EnvelopeRejectedException(EnvelopeRejectedException.Code.RECIPIENT_KEY_MISMATCH)
        }

        trustedPeers.resolveIdentityCommitSender(
            workspaceId,
            header.senderDeviceId,
            header.senderKeyId,
            nowUnixMs,
        )?.let { binding ->
            binding.senderPublicKey.fill(0)
            AuthenticatedEnvelopeReceiver.receiveIdentityTransitionCommitOnce(
                frameBytes,
                workspaceId,
                recipientDeviceId,
                currentIdentity,
                trustedPeers,
                replayLedger,
                nowUnixMs,
            )
            return IdentityTransitionDispatchResult.PEER_COMMIT
        }

        val senderPublicKey = requireApprovedSender(header)
        try {
            try {
                AuthenticatedEnvelopeReceiver.receiveIdentityTransitionOnce(
                    frameBytes,
                    EnvelopeRecipientContext(
                        workspaceId,
                        recipientDeviceId,
                        currentIdentity,
                        senderPublicKey,
                    ),
                    trustedPeers,
                    replayLedger,
                    nowUnixMs,
                )
                return IdentityTransitionDispatchResult.PEER_TRANSITION
            } catch (error: EnvelopeRejectedException) {
                if (error.code != EnvelopeRejectedException.Code.IDENTITY_TRANSITION_PAYLOAD_MISMATCH) {
                    throw error
                }
            }
        } finally {
            senderPublicKey.fill(0)
        }
        businessFallback(frameBytes, nowUnixMs)
        return IdentityTransitionDispatchResult.BUSINESS_FALLBACK
    }

    fun clear() {
        currentIdentity.privateKey.fill(0)
        pendingIdentity?.privateKey?.fill(0)
    }

    private fun requireApprovedSender(header: RoutingHeaderV1): ByteArray =
        trustedPeers.findApproved(
            header.workspaceId,
            header.senderDeviceId,
            header.senderKeyId,
        ) ?: throw EnvelopeRejectedException(EnvelopeRejectedException.Code.WRONG_SENDER)

    private fun requireTransportTuple(header: RoutingHeaderV1) {
        if (!MessageDigest.isEqual(header.workspaceId, workspaceId)) {
            throw EnvelopeRejectedException(EnvelopeRejectedException.Code.WRONG_WORKSPACE)
        }
        if (!MessageDigest.isEqual(header.recipientDeviceId, recipientDeviceId)) {
            throw EnvelopeRejectedException(EnvelopeRejectedException.Code.WRONG_RECIPIENT)
        }
    }

    private fun AuthenticatedHpke.KeyPair.copyKeyPair() = AuthenticatedHpke.KeyPair(
        publicKey.copyOf(),
        privateKey.copyOf(),
    )

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
