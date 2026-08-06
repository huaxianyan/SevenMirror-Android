package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedEnvelopePartsV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.security.MessageDigest

data class ActionResultEnvelopeContext(
    val workspaceId: ByteArray,
    val senderDeviceId: ByteArray,
    val recipientDeviceId: ByteArray,
    val senderIdentity: AuthenticatedHpke.KeyPair,
    val recipientPublicKey: ByteArray,
    val messageId: ByteArray,
    val sequence: Long,
    val createdAtUnixMs: Long,
    val expiresAtUnixMs: Long,
)

/** Encrypts a canonical, cached action.result payload for one Chrome recipient. */
object ActionResultEnvelopeSender {
    fun create(
        context: ActionResultEnvelopeContext,
        canonicalResultPayload: ByteArray,
    ): ByteArray {
        val payload = EncryptedPayloadCodecV1.decode(canonicalResultPayload)
        require(payload.bodyCase == EncryptedPayload.BodyCase.ACTION_RESULT) {
            "Expected canonical action.result payload"
        }

        val routingHeader = RoutingHeaderCodecV1.encode(
            RoutingHeaderV1(
                workspaceId = context.workspaceId,
                senderDeviceId = context.senderDeviceId,
                recipientDeviceId = context.recipientDeviceId,
                senderKeyId = sha256(context.senderIdentity.publicKey),
                recipientKeyId = sha256(context.recipientPublicKey),
                messageId = context.messageId,
                sequence = context.sequence,
                createdAtUnixMs = context.createdAtUnixMs,
                expiresAtUnixMs = context.expiresAtUnixMs,
            ),
        )
        val encrypted = AuthenticatedHpke.seal(
            recipientPublicKey = context.recipientPublicKey,
            sender = context.senderIdentity,
            plaintext = canonicalResultPayload,
            aad = routingHeader,
        )
        return EncryptedEnvelopeCodecV1.encode(
            EncryptedEnvelopePartsV1(
                routingHeader = routingHeader,
                encapsulatedKey = encrypted.encapsulatedKey,
                ciphertext = encrypted.ciphertext,
            ),
        )
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
