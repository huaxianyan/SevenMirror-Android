package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedEnvelopePartsV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.security.MessageDigest

data class IdentityTransitionEnvelopeContext(
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

/** Encrypts exact durable identity lifecycle payloads under fresh envelope tuples. */
object IdentityTransitionEnvelopeSender {
    fun createAck(
        context: IdentityTransitionEnvelopeContext,
        canonicalAck: ByteArray,
    ): ByteArray = create(
        context,
        canonicalAck,
        EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_ACK,
    )

    fun createCommit(
        context: IdentityTransitionEnvelopeContext,
        canonicalCommit: ByteArray,
    ): ByteArray = create(
        context,
        canonicalCommit,
        EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_COMMIT,
    )

    private fun create(
        context: IdentityTransitionEnvelopeContext,
        canonicalPayload: ByteArray,
        expectedBody: EncryptedPayload.BodyCase,
    ): ByteArray {
        val payload = EncryptedPayloadCodecV1.decode(canonicalPayload)
        require(payload.bodyCase == expectedBody) {
            "Stored identity transition payload has wrong body"
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
            plaintext = canonicalPayload,
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
