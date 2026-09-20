package com.neko7ina.sevenmirror.crypto

import com.neko7ina.sevenmirror.protocol.EncryptedEnvelopeCodecV1
import com.neko7ina.sevenmirror.protocol.EncryptedEnvelopePartsV1
import com.neko7ina.sevenmirror.protocol.RoutingHeaderCodecV1
import com.neko7ina.sevenmirror.protocol.RoutingHeaderV1
import java.security.MessageDigest

data class AuthenticatedPayloadEnvelopeContext(
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

/** The single wire implementation shared by encrypted business payload senders. */
internal object AuthenticatedPayloadEnvelopeSender {
    fun create(
        context: AuthenticatedPayloadEnvelopeContext,
        canonicalPayload: ByteArray,
    ): ByteArray {
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
