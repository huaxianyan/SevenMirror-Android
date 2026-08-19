package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload

typealias IdentityTransitionEnvelopeContext = AuthenticatedPayloadEnvelopeContext

/** Encrypts exact durable identity lifecycle payloads under fresh envelope tuples. */
object IdentityTransitionEnvelopeSender {
    fun createTransition(
        context: IdentityTransitionEnvelopeContext,
        canonicalTransition: ByteArray,
    ): ByteArray = create(
        context,
        canonicalTransition,
        EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION,
    )

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
        return AuthenticatedPayloadEnvelopeSender.create(context, canonicalPayload)
    }
}
