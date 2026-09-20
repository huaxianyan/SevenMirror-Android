package com.neko7ina.sevenmirror.crypto

import com.neko7ina.sevenmirror.protocol.EncryptedPayloadCodecV1
import com.neko7ina.sevenmirror.protocol.generated.v1.EncryptedPayload

typealias ActionResultEnvelopeContext = AuthenticatedPayloadEnvelopeContext

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

        return AuthenticatedPayloadEnvelopeSender.create(context, canonicalResultPayload)
    }
}
