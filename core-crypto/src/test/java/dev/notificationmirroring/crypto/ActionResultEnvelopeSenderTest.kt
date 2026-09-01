package dev.notificationmirroring.crypto

import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class ActionResultEnvelopeSenderTest {
    @Test
    fun encryptsCanonicalResultForOnlyTheIntendedRecipient() {
        val androidIdentity = AuthenticatedHpke.deriveKeyPair(ByteArray(32) { (it + 1).toByte() })
        val chromeIdentity = AuthenticatedHpke.deriveKeyPair(ByteArray(32) { (it + 65).toByte() })
        val idempotencyKey = ByteArray(16) { (it + 1).toByte() }
        val resultPayload = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
                .setActionResult(
                    ActionResult.newBuilder()
                        .setIdempotencyKey(ByteString.copyFrom(idempotencyKey))
                        .setStatus(ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED)
                        .setDetail("private result detail")
                        .build(),
                )
                .build(),
        )

        val frame = ActionResultEnvelopeSender.create(
            ActionResultEnvelopeContext(
                workspaceId = filled(16, 1),
                senderDeviceId = filled(16, 2),
                recipientDeviceId = filled(16, 3),
                senderIdentity = androidIdentity,
                recipientPublicKey = chromeIdentity.publicKey,
                messageId = filled(16, 4),
                sequence = 1,
                createdAtUnixMs = 1_700_000_000_000,
                expiresAtUnixMs = 1_700_000_060_000,
            ),
            resultPayload,
        )

        assertFalse(frame.toString(Charsets.UTF_8).contains("private result detail"))
        val envelope = EncryptedEnvelopeCodecV1.decode(frame)
        val opened = AuthenticatedHpke.open(
            recipient = chromeIdentity,
            senderPublicKey = androidIdentity.publicKey,
            encrypted = AuthenticatedHpke.Ciphertext(
                envelope.encapsulatedKey,
                envelope.ciphertext,
            ),
            aad = envelope.routingHeaderBytes,
        )
        assertArrayEquals(resultPayload, opened)
        val decoded = EncryptedPayloadCodecV1.decode(opened)
        assertEquals(
            ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED,
            decoded.actionResult.status,
        )
        assertArrayEquals(idempotencyKey, decoded.actionResult.idempotencyKey.toByteArray())
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsActionInvokePayload() {
        val identity = AuthenticatedHpke.deriveKeyPair(ByteArray(32) { (it + 1).toByte() })
        ActionResultEnvelopeSender.create(
            ActionResultEnvelopeContext(
                workspaceId = filled(16, 1),
                senderDeviceId = filled(16, 2),
                recipientDeviceId = filled(16, 3),
                senderIdentity = identity,
                recipientPublicKey = identity.publicKey,
                messageId = filled(16, 4),
                sequence = 1,
                createdAtUnixMs = 1,
                expiresAtUnixMs = 2,
            ),
            byteArrayOf(8, 1, 82, 0),
        )
    }

    private fun filled(size: Int, value: Int) = ByteArray(size) { value.toByte() }
}
