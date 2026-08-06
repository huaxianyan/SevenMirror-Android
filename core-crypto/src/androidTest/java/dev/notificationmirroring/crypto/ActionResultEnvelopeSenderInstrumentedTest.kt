package dev.notificationmirroring.crypto

import com.google.protobuf.ByteString
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ActionResultEnvelopeSenderInstrumentedTest {
    @Test
    fun encryptsCachedResultOnAndroidRuntime() {
        val androidIdentity = AuthenticatedHpke.generateKeyPair()
        val chromeIdentity = AuthenticatedHpke.generateKeyPair()
        val key = ByteArray(16) { (it + 1).toByte() }
        val resultPayload = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
                .setActionResult(
                    ActionResult.newBuilder()
                        .setIdempotencyKey(ByteString.copyFrom(key))
                        .setStatus(ActionResultStatus.ACTION_RESULT_STATUS_OUTCOME_UNKNOWN)
                        .build(),
                )
                .build(),
        )
        val frame = ActionResultEnvelopeSender.create(
            ActionResultEnvelopeContext(
                workspaceId = ByteArray(16) { 1 },
                senderDeviceId = ByteArray(16) { 2 },
                recipientDeviceId = ByteArray(16) { 3 },
                senderIdentity = androidIdentity,
                recipientPublicKey = chromeIdentity.publicKey,
                messageId = ByteArray(16) { 4 },
                sequence = 1,
                createdAtUnixMs = 1_800_000_000_000,
                expiresAtUnixMs = 1_800_000_060_000,
            ),
            resultPayload,
        )
        val envelope = EncryptedEnvelopeCodecV1.decode(frame)
        val opened = AuthenticatedHpke.open(
            chromeIdentity,
            androidIdentity.publicKey,
            AuthenticatedHpke.Ciphertext(envelope.encapsulatedKey, envelope.ciphertext),
            envelope.routingHeaderBytes,
        )

        assertArrayEquals(resultPayload, opened)
        assertEquals(
            ActionResultStatus.ACTION_RESULT_STATUS_OUTCOME_UNKNOWN,
            EncryptedPayloadCodecV1.decode(opened).actionResult.status,
        )
    }
}
