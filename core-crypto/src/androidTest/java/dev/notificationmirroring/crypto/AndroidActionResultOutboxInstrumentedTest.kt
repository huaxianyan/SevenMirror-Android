package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidActionResultOutboxInstrumentedTest {
    @Test
    fun persistsCanonicalResultRetriesAndSequenceAcrossRecreation() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val name = "test-${UUID.randomUUID()}"
        val recipientDeviceId = ByteArray(16) { 2 }
        val recipientKeyId = ByteArray(32) { 3 }
        val idempotencyKey = ByteArray(16) { 4 }
        val payload = resultPayload(idempotencyKey)
        var outbox = AndroidActionResultOutbox(context, name)
        try {
            assertEquals(
                AndroidActionResultOutbox.EnqueueResult.ENQUEUED,
                outbox.enqueue(recipientDeviceId, recipientKeyId, payload, 1_000),
            )
            assertEquals(
                AndroidActionResultOutbox.EnqueueResult.ALREADY_ENQUEUED,
                outbox.enqueue(recipientDeviceId, recipientKeyId, payload, 1_001),
            )
            val first = outbox.due(1_001).single()
            assertArrayEquals(payload, first.resultPayload)
            assertEquals(0, first.attemptCount)
            assertEquals(1L, outbox.allocateSequence(recipientKeyId))
            outbox.recordSendAttempt(first.rowId, 2_000, maximumAttempts = 3)
            assertTrue(outbox.due(1_999).isEmpty())
            outbox.close()

            outbox = AndroidActionResultOutbox(context, name)
            val recovered = outbox.due(2_000).single()
            assertEquals(1, recovered.attemptCount)
            assertEquals(2L, outbox.allocateSequence(recipientKeyId))
            outbox.recordSendAttempt(recovered.rowId, 3_000, maximumAttempts = 2)
            assertTrue(outbox.due(3_000).isEmpty())
            assertEquals(
                AndroidActionResultOutbox.EnqueueResult.ALREADY_ENQUEUED,
                outbox.enqueue(recipientDeviceId, recipientKeyId, payload, 3_001),
            )
            assertEquals(0, outbox.due(3_001).single().attemptCount)
        } finally {
            outbox.clear()
        }
    }

    @Test
    fun capacityFailsClosedWithoutEvictingLiveResult() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val outbox = AndroidActionResultOutbox(
            context,
            "test-${UUID.randomUUID()}",
            maxEntries = 1,
        )
        try {
            val recipientDeviceId = ByteArray(16) { 2 }
            val recipientKeyId = ByteArray(32) { 3 }
            assertEquals(
                AndroidActionResultOutbox.EnqueueResult.ENQUEUED,
                outbox.enqueue(
                    recipientDeviceId,
                    recipientKeyId,
                    resultPayload(ByteArray(16) { 4 }),
                    1_000,
                ),
            )
            assertEquals(
                AndroidActionResultOutbox.EnqueueResult.CAPACITY_EXCEEDED,
                outbox.enqueue(
                    recipientDeviceId,
                    recipientKeyId,
                    resultPayload(ByteArray(16) { 5 }),
                    1_001,
                ),
            )
            assertEquals(1, outbox.due(1_001).size)
        } finally {
            outbox.clear()
        }
    }

    private fun resultPayload(idempotencyKey: ByteArray): ByteArray =
        EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
                .setActionResult(
                    ActionResult.newBuilder()
                        .setIdempotencyKey(ByteString.copyFrom(idempotencyKey))
                        .setStatus(ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED)
                        .build(),
                )
                .build(),
        )
}
