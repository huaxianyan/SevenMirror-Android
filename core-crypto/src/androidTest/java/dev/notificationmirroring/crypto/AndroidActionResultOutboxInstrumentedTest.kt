package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
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
            assertEquals(
                AndroidActionResultOutbox.Snapshot(
                    reservations = 1,
                    completedResults = 1,
                    dueResults = 1,
                    dormantResults = 0,
                    acknowledgedResults = 0,
                    acceptedSendAttempts = 0,
                ),
                outbox.snapshot(1_001),
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
                AndroidActionResultOutbox.Snapshot(
                    reservations = 1,
                    completedResults = 1,
                    dueResults = 0,
                    dormantResults = 1,
                    acknowledgedResults = 0,
                    acceptedSendAttempts = 2,
                ),
                outbox.snapshot(3_000),
            )
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
    fun encryptsAndRetriesOnlyForStillAuthorizedRecipient() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val name = "test-${UUID.randomUUID()}"
        val outbox = AndroidActionResultOutbox(context, name)
        var recipientAuthorized = true
        val workspace = ByteArray(16) { 1 }
        val senderDeviceId = ByteArray(16) { 2 }
        val recipientDeviceId = ByteArray(16) { 3 }
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val recipientKeyId = java.security.MessageDigest.getInstance("SHA-256")
            .digest(recipient.publicKey)
        val payload = resultPayload(ByteArray(16) { 4 })
        try {
            assertEquals(
                AndroidActionResultOutbox.EnqueueResult.ENQUEUED,
                outbox.enqueue(recipientDeviceId, recipientKeyId, payload, 1_000),
            )
            val drainer = ActionResultOutboxDrainer(
                workspace,
                senderDeviceId,
                sender,
                WorkspaceActionPeerResolver { resolvedWorkspace, _, deviceId, keyId, _ ->
                    if (
                        recipientAuthorized &&
                        resolvedWorkspace.contentEquals(workspace) &&
                        deviceId.contentEquals(recipientDeviceId) &&
                        keyId.contentEquals(recipientKeyId)
                    ) {
                        WorkspaceActionPeer(deviceId, keyId, recipient.publicKey)
                    } else {
                        null
                    }
                },
                outbox,
            )
            var encryptedFrame: ByteArray? = null
            val first = drainer.drainDue(1_000) { frame ->
                encryptedFrame = frame.copyOf()
                true
            }
            assertEquals(1, first.acceptedSends)
            assertEquals(1_000L, first.nextWakeDelayMs)
            val envelope = EncryptedEnvelopeCodecV1.decode(requireNotNull(encryptedFrame))
            val opened = AuthenticatedHpke.open(
                recipient,
                sender.publicKey,
                AuthenticatedHpke.Ciphertext(envelope.encapsulatedKey, envelope.ciphertext),
                envelope.routingHeaderBytes,
            )
            assertArrayEquals(payload, opened)
            assertEquals(1L, envelope.routingHeader.sequence)

            assertEquals(2_000L, drainer.drainDue(2_000) { true }.nextWakeDelayMs)
            assertEquals(4_000L, drainer.drainDue(4_000) { true }.nextWakeDelayMs)
            assertEquals(8_000L, drainer.drainDue(8_000) { true }.nextWakeDelayMs)
            val finalAttempt = drainer.drainDue(16_000) { true }
            assertEquals(1, finalAttempt.acceptedSends)
            assertEquals(null, finalAttempt.nextWakeDelayMs)
            assertTrue(outbox.due(30_000).isEmpty())

            recipientAuthorized = false
            assertEquals(
                AndroidActionResultOutbox.EnqueueResult.ALREADY_ENQUEUED,
                outbox.enqueue(recipientDeviceId, recipientKeyId, payload, 31_000),
            )
            assertEquals(0, drainer.drainDue(31_000) { true }.attemptedEntries)
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
