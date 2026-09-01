package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedEnvelopePartsV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultAck
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AuthenticatedActionResultAckReceiverInstrumentedTest {
    @Test
    fun exactAckDeletesResultAndDuplicateRemainsIdempotentAcrossRecreation() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val name = "result-ack-${System.nanoTime()}"
        var replay = AndroidReplayLedger(context, name)
        var operations = AndroidOperationLedger(context, name)
        var outbox = AndroidActionResultOutbox(context, name)
        val now = 1_800_000_000_000L
        val chrome = AuthenticatedHpke.generateKeyPair()
        val android = AuthenticatedHpke.generateKeyPair()
        val workspace = ByteArray(16) { 1 }
        val chromeDevice = ByteArray(16) { 2 }
        val androidDevice = ByteArray(16) { 3 }
        val idempotencyKey = ByteArray(16) { 4 }
        val chromeKeyId = sha256(chrome.publicKey)
        val resultPayload = resultPayload(idempotencyKey)
        val resultDigest = sha256(resultPayload)
        val recipientContext = EnvelopeRecipientContext(
            workspace,
            androidDevice,
            android,
            chrome.publicKey,
        )
        try {
            assertEquals(
                AndroidOperationLedger.BeginResult.Accepted,
                operations.beginOrRecover(chromeKeyId, idempotencyKey, now),
            )
            operations.complete(chromeKeyId, idempotencyKey, resultPayload)
            assertEquals(
                AndroidActionResultOutbox.EnqueueResult.ENQUEUED,
                outbox.enqueue(chromeDevice, chromeKeyId, resultPayload, now),
            )

            // Simulate Android process death after result persistence but before ACK receipt.
            replay.close()
            operations.close()
            outbox.close()
            replay = AndroidReplayLedger(context, name)
            operations = AndroidOperationLedger(context, name)
            outbox = AndroidActionResultOutbox(context, name)

            assertEquals(
                AndroidActionResultOutbox.AcknowledgeResult.ACKNOWLEDGED,
                AuthenticatedActionResultAckReceiver.receiveOnce(
                    frame(8, ackPayload(idempotencyKey, resultDigest), now, workspace,
                        chromeDevice, androidDevice, chrome, android),
                    recipientContext,
                    replay,
                    operations,
                    outbox,
                    now,
                ),
            )
            assertEquals(0, outbox.snapshot(now).reservations)
            assertEquals(1, outbox.snapshot(now).acknowledgedResults)
            outbox.close()
            outbox = AndroidActionResultOutbox(context, name)

            assertEquals(
                AndroidActionResultOutbox.AcknowledgeResult.ALREADY_ACKNOWLEDGED,
                AuthenticatedActionResultAckReceiver.receiveOnce(
                    frame(9, ackPayload(idempotencyKey, resultDigest), now, workspace,
                        chromeDevice, androidDevice, chrome, android),
                    recipientContext,
                    replay,
                    operations,
                    outbox,
                    now + 1,
                ),
            )
            assertEquals(0, outbox.snapshot(now + 1).reservations)
            assertEquals(1, outbox.snapshot(now + 1).acknowledgedResults)
        } finally {
            replay.clear()
            operations.clear()
            outbox.clear()
        }
    }

    @Test
    fun wrongDigestSenderDeviceAndUnknownOperationFailClosedWithoutDeletion() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val name = "rejected-result-ack-${System.nanoTime()}"
        val replay = AndroidReplayLedger(context, name)
        val operations = AndroidOperationLedger(context, name)
        val outbox = AndroidActionResultOutbox(context, name)
        val now = 1_800_000_000_000L
        val chrome = AuthenticatedHpke.generateKeyPair()
        val otherChrome = AuthenticatedHpke.generateKeyPair()
        val android = AuthenticatedHpke.generateKeyPair()
        val workspace = ByteArray(16) { 1 }
        val chromeDevice = ByteArray(16) { 2 }
        val androidDevice = ByteArray(16) { 3 }
        val idempotencyKey = ByteArray(16) { 4 }
        val chromeKeyId = sha256(chrome.publicKey)
        val resultPayload = resultPayload(idempotencyKey)
        val resultDigest = sha256(resultPayload)
        try {
            operations.beginOrRecover(chromeKeyId, idempotencyKey, now)
            operations.complete(chromeKeyId, idempotencyKey, resultPayload)
            outbox.enqueue(chromeDevice, chromeKeyId, resultPayload, now)

            val wrongDigest = assertThrows(ActionResultAckRejectedException::class.java) {
                AuthenticatedActionResultAckReceiver.receiveOnce(
                    frame(10, ackPayload(idempotencyKey, ByteArray(32) { 7 }), now, workspace,
                        chromeDevice, androidDevice, chrome, android),
                    EnvelopeRecipientContext(workspace, androidDevice, android, chrome.publicKey),
                    replay,
                    operations,
                    outbox,
                    now,
                )
            }
            assertEquals(
                ActionResultAckRejectedException.Code.RESULT_DIGEST_MISMATCH,
                wrongDigest.code,
            )

            val wrongSender = assertThrows(ActionResultAckRejectedException::class.java) {
                AuthenticatedActionResultAckReceiver.receiveOnce(
                    frame(11, ackPayload(idempotencyKey, resultDigest), now, workspace,
                        chromeDevice, androidDevice, otherChrome, android),
                    EnvelopeRecipientContext(workspace, androidDevice, android, otherChrome.publicKey),
                    replay,
                    operations,
                    outbox,
                    now,
                )
            }
            assertEquals(ActionResultAckRejectedException.Code.UNKNOWN_OPERATION, wrongSender.code)

            assertThrows(IllegalStateException::class.java) {
                AuthenticatedActionResultAckReceiver.receiveOnce(
                    frame(12, ackPayload(idempotencyKey, resultDigest), now, workspace,
                        ByteArray(16) { 6 }, androidDevice, chrome, android),
                    EnvelopeRecipientContext(workspace, androidDevice, android, chrome.publicKey),
                    replay,
                    operations,
                    outbox,
                    now,
                )
            }

            val unknownKey = ByteArray(16) { 9 }
            val unknown = assertThrows(ActionResultAckRejectedException::class.java) {
                AuthenticatedActionResultAckReceiver.receiveOnce(
                    frame(13, ackPayload(unknownKey, resultDigest), now, workspace,
                        chromeDevice, androidDevice, chrome, android),
                    EnvelopeRecipientContext(workspace, androidDevice, android, chrome.publicKey),
                    replay,
                    operations,
                    outbox,
                    now,
                )
            }
            assertEquals(ActionResultAckRejectedException.Code.UNKNOWN_OPERATION, unknown.code)
            assertEquals(1, outbox.snapshot(now).reservations)
        } finally {
            replay.clear()
            operations.clear()
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

    private fun ackPayload(idempotencyKey: ByteArray, digest: ByteArray): ByteArray =
        EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
                .setActionResultAck(
                    ActionResultAck.newBuilder()
                        .setIdempotencyKey(ByteString.copyFrom(idempotencyKey))
                        .setResultSha256(ByteString.copyFrom(digest))
                        .build(),
                )
                .build(),
        )

    private fun frame(
        messageByte: Int,
        plaintext: ByteArray,
        now: Long,
        workspace: ByteArray,
        senderDevice: ByteArray,
        recipientDevice: ByteArray,
        sender: AuthenticatedHpke.KeyPair,
        recipient: AuthenticatedHpke.KeyPair,
    ): ByteArray {
        val header = RoutingHeaderCodecV1.encode(
            RoutingHeaderV1(
                workspaceId = workspace,
                senderDeviceId = senderDevice,
                recipientDeviceId = recipientDevice,
                senderKeyId = sha256(sender.publicKey),
                recipientKeyId = sha256(recipient.publicKey),
                messageId = ByteArray(16) { messageByte.toByte() },
                sequence = messageByte.toLong(),
                createdAtUnixMs = now,
                expiresAtUnixMs = now + 60_000,
            ),
        )
        val encrypted = AuthenticatedHpke.seal(recipient.publicKey, sender, plaintext, header)
        return EncryptedEnvelopeCodecV1.encode(
            EncryptedEnvelopePartsV1(header, encrypted.encapsulatedKey, encrypted.ciphertext),
        )
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
