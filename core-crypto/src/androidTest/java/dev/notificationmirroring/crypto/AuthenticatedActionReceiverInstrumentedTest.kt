package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedEnvelopePartsV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import dev.notificationmirroring.protocol.generated.v1.ActionInvoke
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

@RunWith(AndroidJUnit4::class)
class AuthenticatedActionReceiverInstrumentedTest {
    @Test
    fun commitsReplayAndOperationLedgersBeforeSideEffect() {
        val androidContext = ApplicationProvider.getApplicationContext<android.content.Context>()
        val name = "action-${System.nanoTime()}"
        val replay = AndroidReplayLedger(androidContext, name)
        var operations = AndroidOperationLedger(androidContext, name)
        val now = 1_800_000_000_000L
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val workspace = ByteArray(16) { 1 }
        val recipientDevice = ByteArray(16) { 3 }
        val recipientContext = EnvelopeRecipientContext(
            workspace,
            recipientDevice,
            recipient,
            sender.publicKey,
        )
        var sideEffects = 0
        val payload = canonicalActionPayload()

        try {
            val first = frame(4, payload, now, workspace, recipientDevice, sender, recipient)
            val result = AuthenticatedActionReceiver.receiveOnce(
                first,
                recipientContext,
                replay,
                operations,
                now,
            ) {
                sideEffects += 1
                successResult(it)
            }
            assertEquals(ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED, result.result.status)
            assertEquals(false, result.recovered)
            assertEquals(1, sideEffects)

            val replayDuplicate = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedActionReceiver.receiveOnce(
                    first,
                    recipientContext,
                    replay,
                    operations,
                    now,
                ) {
                    sideEffects += 1
                    successResult(it)
                }
            }
            assertEquals(EnvelopeRejectedException.Code.DUPLICATE, replayDuplicate.code)

            operations.close()
            operations = AndroidOperationLedger(androidContext, name)
            val logicalDuplicate = frame(5, payload, now, workspace, recipientDevice, sender, recipient)
            val recovered = AuthenticatedActionReceiver.receiveOnce(
                logicalDuplicate,
                recipientContext,
                replay,
                operations,
                now,
            ) {
                sideEffects += 1
                successResult(it)
            }
            assertEquals(true, recovered.recovered)
            assertEquals(ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED, recovered.result.status)
            assertEquals(1, sideEffects)

            val invalid = frame(
                6,
                byteArrayOf(8, 1),
                now,
                workspace,
                recipientDevice,
                sender,
                recipient,
            )
            assertThrows(IllegalArgumentException::class.java) {
                AuthenticatedActionReceiver.receiveOnce(
                    invalid,
                    recipientContext,
                    replay,
                    operations,
                    now,
                ) {
                    sideEffects += 1
                    successResult(it)
                }
            }
            val consumedInvalid = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedActionReceiver.receiveOnce(
                    invalid,
                    recipientContext,
                    replay,
                    operations,
                    now,
                ) {
                    sideEffects += 1
                    successResult(it)
                }
            }
            assertEquals(EnvelopeRejectedException.Code.DUPLICATE, consumedInvalid.code)
            assertEquals(1, sideEffects)

            val uncertainPayload = canonicalActionPayload(0xc3)
            val uncertain = frame(7, uncertainPayload, now, workspace, recipientDevice, sender, recipient)
            assertThrows(IllegalStateException::class.java) {
                AuthenticatedActionReceiver.receiveOnce(
                    uncertain,
                    recipientContext,
                    replay,
                    operations,
                    now,
                ) {
                    sideEffects += 1
                    throw IllegalStateException("simulated crash around side effect")
                }
            }
            val uncertainRetry = frame(8, uncertainPayload, now, workspace, recipientDevice, sender, recipient)
            val unknown = AuthenticatedActionReceiver.receiveOnce(
                uncertainRetry,
                recipientContext,
                replay,
                operations,
                now,
            ) {
                sideEffects += 1
                successResult(it)
            }
            assertEquals(true, unknown.recovered)
            assertEquals(ActionResultStatus.ACTION_RESULT_STATUS_OUTCOME_UNKNOWN, unknown.result.status)
            assertEquals(2, sideEffects)
        } finally {
            replay.clear()
            operations.clear()
        }
    }

    @Test
    fun reservesResultCapacityBeforeExecutionAndCompletesCrashRecovery() {
        val androidContext = ApplicationProvider.getApplicationContext<android.content.Context>()
        val name = "queued-action-${System.nanoTime()}"
        val replay = AndroidReplayLedger(androidContext, name)
        val operations = AndroidOperationLedger(androidContext, name)
        val outbox = AndroidActionResultOutbox(androidContext, name)
        val now = 1_800_000_000_000L
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val workspace = ByteArray(16) { 1 }
        val recipientDevice = ByteArray(16) { 3 }
        val recipientContext = EnvelopeRecipientContext(
            workspace,
            recipientDevice,
            recipient,
            sender.publicKey,
        )
        val payload = canonicalActionPayload(0xc4)
        var sideEffects = 0
        try {
            assertThrows(IllegalStateException::class.java) {
                AuthenticatedActionReceiver.receiveAndQueueOnce(
                    frame(9, payload, now, workspace, recipientDevice, sender, recipient),
                    recipientContext,
                    replay,
                    operations,
                    outbox,
                    now,
                ) {
                    sideEffects += 1
                    throw IllegalStateException("simulated crash after reservation")
                }
            }
            assertEquals(1, sideEffects)
            assertTrue(outbox.due(now).isEmpty())

            val recovered = AuthenticatedActionReceiver.receiveAndQueueOnce(
                frame(10, payload, now, workspace, recipientDevice, sender, recipient),
                recipientContext,
                replay,
                operations,
                outbox,
                now + 1,
            ) {
                sideEffects += 1
                successResult(it)
            }
            assertEquals(true, recovered.recovered)
            assertEquals(ActionResultStatus.ACTION_RESULT_STATUS_OUTCOME_UNKNOWN, recovered.result.status)
            assertEquals(1, sideEffects)
            assertEquals(1, outbox.due(now + 1).size)
        } finally {
            replay.clear()
            operations.clear()
            outbox.clear()
        }
    }

    @Test
    fun fullResultOutboxRejectsBeforeExecution() {
        val androidContext = ApplicationProvider.getApplicationContext<android.content.Context>()
        val name = "full-outbox-${System.nanoTime()}"
        val replay = AndroidReplayLedger(androidContext, name)
        val operations = AndroidOperationLedger(androidContext, name)
        val outbox = AndroidActionResultOutbox(androidContext, name, maxEntries = 1)
        val now = 1_800_000_000_000L
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val workspace = ByteArray(16) { 1 }
        val recipientDevice = ByteArray(16) { 3 }
        val recipientContext = EnvelopeRecipientContext(
            workspace,
            recipientDevice,
            recipient,
            sender.publicKey,
        )
        var sideEffects = 0
        try {
            assertEquals(
                AndroidActionResultOutbox.ReserveResult.RESERVED,
                outbox.reserve(
                    ByteArray(16) { 8 },
                    ByteArray(32) { 9 },
                    ByteArray(16) { 10 },
                    now,
                ),
            )
            val rejected = assertThrows(ActionRejectedException::class.java) {
                AuthenticatedActionReceiver.receiveAndQueueOnce(
                    frame(
                        11,
                        canonicalActionPayload(0xc5),
                        now,
                        workspace,
                        recipientDevice,
                        sender,
                        recipient,
                    ),
                    recipientContext,
                    replay,
                    operations,
                    outbox,
                    now,
                ) {
                    sideEffects += 1
                    successResult(it)
                }
            }
            assertEquals(
                ActionRejectedException.Code.RESULT_OUTBOX_CAPACITY_EXCEEDED,
                rejected.code,
            )
            assertEquals(0, sideEffects)
        } finally {
            replay.clear()
            operations.clear()
            outbox.clear()
        }
    }

    private fun successResult(action: ActionInvoke): ActionResult = ActionResult.newBuilder()
        .setIdempotencyKey(action.idempotencyKey)
        .setStatus(ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED)
        .build()

    private fun canonicalActionPayload(idempotencyByte: Int = 0xb2): ByteArray {
        val action = ActionInvoke.newBuilder()
            .setNotificationId("test.notification/42")
            .setNotificationRevision(7)
            .setActionId(ByteString.copyFrom(ByteArray(16) { 0xa1.toByte() }))
            .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { idempotencyByte.toByte() }))
            .setReplyText("acknowledged")
            .build()
        return EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
                .setActionInvoke(action)
                .build(),
        )
    }

    private fun frame(
        messageByte: Int,
        plaintext: ByteArray,
        now: Long,
        workspace: ByteArray,
        recipientDevice: ByteArray,
        sender: AuthenticatedHpke.KeyPair,
        recipient: AuthenticatedHpke.KeyPair,
    ): ByteArray {
        val header = RoutingHeaderCodecV1.encode(
            RoutingHeaderV1(
                workspaceId = workspace,
                senderDeviceId = ByteArray(16) { 2 },
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
