package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedEnvelopePartsV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import org.bouncycastle.crypto.InvalidCipherTextException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

@RunWith(AndroidJUnit4::class)
class AuthenticatedEnvelopeReceiverInstrumentedTest {
    @Test
    fun authenticatesBeforePersistentlyConsumingReplayTuple() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val ledger = AndroidReplayLedger(context, "receiver-${System.nanoTime()}")
        val now = 1_800_000_000_000L
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val workspaceId = ByteArray(16) { 1 }
        val recipientDeviceId = ByteArray(16) { 3 }
        val routingHeader = RoutingHeaderCodecV1.encode(
            RoutingHeaderV1(
                workspaceId = workspaceId,
                senderDeviceId = ByteArray(16) { 2 },
                recipientDeviceId = recipientDeviceId,
                senderKeyId = sha256(sender.publicKey),
                recipientKeyId = sha256(recipient.publicKey),
                messageId = ByteArray(16) { 4 },
                sequence = 1,
                createdAtUnixMs = now,
                expiresAtUnixMs = now + 60_000,
            ),
        )
        val plaintext = "mark as read".encodeToByteArray()
        val encrypted = AuthenticatedHpke.seal(
            recipient.publicKey,
            sender,
            plaintext,
            routingHeader,
        )
        val frame = EncryptedEnvelopeCodecV1.encode(
            EncryptedEnvelopePartsV1(
                routingHeader,
                encrypted.encapsulatedKey,
                encrypted.ciphertext,
            ),
        )
        val recipientContext = EnvelopeRecipientContext(
            workspaceId,
            recipientDeviceId,
            recipient,
            sender.publicKey,
        )

        try {
            val tampered = frame.copyOf().apply {
                this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
            }
            assertThrows(InvalidCipherTextException::class.java) {
                AuthenticatedEnvelopeReceiver.openOnce(tampered, recipientContext, ledger, now)
            }

            val opened = AuthenticatedEnvelopeReceiver.openOnce(
                frame,
                recipientContext,
                ledger,
                now,
            )
            assertArrayEquals(plaintext, opened.plaintext)

            val duplicate = assertThrows(EnvelopeRejectedException::class.java) {
                AuthenticatedEnvelopeReceiver.openOnce(frame, recipientContext, ledger, now)
            }
            assertEquals(EnvelopeRejectedException.Code.DUPLICATE, duplicate.code)
        } finally {
            ledger.clear()
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
