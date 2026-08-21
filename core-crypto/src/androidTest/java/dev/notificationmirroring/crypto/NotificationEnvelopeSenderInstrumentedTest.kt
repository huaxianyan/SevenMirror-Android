package dev.notificationmirroring.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NotificationEnvelopeSenderInstrumentedTest {
    @Test
    fun appNotificationIsIndependentlyEncryptedForEveryRosterRecipient() {
        val workspaceId = filled(16, 1)
        val androidDeviceId = filled(16, 2)
        val firstChromeDeviceId = filled(16, 3)
        val secondChromeDeviceId = filled(16, 6)
        val androidIdentity = AuthenticatedHpke.deriveKeyPair(filled(32, 4))
        val firstChromeIdentity = AuthenticatedHpke.deriveKeyPair(filled(32, 5))
        val secondChromeIdentity = AuthenticatedHpke.deriveKeyPair(filled(32, 7))
        val directory = WorkspaceNotificationRecipientDirectory { _, _, _ ->
            listOf(
                recipient(firstChromeDeviceId, firstChromeIdentity.publicKey),
                recipient(secondChromeDeviceId, secondChromeIdentity.publicKey),
            )
        }
        val sequence = AtomicLong(8)
        val sender = NotificationEnvelopeSender(
            workspaceId = workspaceId,
            senderDeviceId = androidDeviceId,
            senderIdentity = androidIdentity,
            recipients = directory,
            allocateSequence = { sequence.incrementAndGet() },
        )
        try {
            val frames = requireNotNull(
                sender.createUpsert(
                    notificationId = "synthetic.notification/42",
                    revision = 7,
                    title = "Synthetic notification",
                    body = "Encrypted test notification",
                    nowUnixMs = 1_700_000_000_000,
                ),
            )

            assertEquals(2, frames.size)
            assertFalse(frames.any { it.toString(Charsets.UTF_8).contains("Encrypted test notification") })
            val firstPayload = openPayload(frames[0], firstChromeIdentity, androidIdentity)
            val secondPayload = openPayload(frames[1], secondChromeIdentity, androidIdentity)
            assertEquals(9L, firstPayload.first)
            assertEquals(10L, secondPayload.first)
            assertEquals(EncryptedPayload.BodyCase.NOTIFICATION_UPSERT, firstPayload.second.bodyCase)
            assertEquals(firstPayload.second, secondPayload.second)
            assertEquals("Encrypted test notification", firstPayload.second.notificationUpsert.body)
            val firstRoute = RoutingHeaderCodecV1.decode(
                EncryptedEnvelopeCodecV1.decode(frames[0]).routingHeaderBytes,
            )
            val secondRoute = RoutingHeaderCodecV1.decode(
                EncryptedEnvelopeCodecV1.decode(frames[1]).routingHeaderBytes,
            )
            assertNotEquals(firstRoute.messageId.toList(), secondRoute.messageId.toList())
            assertNotEquals(frames[0].toList(), frames[1].toList())

            val snapshotFrames = requireNotNull(
                sender.createSnapshotManifest(
                    highWaterRevision = 9,
                    activeNotifications = mapOf(
                        "synthetic.notification/99" to 9L,
                        "synthetic.notification/42" to 7L,
                    ),
                    nowUnixMs = 1_700_000_000_000,
                ),
            )
            assertEquals(2, snapshotFrames.size)
            val snapshot = openPayload(snapshotFrames[0], firstChromeIdentity, androidIdentity)
            assertEquals(11L, snapshot.first)
            assertEquals(
                listOf("synthetic.notification/42", "synthetic.notification/99"),
                snapshot.second.notificationSnapshotManifest.activeNotificationsList
                    .map { it.notificationId },
            )
            assertEquals(9L, snapshot.second.notificationSnapshotManifest.highWaterRevision)
        } finally {
            sender.clearIdentity()
        }
    }

    private fun recipient(deviceId: ByteArray, publicKey: ByteArray) =
        WorkspaceNotificationRecipient(
            deviceId.copyOf(),
            MessageDigest.getInstance("SHA-256").digest(publicKey),
            publicKey.copyOf(),
        )

    private fun openPayload(
        frame: ByteArray,
        recipient: AuthenticatedHpke.KeyPair,
        sender: AuthenticatedHpke.KeyPair,
    ): Pair<Long, EncryptedPayload> {
        val envelope = EncryptedEnvelopeCodecV1.decode(frame)
        val route = RoutingHeaderCodecV1.decode(envelope.routingHeaderBytes)
        val opened = AuthenticatedHpke.open(
            recipient = recipient,
            senderPublicKey = sender.publicKey,
            encrypted = AuthenticatedHpke.Ciphertext(
                envelope.encapsulatedKey,
                envelope.ciphertext,
            ),
            aad = envelope.routingHeaderBytes,
        )
        return route.sequence to EncryptedPayloadCodecV1.decode(opened)
    }

    private fun filled(size: Int, value: Int) = ByteArray(size) { value.toByte() }
}
