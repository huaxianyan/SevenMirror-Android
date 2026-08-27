package dev.notificationmirroring.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.NotificationActionDescriptor
import dev.notificationmirroring.protocol.generated.v1.NotificationMedia
import dev.notificationmirroring.protocol.generated.v1.NotificationMediaMimeType
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
        val appIcon = media(
            contentSha256Hex = "b8ddfdc36eaa6806b874553dca78f3fcaa8b6b964c769ef086868804a31f3bd6",
            width = 2,
            height = 1,
            encodedHex = "89504e470d0a1a0a0000000d4948445200000002000000010806000000f4227f8a" +
                "0000000e4944415478da63f8cfc0f01f040110f803fd53fd8f190000000049454e44ae426082",
        )
        val avatar = media(
            contentSha256Hex = "9f02a3200ce114a72862a10250f945abeef64b11fc3797ed5327f74147a894af",
            width = 1,
            height = 2,
            encodedHex = "89504e470d0a1a0a0000000d49484452000000010000000208060000009981b627" +
                "0000000e4944415478da636060f8ff1f8c0014f504fc54cca3620000000049454e44ae426082",
        )
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
                    sourceApplicationId = "dev.notificationmirroring.android",
                    sourceApplicationName = "SevenMirror",
                    title = "Synthetic notification",
                    body = "Encrypted test notification\n[图片]",
                    appIcon = appIcon,
                    avatar = avatar,
                    containsContentImage = true,
                    actions = listOf(
                        NotificationActionDescriptor.newBuilder()
                            .setActionId(ByteString.copyFrom(filled(16, 11)))
                            .setTitle("Mark handled")
                            .build(),
                    ),
                    nowUnixMs = 1_700_000_000_000,
                ),
            )

            assertEquals(2, frames.size)
            assertFalse(frames.any { it.toString(Charsets.UTF_8).contains("Encrypted test notification") })
            assertFalse(frames.any { it.toString(Charsets.UTF_8).contains("dev.notificationmirroring.android") })
            assertFalse(frames.any { it.toString(Charsets.UTF_8).contains("SevenMirror") })
            assertFalse(frames.any { it.toString(Charsets.UTF_8).contains("Mark handled") })
            assertFalse(frames.any { it.contains(appIcon.encodedBytes.toByteArray()) })
            assertFalse(frames.any { it.contains(avatar.encodedBytes.toByteArray()) })
            val firstPayload = openPayload(frames[0], firstChromeIdentity, androidIdentity)
            val secondPayload = openPayload(frames[1], secondChromeIdentity, androidIdentity)
            assertEquals(9L, firstPayload.first)
            assertEquals(10L, secondPayload.first)
            assertEquals(EncryptedPayload.BodyCase.NOTIFICATION_UPSERT, firstPayload.second.bodyCase)
            assertEquals("dev.notificationmirroring.android", firstPayload.second.notificationUpsert.sourceApplicationId)
            assertEquals("SevenMirror", firstPayload.second.notificationUpsert.sourceApplicationName)
            assertEquals(firstPayload.second, secondPayload.second)
            val upsert = firstPayload.second.notificationUpsert
            assertEquals("Encrypted test notification\n[图片]", upsert.body)
            assertEquals(true, upsert.containsContentImage)
            assertEquals(appIcon, upsert.appIcon)
            assertEquals(avatar, upsert.avatar)
            assertEquals("Mark handled", upsert.getActions(0).title)
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

    private fun media(
        contentSha256Hex: String,
        width: Int,
        height: Int,
        encodedHex: String,
    ): NotificationMedia = NotificationMedia.newBuilder()
        .setContentSha256(ByteString.copyFrom(contentSha256Hex.hexToBytes()))
        .setMimeType(NotificationMediaMimeType.NOTIFICATION_MEDIA_MIME_TYPE_PNG)
        .setWidth(width)
        .setHeight(height)
        .setEncodedBytes(ByteString.copyFrom(encodedHex.hexToBytes()))
        .build()

    private fun String.hexToBytes(): ByteArray =
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.contains(expected: ByteArray): Boolean =
        expected.isNotEmpty() && indices.any { start ->
            start + expected.size <= size && expected.indices.all { this[start + it] == expected[it] }
        }

    private fun filled(size: Int, value: Int) = ByteArray(size) { value.toByte() }
}
