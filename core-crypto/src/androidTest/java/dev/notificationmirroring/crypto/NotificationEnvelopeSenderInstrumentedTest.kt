package dev.notificationmirroring.crypto

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NotificationEnvelopeSenderInstrumentedTest {
    @Test
    fun appNotificationAndReconnectSnapshotAreEncryptedForTheSingleApprovedChrome() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = AndroidTrustedPeerStore(context, "notification-${UUID.randomUUID()}")
        val workspaceId = filled(16, 1)
        val androidDeviceId = filled(16, 2)
        val chromeDeviceId = filled(16, 3)
        val androidIdentity = AuthenticatedHpke.deriveKeyPair(filled(32, 4))
        val chromeIdentity = AuthenticatedHpke.deriveKeyPair(filled(32, 5))
        try {
            store.pinApproved(workspaceId, chromeDeviceId, chromeIdentity.publicKey)
            val sequence = AtomicLong(8)
            val sender = NotificationEnvelopeSender(
                workspaceId = workspaceId,
                senderDeviceId = androidDeviceId,
                senderIdentity = androidIdentity,
                trustedPeers = store,
                allocateSequence = { sequence.incrementAndGet() },
            )
            val frame = requireNotNull(
                sender.createUpsert(
                    notificationId = "synthetic.notification/42",
                    revision = 7,
                    title = "Synthetic notification",
                    body = "Encrypted test notification",
                    nowUnixMs = 1_700_000_000_000,
                ),
            )

            assertFalse(frame.toString(Charsets.UTF_8).contains("Encrypted test notification"))
            val payload = openPayload(frame, chromeIdentity, androidIdentity)
            assertEquals(9L, payload.first)
            assertEquals(EncryptedPayload.BodyCase.NOTIFICATION_UPSERT, payload.second.bodyCase)
            assertEquals("Encrypted test notification", payload.second.notificationUpsert.body)

            val snapshotFrame = requireNotNull(
                sender.createSnapshotManifest(
                    highWaterRevision = 9,
                    activeNotifications = mapOf(
                        "synthetic.notification/99" to 9L,
                        "synthetic.notification/42" to 7L,
                    ),
                    nowUnixMs = 1_700_000_000_000,
                ),
            )
            val snapshot = openPayload(snapshotFrame, chromeIdentity, androidIdentity)
            assertEquals(10L, snapshot.first)
            assertEquals(
                listOf("synthetic.notification/42", "synthetic.notification/99"),
                snapshot.second.notificationSnapshotManifest.activeNotificationsList
                    .map { it.notificationId },
            )
            assertEquals(9L, snapshot.second.notificationSnapshotManifest.highWaterRevision)
        } finally {
            store.clear()
            store.close()
        }
    }

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
