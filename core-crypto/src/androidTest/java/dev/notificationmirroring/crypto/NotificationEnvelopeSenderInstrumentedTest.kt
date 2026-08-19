package dev.notificationmirroring.crypto

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NotificationEnvelopeSenderInstrumentedTest {
    @Test
    fun appNotificationTextIsEncryptedForTheSingleApprovedChrome() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = AndroidTrustedPeerStore(context, "notification-${UUID.randomUUID()}")
        val workspaceId = filled(16, 1)
        val androidDeviceId = filled(16, 2)
        val chromeDeviceId = filled(16, 3)
        val androidIdentity = AuthenticatedHpke.deriveKeyPair(filled(32, 4))
        val chromeIdentity = AuthenticatedHpke.deriveKeyPair(filled(32, 5))
        try {
            store.pinApproved(workspaceId, chromeDeviceId, chromeIdentity.publicKey)
            val sender = NotificationEnvelopeSender(
                workspaceId = workspaceId,
                senderDeviceId = androidDeviceId,
                senderIdentity = androidIdentity,
                trustedPeers = store,
                allocateSequence = { 9L },
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
            val envelope = EncryptedEnvelopeCodecV1.decode(frame)
            val route = RoutingHeaderCodecV1.decode(envelope.routingHeaderBytes)
            assertEquals(9L, route.sequence)
            val opened = AuthenticatedHpke.open(
                recipient = chromeIdentity,
                senderPublicKey = androidIdentity.publicKey,
                encrypted = AuthenticatedHpke.Ciphertext(
                    envelope.encapsulatedKey,
                    envelope.ciphertext,
                ),
                aad = envelope.routingHeaderBytes,
            )
            val payload = EncryptedPayloadCodecV1.decode(opened)
            assertEquals(EncryptedPayload.BodyCase.NOTIFICATION_UPSERT, payload.bodyCase)
            assertEquals("Encrypted test notification", payload.notificationUpsert.body)
        } finally {
            store.clear()
            store.close()
        }
    }

    private fun filled(size: Int, value: Int) = ByteArray(size) { value.toByte() }
}
