package com.neko7ina.sevenmirror.crypto

import com.neko7ina.sevenmirror.protocol.EncryptedEnvelopeCodecV1
import com.neko7ina.sevenmirror.protocol.EncryptedPayloadCodecV1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.security.MessageDigest

class NotificationEnvelopeSenderTest {
    @Test
    fun `missing text uses only the app name while existing text stays unchanged`() {
        val phone = AuthenticatedHpke.deriveKeyPair(ByteArray(32) { (it + 1).toByte() })
        val browser = AuthenticatedHpke.deriveKeyPair(ByteArray(32) { (it + 65).toByte() })
        val sender = NotificationEnvelopeSender(
            workspaceId = ByteArray(16) { 1 },
            senderDeviceId = ByteArray(16) { 2 },
            senderIdentity = phone,
            recipients = WorkspaceNotificationRecipientDirectory { _, _, _ ->
                listOf(WorkspaceNotificationRecipient(
                    displayName = "Browser",
                    deviceId = ByteArray(16) { 3 },
                    identityKeyId = MessageDigest.getInstance("SHA-256").digest(browser.publicKey),
                    identityPublicKey = browser.publicKey.copyOf(),
                ))
            },
            allocateSequence = { 1L },
        )
        try {
            listOf(
                Triple(null, null, "Messages"),
                Triple("Original title", null, "Original title"),
                Triple(null, "Original body", null),
                Triple("Original title", "Original body", "Original title"),
            ).forEach { (title, body, expectedTitle) ->
                val frame = requireNotNull(sender.createUpsert(
                    notificationId = "synthetic.notification/42",
                    revision = 7,
                    sourceApplicationId = "com.example.messages",
                    sourceApplicationName = "Messages",
                    title = title,
                    body = body,
                    appIcon = null,
                    avatar = null,
                    containsContentImage = false,
                    actions = emptyList(),
                    nowUnixMs = 1_700_000_000_000,
                )).single()
                val envelope = EncryptedEnvelopeCodecV1.decode(frame)
                val opened = AuthenticatedHpke.open(
                    recipient = browser,
                    senderPublicKey = phone.publicKey,
                    encrypted = AuthenticatedHpke.Ciphertext(envelope.encapsulatedKey, envelope.ciphertext),
                    aad = envelope.routingHeaderBytes,
                )
                val notification = EncryptedPayloadCodecV1.decode(opened).notificationUpsert
                assertEquals(expectedTitle != null, notification.hasTitle())
                assertEquals(expectedTitle.orEmpty(), notification.title)
                assertEquals(body != null, notification.hasBody())
                assertEquals(body.orEmpty(), notification.body)
                assertFalse(notification.hasAvatar())
                assertEquals(0, notification.actionsCount)
            }
        } finally {
            sender.clearIdentity()
            phone.privateKey.fill(0)
            browser.privateKey.fill(0)
        }
    }
}
