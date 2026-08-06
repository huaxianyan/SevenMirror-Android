package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class EncryptedEnvelopeInteropTest {
    private val hpke = JsonVector.load("hpke-auth-p256-aes128gcm.json")
    private val envelope = JsonVector.load("encrypted-envelope-v1.json")

    @Test
    fun opensCanonicalChromeGeneratedEnvelope() {
        val decoded = EncryptedEnvelopeCodecV1.decode(envelope.hex("frameHex"))
        val plaintext = AuthenticatedHpke.open(
            recipient = AuthenticatedHpke.KeyPair(
                publicKey = hpke.hex("recipientPublicKey"),
                privateKey = hpke.hex("recipientPrivateKey"),
            ),
            senderPublicKey = hpke.hex("senderPublicKey"),
            encrypted = AuthenticatedHpke.Ciphertext(
                encapsulatedKey = decoded.encapsulatedKey,
                ciphertext = decoded.ciphertext,
            ),
            aad = decoded.routingHeaderBytes,
        )
        assertArrayEquals(envelope.hex("plaintext"), plaintext)
        val payload = EncryptedPayloadCodecV1.decode(plaintext)
        assertEquals("test.notification/42", payload.actionInvoke.notificationId)
        assertEquals(7L, payload.actionInvoke.notificationRevision)
    }

    private class JsonVector(private val json: String) {
        fun hex(name: String): ByteArray {
            val value = Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
                .find(json)?.groupValues?.get(1)
                ?: error("Missing test vector field: $name")
            return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }

        companion object {
            fun load(resource: String): JsonVector {
                val stream = requireNotNull(
                    EncryptedEnvelopeInteropTest::class.java.classLoader
                        ?.getResourceAsStream(resource),
                )
                return JsonVector(stream.bufferedReader().use { it.readText() })
            }
        }
    }
}
