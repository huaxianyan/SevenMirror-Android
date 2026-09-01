package dev.notificationmirroring.crypto

import org.bouncycastle.crypto.InvalidCipherTextException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AuthenticatedHpkeTest {
    private val vector = Vector.load()

    @Test
    fun opensCanonicalChromeGeneratedAuthenticatedVector() {
        val recipient = AuthenticatedHpke.KeyPair(
            publicKey = vector.hex("recipientPublicKey"),
            privateKey = vector.hex("recipientPrivateKey"),
        )
        val opened = AuthenticatedHpke.open(
            recipient = recipient,
            senderPublicKey = vector.hex("senderPublicKey"),
            encrypted = AuthenticatedHpke.Ciphertext(
                encapsulatedKey = vector.hex("encapsulatedKey"),
                ciphertext = vector.hex("ciphertext"),
            ),
            aad = vector.hex("aad"),
        )

        assertArrayEquals(vector.hex("plaintext"), opened)
    }

    @Test
    fun derivesTheSameRfcKeyMaterialAsChrome() {
        val sender = AuthenticatedHpke.deriveKeyPair(vector.hex("senderIkm"))
        val recipient = AuthenticatedHpke.deriveKeyPair(vector.hex("recipientIkm"))

        assertArrayEquals(vector.hex("senderPublicKey"), sender.publicKey)
        assertArrayEquals(vector.hex("senderPrivateKey"), sender.privateKey)
        assertArrayEquals(vector.hex("recipientPublicKey"), recipient.publicKey)
        assertArrayEquals(vector.hex("recipientPrivateKey"), recipient.privateKey)
    }

    @Test
    fun roundTripsAndRejectsSubstitutedSender() {
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val attacker = AuthenticatedHpke.generateKeyPair()
        val plaintext = "Android authenticated payload".encodeToByteArray()
        val aad = "workspace|sender|recipient|message|1".encodeToByteArray()
        val encrypted = AuthenticatedHpke.seal(
            recipient.publicKey,
            sender,
            plaintext,
            aad,
        )

        assertArrayEquals(
            plaintext,
            AuthenticatedHpke.open(recipient, sender.publicKey, encrypted, aad),
        )
        assertThrows(InvalidCipherTextException::class.java) {
            AuthenticatedHpke.open(recipient, attacker.publicKey, encrypted, aad)
        }

    }

    private class Vector(private val json: String) {
        fun hex(name: String): ByteArray {
            val value = Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
                .find(json)
                ?.groupValues
                ?.get(1)
                ?: error("Missing test vector field: $name")
            require(value.length % 2 == 0)
            return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }

        companion object {
            fun load(): Vector {
                val stream = requireNotNull(
                    AuthenticatedHpkeTest::class.java.classLoader
                        ?.getResourceAsStream("hpke-auth-p256-aes128gcm.json"),
                )
                return Vector(stream.bufferedReader().use { it.readText() })
            }
        }
    }
}
