package dev.notificationmirroring.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class EncryptedEnvelopeV1Test {
    private val vector = Vector.load()

    @Test
    fun matchesCanonicalCrossPlatformFrame() {
        val encoded = EncryptedEnvelopeCodecV1.encode(
            EncryptedEnvelopePartsV1(
                routingHeader = vector.hex("routingHeader"),
                encapsulatedKey = vector.hex("encapsulatedKey"),
                ciphertext = vector.hex("ciphertext"),
            ),
        )
        assertArrayEquals(vector.hex("frameHex"), encoded)

        val decoded = EncryptedEnvelopeCodecV1.decode(encoded)
        assertArrayEquals(vector.hex("routingHeader"), decoded.routingHeaderBytes)
        assertArrayEquals(vector.hex("encapsulatedKey"), decoded.encapsulatedKey)
        assertArrayEquals(vector.hex("ciphertext"), decoded.ciphertext)
        assertEquals(42L, decoded.routingHeader.sequence)
    }

    @Test
    fun rejectsTruncationTrailingBytesBadMagicAndInvalidPoint() {
        val valid = vector.hex("frameHex")
        val invalid = listOf(
            valid.copyOf(valid.size - 1),
            valid + byteArrayOf(0),
            valid.copyOf().apply { this[0] = 0 },
            valid.copyOf().apply { this[164] = 3 },
        )
        invalid.forEach { frame ->
            assertThrows(IllegalArgumentException::class.java) {
                EncryptedEnvelopeCodecV1.decode(frame)
            }
        }
    }

    private class Vector(private val json: String) {
        fun hex(name: String): ByteArray {
            val value = Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
                .find(json)?.groupValues?.get(1)
                ?: error("Missing test vector field: $name")
            return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }

        companion object {
            fun load(): Vector {
                val stream = requireNotNull(
                    EncryptedEnvelopeV1Test::class.java.classLoader
                        ?.getResourceAsStream("encrypted-envelope-v1.json"),
                )
                return Vector(stream.bufferedReader().use { it.readText() })
            }
        }
    }
}
