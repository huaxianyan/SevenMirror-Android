package dev.notificationmirroring.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RoutingHeaderV1Test {
    private val vector = Vector.load()

    @Test
    fun matchesCanonicalCrossPlatformVector() {
        val header = vector.header()
        val encoded = RoutingHeaderCodecV1.encode(header)

        assertEquals(160, encoded.size)
        assertArrayEquals(vector.hex("headerHex"), encoded)
        val decoded = RoutingHeaderCodecV1.decode(encoded)
        assertHeaderEquals(header, decoded)
    }

    @Test
    fun rejectsMalformedAndSemanticallyInvalidHeaders() {
        val valid = vector.hex("headerHex")
        val invalid = listOf(
            valid.copyOf(valid.size - 1),
            valid.copyOf().apply { this[0] = (this[0].toInt() xor 0xff).toByte() },
            valid.copyOf().apply { this[5] = 2 },
            valid.copyOf().apply { this[7] = 1 },
            valid.copyOf().apply { fill(0, 8, 24) },
            valid.copyOf().apply { fill(0, 136, 144) },
            valid.copyOf().apply { copyInto(this, 152, 144, 152) },
        )

        invalid.forEach { encoded ->
            assertThrows(IllegalArgumentException::class.java) {
                RoutingHeaderCodecV1.decode(encoded)
            }
        }
    }

    private fun assertHeaderEquals(expected: RoutingHeaderV1, actual: RoutingHeaderV1) {
        assertArrayEquals(expected.workspaceId, actual.workspaceId)
        assertArrayEquals(expected.senderDeviceId, actual.senderDeviceId)
        assertArrayEquals(expected.recipientDeviceId, actual.recipientDeviceId)
        assertArrayEquals(expected.senderKeyId, actual.senderKeyId)
        assertArrayEquals(expected.recipientKeyId, actual.recipientKeyId)
        assertArrayEquals(expected.messageId, actual.messageId)
        assertEquals(expected.sequence, actual.sequence)
        assertEquals(expected.createdAtUnixMs, actual.createdAtUnixMs)
        assertEquals(expected.expiresAtUnixMs, actual.expiresAtUnixMs)
    }

    private class Vector(private val json: String) {
        fun header(): RoutingHeaderV1 = RoutingHeaderV1(
            workspaceId = hex("workspaceId"),
            senderDeviceId = hex("senderDeviceId"),
            recipientDeviceId = hex("recipientDeviceId"),
            senderKeyId = hex("senderKeyId"),
            recipientKeyId = hex("recipientKeyId"),
            messageId = hex("messageId"),
            sequence = string("sequence").toLong(),
            createdAtUnixMs = number("createdAtUnixMs"),
            expiresAtUnixMs = number("expiresAtUnixMs"),
        )

        fun hex(name: String): ByteArray = string(name)
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

        private fun string(name: String): String =
            Regex("\\\"$name\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"")
                .find(json)?.groupValues?.get(1)
                ?: error("Missing test vector field: $name")

        private fun number(name: String): Long =
            Regex("\\\"$name\\\"\\s*:\\s*([0-9]+)")
                .find(json)?.groupValues?.get(1)?.toLong()
                ?: error("Missing test vector field: $name")

        companion object {
            fun load(): Vector {
                val stream = requireNotNull(
                    RoutingHeaderV1Test::class.java.classLoader
                        ?.getResourceAsStream("routing-header-v1.json"),
                )
                return Vector(stream.bufferedReader().use { it.readText() })
            }
        }
    }
}
