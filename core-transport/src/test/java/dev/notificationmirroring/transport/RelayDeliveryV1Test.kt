package dev.notificationmirroring.transport

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RelayDeliveryV1Test {
    private val vector = JsonVector.load("relay-delivery-v1.json")

    @Test
    fun matchesCanonicalGoVector() {
        val durableSubmission = vector.hex("durableSubmissionHex")
        val envelope = durableSubmission.copyOfRange(4, durableSubmission.size)
        assertEquals(
            vector.text("durableSubmissionHex"),
            RelayDeliveryCodecV1.encodeDurableSubmission(envelope).toHex(),
        )
        assertEquals(
            vector.text("resumeZeroHex"),
            RelayDeliveryCodecV1.encodeResume(0).toHex(),
        )
        assertEquals(
            vector.text("acknowledgementHex"),
            RelayDeliveryCodecV1.encodeAcknowledgement(7).toHex(),
        )

        val delivery = RelayDeliveryCodecV1.decodeServerMessage(vector.hex("deliveryHex"))
            as RelayServerMessageV1.Delivery
        assertEquals(7, delivery.deliveryId)
        assertArrayEquals(envelope, delivery.envelope)
        assertEquals(
            RelayServerMessageV1.CaughtUp(7),
            RelayDeliveryCodecV1.decodeServerMessage(vector.hex("caughtUpHex")),
        )
        assertEquals(
            RelayServerMessageV1.SnapshotRequired(9),
            RelayDeliveryCodecV1.decodeServerMessage(vector.hex("resetRequiredHex")),
        )
    }

    @Test
    fun rejectsZeroDeliveriesAndMalformedEnvelopes() {
        assertThrows(IllegalArgumentException::class.java) {
            RelayDeliveryCodecV1.encodeAcknowledgement(0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RelayDeliveryCodecV1.decodeServerMessage("SND1".toByteArray())
        }
        assertThrows(IllegalArgumentException::class.java) {
            RelayDeliveryCodecV1.encodeDurableSubmission(ByteArray(249))
        }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private class JsonVector(private val json: String) {
        fun text(name: String): String = Regex("\\\"$name\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"")
            .find(json)?.groupValues?.get(1) ?: error("Missing field $name")

        fun hex(name: String): ByteArray = text(name).chunked(2)
            .map { it.toInt(16).toByte() }.toByteArray()

        companion object {
            fun load(resource: String): JsonVector {
                val stream = requireNotNull(
                    RelayDeliveryV1Test::class.java.classLoader?.getResourceAsStream(resource),
                )
                return JsonVector(stream.bufferedReader().use { it.readText() })
            }
        }
    }
}
