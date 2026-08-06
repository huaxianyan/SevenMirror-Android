package dev.notificationmirroring.protocol

import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.generated.v1.ActionInvoke
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class EncryptedPayloadV1Test {
    private val vector = Vector.load()

    @Test
    fun matchesCanonicalCrossPlatformVector() {
        val encoded = EncryptedPayloadCodecV1.encode(validPayload())
        assertArrayEquals(vector.encoded, encoded)
        val decoded = EncryptedPayloadCodecV1.decode(encoded)
        assertEquals(7L, decoded.actionInvoke.notificationRevision)
        assertEquals("acknowledged", decoded.actionInvoke.replyText)
    }

    @Test
    fun roundTripsCanonicalActionResult() {
        val encoded = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(1)
                .setActionResult(
                    ActionResult.newBuilder()
                        .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { 0xb2.toByte() }))
                        .setStatus(ActionResultStatus.ACTION_RESULT_STATUS_STALE_NOTIFICATION_VERSION)
                        .setDetail("revision changed"),
                )
                .build(),
        )
        assertArrayEquals(vector.actionResultEncoded, encoded)
        val decoded = EncryptedPayloadCodecV1.decode(encoded)
        assertEquals(
            ActionResultStatus.ACTION_RESULT_STATUS_STALE_NOTIFICATION_VERSION,
            decoded.actionResult.status,
        )
    }

    @Test
    fun rejectsDuplicateUnknownAndInvalidSemanticFields() {
        val valid = vector.encoded
        listOf(
            byteArrayOf(8, 1) + valid,
            valid + byteArrayOf(0x78, 1),
        ).forEach {
            assertThrows(IllegalArgumentException::class.java) {
                EncryptedPayloadCodecV1.decode(it)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            EncryptedPayloadCodecV1.encode(
                validPayload().toBuilder()
                    .setActionInvoke(validPayload().actionInvoke.toBuilder().setNotificationRevision(0))
                    .build(),
            )
        }
    }

    private fun validPayload(): EncryptedPayload = EncryptedPayload.newBuilder()
        .setSchemaVersion(1)
        .setActionInvoke(
            ActionInvoke.newBuilder()
                .setNotificationId("test.notification/42")
                .setNotificationRevision(7)
                .setActionId(ByteString.copyFrom(ByteArray(16) { 0xa1.toByte() }))
                .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { 0xb2.toByte() }))
                .setReplyText("acknowledged"),
        )
        .build()

    private class Vector(private val json: String) {
        val encoded: ByteArray get() = hex("encodedHex")
        val actionResultEncoded: ByteArray get() = hex("actionResultEncodedHex")

        private fun hex(name: String): ByteArray {
            val value = Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
                .find(json)?.groupValues?.get(1)
                ?: error("Missing $name")
            return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }

        companion object {
            fun load(): Vector {
                val stream = requireNotNull(
                    EncryptedPayloadV1Test::class.java.classLoader
                        ?.getResourceAsStream("encrypted-payload-v1.json"),
                )
                return Vector(stream.bufferedReader().use { it.readText() })
            }
        }
    }
}
