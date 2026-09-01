package dev.notificationmirroring.transport

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceAuthFrameV1Test {
    private val vector = JsonVector.load("device-auth-frame-v1.json")

    @Test
    fun matchesCanonicalGoVector() {
        val credential = DeviceTransportCredential(
            vector.hex("workspaceId"),
            vector.hex("deviceId"),
            vector.hex("authToken"),
        )
        val encoded = DeviceAuthFrameCodecV1.encode(credential)
        assertEquals(vector.text("frameHex"), encoded.toHex())
        val decoded = DeviceAuthFrameCodecV1.decode(encoded)
        assertArrayEquals(credential.workspaceId, decoded.workspaceId)
        assertArrayEquals(credential.deviceId, decoded.deviceId)
        assertArrayEquals(credential.authToken, decoded.authToken)
        assertArrayEquals(vector.hex("successAckHex"), TransportAuthenticationSuccessV1.encode())
        TransportAuthenticationSuccessV1.requireCanonical(vector.hex("successAckHex"))
    }

    @Test
    fun normalizesSecureOriginsAndOnlyPermitsLoopbackHttp() {
        assertEquals(
            "https://notify.example",
            AndroidTransportCredentialStore.normalizeServerOrigin("https://notify.example/"),
        )
        assertEquals(
            "http://127.0.0.1:8080",
            AndroidTransportCredentialStore.normalizeServerOrigin("http://127.0.0.1:8080"),
        )
        assertThrows(IllegalArgumentException::class.java) {
            AndroidTransportCredentialStore.normalizeServerOrigin("http://notify.example")
        }
        assertThrows(IllegalArgumentException::class.java) {
            AndroidTransportCredentialStore.normalizeServerOrigin("https://notify.example/path")
        }
    }

    @Test
    fun rejectsMalformedFramesAndIdentifiers() {
        assertThrows(IllegalArgumentException::class.java) {
            DeviceAuthFrameCodecV1.decode(ByteArray(67))
        }
        val badMagic = vector.hex("frameHex").also { it[0] = 0 }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceAuthFrameCodecV1.decode(badMagic)
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceAuthFrameCodecV1.encode(
                DeviceTransportCredential(ByteArray(16), vector.hex("deviceId"), vector.hex("authToken")),
            )
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
                    DeviceAuthFrameV1Test::class.java.classLoader?.getResourceAsStream(resource),
                )
                return JsonVector(stream.bufferedReader().use { it.readText() })
            }
        }
    }
}
