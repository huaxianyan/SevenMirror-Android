package dev.notificationmirroring.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TrustedDevicePairingV1Test {
    private val vector = Vector.load()

    @Test
    fun matchesCanonicalOfferApprovalQrAndSafetyCode() {
        val offer = vector.hexValues("encoded")[0]
        val approval = vector.hexValues("encoded")[1]
        assertArrayEquals(offer, TrustedDevicePairingCodecV1.encodeOffer(
            TrustedDevicePairingCodecV1.decodeOffer(offer),
        ))
        assertArrayEquals(approval, TrustedDevicePairingCodecV1.encodeApproval(
            TrustedDevicePairingCodecV1.decodeApproval(approval),
        ))
        assertEquals(vector.stringValues("qr")[0], TrustedDevicePairingCodecV1.encodeQr(offer))
        assertEquals(vector.stringValues("qr")[1], TrustedDevicePairingCodecV1.encodeQr(approval))
        assertArrayEquals(offer, TrustedDevicePairingCodecV1.decodeQr(vector.stringValues("qr")[0]))
        assertEquals(vector.stringValues("safetyCode").single(),
            TrustedDevicePairingCodecV1.safetyCode(offer, approval))
    }

    @Test
    fun rejectsMutationWrongBindingInvalidPointAndNonCanonicalQr() {
        val offer = vector.hexValues("encoded")[0]
        val approval = vector.hexValues("encoded")[1]
        assertThrows(IllegalArgumentException::class.java) {
            TrustedDevicePairingCodecV1.validatePair(offer.copyOf().apply { this[10] = (this[10].toInt() xor 1).toByte() }, approval)
        }
        assertThrows(IllegalArgumentException::class.java) {
            TrustedDevicePairingCodecV1.validatePair(offer, approval.copyOf().apply { this[4] = (this[4].toInt() xor 1).toByte() })
        }
        assertThrows(IllegalArgumentException::class.java) {
            TrustedDevicePairingCodecV1.decodeOffer(offer.copyOf().apply {
                fill(0, 36, 101)
                this[36] = 4
            })
        }
        assertThrows(IllegalArgumentException::class.java) {
            TrustedDevicePairingCodecV1.decodeQr(vector.stringValues("qr")[0] + "=")
        }
        assertThrows(IllegalArgumentException::class.java) {
            TrustedDevicePairingCodecV1.decodeQr(" ${vector.stringValues("qr")[0]}")
        }
    }

    @Test
    fun checksActiveWindowWithoutExtendingExpiry() {
        val offer = TrustedDevicePairingCodecV1.decodeOffer(vector.hexValues("encoded")[0])
        TrustedDevicePairingCodecV1.validateActive(
            offer.createdAtUnixMs,
            offer.expiresAtUnixMs,
            offer.createdAtUnixMs,
        )
        assertThrows(IllegalArgumentException::class.java) {
            TrustedDevicePairingCodecV1.validateActive(
                offer.createdAtUnixMs,
                offer.expiresAtUnixMs,
                offer.expiresAtUnixMs,
            )
        }
    }

    private class Vector(private val json: String) {
        fun stringValues(name: String): List<String> =
            Regex("\\\"$name\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"")
                .findAll(json).map { it.groupValues[1] }.toList()

        fun hexValues(name: String): List<ByteArray> = stringValues(name).map { value ->
            value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }

        companion object {
            fun load(): Vector {
                val stream = requireNotNull(
                    TrustedDevicePairingV1Test::class.java.classLoader
                        ?.getResourceAsStream("trusted-device-pairing-v1.json"),
                )
                return Vector(stream.bufferedReader().use { it.readText() })
            }
        }
    }
}
