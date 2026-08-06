package dev.notificationmirroring.notification

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class NotificationActionIdTest {
    @Test
    fun roundTripsOpaqueSixteenBytes() {
        val bytes = ByteArray(16) { it.toByte() }
        val id = NotificationActionId.fromBytes(bytes)
        assertArrayEquals(bytes, id.toByteArray())
    }

    @Test
    fun rejectsWrongLengthAndNonCanonicalHex() {
        assertThrows(IllegalArgumentException::class.java) {
            NotificationActionId.fromBytes(ByteArray(15))
        }
        assertThrows(IllegalArgumentException::class.java) {
            NotificationActionId("AA".repeat(16))
        }
    }
}
