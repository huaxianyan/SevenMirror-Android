package dev.notificationmirroring.transport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class BoundedReconnectBackoffTest {
    @Test
    fun growsExponentiallyStopsAtMaximumAndResets() {
        val backoff = BoundedReconnectBackoff(
            initialDelayMs = 1_000,
            maximumDelayMs = 5_000,
            multiplier = 2.0,
            jitterRatio = 0.0,
            random = { 0.5 },
        )

        assertEquals(listOf(1_000L, 2_000L, 4_000L, 5_000L, 5_000L),
            List(5) { backoff.nextDelayMs() })
        backoff.reset()
        assertEquals(1_000L, backoff.nextDelayMs())
    }

    @Test
    fun jitterRemainsWithinZeroAndConfiguredMaximum() {
        val low = BoundedReconnectBackoff(
            initialDelayMs = 1_000,
            maximumDelayMs = 1_000,
            jitterRatio = 0.2,
            random = { 0.0 },
        )
        val high = BoundedReconnectBackoff(
            initialDelayMs = 1_000,
            maximumDelayMs = 1_000,
            jitterRatio = 0.2,
            random = { 1.0 },
        )

        assertEquals(800L, low.nextDelayMs())
        assertEquals(1_000L, high.nextDelayMs())
    }

    @Test
    fun rejectsInvalidPolicyAndRandomSource() {
        assertThrows(IllegalArgumentException::class.java) {
            BoundedReconnectBackoff(initialDelayMs = 0)
        }
        val invalidRandom = BoundedReconnectBackoff(random = { 2.0 })
        assertThrows(IllegalArgumentException::class.java) {
            invalidRandom.nextDelayMs()
        }
    }
}
