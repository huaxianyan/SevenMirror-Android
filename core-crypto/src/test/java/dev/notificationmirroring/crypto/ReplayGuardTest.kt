package dev.notificationmirroring.crypto

import org.junit.Assert.assertEquals
import org.junit.Test

class ReplayGuardTest {
    private val now = 1_800_000_000_000

    @Test
    fun acceptsOnceAndRejectsDuplicateTuple() {
        val guard = ReplayGuard()
        val token = ReplayGuard.Token("sender-key-1", "message-1", now + 60_000)

        assertEquals(ReplayGuard.Decision.ACCEPTED, guard.checkAndRecord(token, now))
        assertEquals(ReplayGuard.Decision.DUPLICATE, guard.checkAndRecord(token, now))
        assertEquals(
            ReplayGuard.Decision.ACCEPTED,
            guard.checkAndRecord(token.copy(senderKeyId = "sender-key-2"), now),
        )
    }

    @Test
    fun rejectsExpiredAndBoundsState() {
        val guard = ReplayGuard(maxEntries = 1)
        assertEquals(
            ReplayGuard.Decision.EXPIRED,
            guard.checkAndRecord(ReplayGuard.Token("sender", "expired", now), now),
        )
        assertEquals(
            ReplayGuard.Decision.ACCEPTED,
            guard.checkAndRecord(ReplayGuard.Token("sender", "one", now + 10), now),
        )
        assertEquals(
            ReplayGuard.Decision.ACCEPTED,
            guard.checkAndRecord(ReplayGuard.Token("sender", "two", now + 20), now),
        )
    }
}
