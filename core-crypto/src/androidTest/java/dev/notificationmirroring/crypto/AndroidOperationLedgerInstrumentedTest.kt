package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidOperationLedgerInstrumentedTest {
    @Test
    fun persistsPendingAndCompletedResultsAndFailsClosedAtCapacity() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val name = "operation-${System.nanoTime()}"
        var ledger = AndroidOperationLedger(context, name, maxEntries = 2)
        val sender = ByteArray(32) { 1 }
        val firstKey = ByteArray(16) { 2 }
        val now = 1_800_000_000_000L
        try {
            assertEquals(
                AndroidOperationLedger.BeginResult.Accepted,
                ledger.beginOrRecover(sender, firstKey, now),
            )
            ledger.close()
            ledger = AndroidOperationLedger(context, name, maxEntries = 2)
            assertEquals(
                AndroidOperationLedger.BeginResult.DuplicatePending,
                ledger.beginOrRecover(sender, firstKey, now),
            )
            val storedResult = byteArrayOf(8, 1, 90, 0)
            ledger.complete(sender, firstKey, storedResult)
            val recovered = ledger.beginOrRecover(sender, firstKey, now)
            assertTrue(recovered is AndroidOperationLedger.BeginResult.DuplicateCompleted)
            assertArrayEquals(
                storedResult,
                (recovered as AndroidOperationLedger.BeginResult.DuplicateCompleted).resultPayload,
            )
            assertEquals(
                AndroidOperationLedger.BeginResult.Accepted,
                ledger.beginOrRecover(sender, ByteArray(16) { 3 }, now),
            )
            assertEquals(
                AndroidOperationLedger.BeginResult.CapacityExceeded,
                ledger.beginOrRecover(sender, ByteArray(16) { 4 }, now),
            )
        } finally {
            ledger.clear()
        }
    }
}
