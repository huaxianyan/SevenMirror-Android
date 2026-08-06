package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidOperationLedgerInstrumentedTest {
    @Test
    fun persistsDuplicatesAndFailsClosedAtCapacity() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val name = "operation-${System.nanoTime()}"
        var ledger = AndroidOperationLedger(context, name, maxEntries = 2)
        val sender = ByteArray(32) { 1 }
        val now = 1_800_000_000_000L
        try {
            assertEquals(
                AndroidOperationLedger.Decision.ACCEPTED,
                ledger.checkAndRecord(sender, ByteArray(16) { 2 }, now),
            )
            ledger.close()
            ledger = AndroidOperationLedger(context, name, maxEntries = 2)
            assertEquals(
                AndroidOperationLedger.Decision.DUPLICATE,
                ledger.checkAndRecord(sender, ByteArray(16) { 2 }, now),
            )
            assertEquals(
                AndroidOperationLedger.Decision.ACCEPTED,
                ledger.checkAndRecord(sender, ByteArray(16) { 3 }, now),
            )
            assertEquals(
                AndroidOperationLedger.Decision.CAPACITY_EXCEEDED,
                ledger.checkAndRecord(sender, ByteArray(16) { 4 }, now),
            )
        } finally {
            ledger.clear()
        }
    }
}
