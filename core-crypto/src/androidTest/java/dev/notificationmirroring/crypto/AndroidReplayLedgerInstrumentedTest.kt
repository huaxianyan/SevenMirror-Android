package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidReplayLedgerInstrumentedTest {
    private val now = 1_800_000_000_000L

    @Test
    fun duplicateRemainsRejectedAfterLedgerRecreation() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val ledgerName = "instrumented-${System.nanoTime()}"
        val senderKeyId = ByteArray(32) { it.toByte() }
        val messageId = ByteArray(16) { (it + 32).toByte() }
        val first = AndroidReplayLedger(context, ledgerName)

        try {
            assertEquals(
                AndroidReplayLedger.Decision.ACCEPTED,
                first.checkAndRecord(senderKeyId, messageId, now + 60_000, now),
            )
            first.close()

            val restored = AndroidReplayLedger(context, ledgerName)
            assertEquals(
                AndroidReplayLedger.Decision.DUPLICATE,
                restored.checkAndRecord(senderKeyId, messageId, now + 60_000, now),
            )
            restored.close()
        } finally {
            first.clear()
        }
    }

    @Test
    fun rejectsExpiredAndFailsClosedAtCapacity() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val ledgerName = "instrumented-${System.nanoTime()}"
        val ledger = AndroidReplayLedger(context, ledgerName, maxEntries = 1)
        val senderKeyId = ByteArray(32) { 1 }

        try {
            assertEquals(
                AndroidReplayLedger.Decision.EXPIRED,
                ledger.checkAndRecord(senderKeyId, ByteArray(16) { 1 }, now, now),
            )
            assertEquals(
                AndroidReplayLedger.Decision.ACCEPTED,
                ledger.checkAndRecord(senderKeyId, ByteArray(16) { 2 }, now + 60_000, now),
            )
            assertEquals(
                AndroidReplayLedger.Decision.CAPACITY_EXCEEDED,
                ledger.checkAndRecord(senderKeyId, ByteArray(16) { 3 }, now + 60_000, now),
            )
            assertEquals(
                AndroidReplayLedger.Decision.ACCEPTED,
                ledger.checkAndRecord(senderKeyId, ByteArray(16) { 3 }, now + 120_000, now + 60_000),
            )
        } finally {
            ledger.clear()
        }
    }
}
