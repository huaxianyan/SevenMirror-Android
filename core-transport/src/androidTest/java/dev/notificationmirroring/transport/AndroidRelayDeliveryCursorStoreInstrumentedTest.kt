package dev.notificationmirroring.transport

import androidx.test.core.app.ApplicationProvider
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AndroidRelayDeliveryCursorStoreInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val workspaceId = ByteArray(16) { (it + 1).toByte() }
    private val deviceId = ByteArray(16) { (it + 17).toByte() }

    @Test
    fun survivesReconstructionAndRequiresContiguousCommit() {
        val stateName = "test-${UUID.randomUUID()}"
        val first = AndroidRelayDeliveryCursorStore(context, stateName)
        try {
            assertEquals(RelayDeliveryCursorState(0), first.load(workspaceId, deviceId))
            assertEquals(
                RelayDeliveryCursorState(1),
                first.commitDelivery(workspaceId, deviceId, 1),
            )

            val reconstructed = AndroidRelayDeliveryCursorStore(context, stateName)
            assertEquals(RelayDeliveryCursorState(1), reconstructed.load(workspaceId, deviceId))
            assertThrows(IllegalStateException::class.java) {
                reconstructed.commitDelivery(workspaceId, deviceId, 3)
            }
            assertEquals(
                RelayDeliveryCursorState(1, 4),
                reconstructed.requireSnapshot(workspaceId, deviceId, 4),
            )
            assertThrows(IllegalStateException::class.java) {
                reconstructed.commitDelivery(workspaceId, deviceId, 2)
            }
        } finally {
            first.clearForTests()
        }
    }

    @Test
    fun isolatesWorkspaceAndDeviceTuples() {
        val store = AndroidRelayDeliveryCursorStore(context, "test-${UUID.randomUUID()}")
        try {
            store.commitDelivery(workspaceId, deviceId, 1)
            assertEquals(
                RelayDeliveryCursorState(0),
                store.load(workspaceId, deviceId.copyOf().also { it[15]++ }),
            )
        } finally {
            store.clearForTests()
        }
    }
}
