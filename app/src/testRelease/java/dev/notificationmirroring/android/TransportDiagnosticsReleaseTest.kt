package dev.notificationmirroring.android

import dev.notificationmirroring.transport.TransportDiagnosticEvent
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportDiagnosticsReleaseTest {
    @Test
    fun releaseDefaultDoesNotPublishDiagnosticEvents() {
        assertFalse(BuildConfig.DEBUG)
        val output = mutableListOf<String>()
        val diagnostics = TransportDiagnostics(
            state = { AndroidTransportState.ONLINE },
            clock = { 1234L },
            write = output::add,
        )
        diagnostics.record(TransportDiagnosticEvent.AUTHENTICATED, 7L)
        assertTrue(diagnostics.measure(CoordinatorDiagnosticEvent.STARTUP_SNAPSHOT, 7L) { true })
        assertTrue(output.isEmpty())
    }
}
