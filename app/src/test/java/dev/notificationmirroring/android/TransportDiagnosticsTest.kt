package dev.notificationmirroring.android

import dev.notificationmirroring.transport.TransportDiagnosticEvent
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportDiagnosticsTest {
    @Test
    fun recordsOnlyTypedDiagnosticMetadata() {
        val output = mutableListOf<String>()
        val diagnostics = TransportDiagnostics(
            state = { AndroidTransportState.OFFLINE },
            enabled = true,
            clock = { 1234L },
            write = output::add,
        )
        diagnostics.record(
            CoordinatorDiagnosticEvent.NETWORK_CAPABILITIES_CHANGED,
            generation = 7L,
            networkHandle = 42L,
            wifi = true,
            cellular = false,
            vpn = true,
            validated = true,
        )
        val fields = output.single().split(' ').associate {
            it.substringBefore('=') to it.substringAfter('=')
        }
        assertEquals(mapOf(
            "t_ms" to "1234", "gen" to "7",
            "event" to "NETWORK_CAPABILITIES_CHANGED", "state" to "OFFLINE",
            "network" to "42", "wifi" to "true", "cellular" to "false",
            "vpn" to "true", "validated" to "true",
        ), fields)
    }

    @Test
    fun disabledDiagnosticsPreserveOperationResultWithoutPublishingLogs() {
        val output = mutableListOf<String>()
        val diagnostics = TransportDiagnostics(
            state = { AndroidTransportState.ONLINE },
            enabled = false,
            clock = { 1234L },
            write = output::add,
        )
        diagnostics.record(TransportDiagnosticEvent.AUTHENTICATED, 7L)
        val result = diagnostics.measure(CoordinatorDiagnosticEvent.STARTUP_SNAPSHOT, 7L) { false }
        assertFalse(result)
        assertTrue(output.isEmpty())
    }

    @Test
    fun failedOperationPropagatesOriginalFailureWithoutLoggingItsMessage() {
        val output = mutableListOf<String>()
        val diagnostics = TransportDiagnostics(
            state = { AndroidTransportState.CONNECTING },
            enabled = true,
            clock = { 1234L },
            write = output::add,
        )
        // Exception messages are forbidden diagnostic inputs by docs/SENSITIVE_DATA.md.
        val failure = IOException("private-diagnostic-canary")
        val observed = assertThrows(IOException::class.java) {
            diagnostics.measure(CoordinatorDiagnosticEvent.MEMBERSHIP_REFRESH, 7L) { throw failure }
        }
        assertSame(failure, observed)
        assertTrue(output.any { it.contains("phase=END completed=false") })
        assertFalse(output.any { it.contains("private-diagnostic-canary") })
    }
}
