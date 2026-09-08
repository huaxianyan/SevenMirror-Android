package dev.notificationmirroring.android

import android.os.SystemClock
import android.util.Log

internal enum class CoordinatorDiagnosticEvent {
    NETWORK_AVAILABLE,
    NETWORK_LOST,
    NETWORK_CAPABILITIES_CHANGED,
    CONNECTION_REQUESTED,
    CONNECTION_ATTEMPT,
    CONNECTION_READY,
    TERMINATION_QUEUED,
    CONNECTION_TERMINATED,
    RECONNECT_SCHEDULED,
    RECONNECT_TIMER_FIRED,
    PENDING_MEMBERSHIP_RECOVERY,
    MEMBERSHIP_REFRESH,
    STARTUP_SNAPSHOT,
    STARTUP_SNAPSHOT_SUBMITTED,
}

/** Code-defined enums and scalar metadata only: never accept payloads or exception messages. */
internal class TransportDiagnostics(
    private val state: () -> AndroidTransportState,
    private val enabled: Boolean = BuildConfig.DEBUG,
    private val clock: () -> Long = SystemClock::elapsedRealtime,
    private val write: (String) -> Unit = { Log.d("SevenMirrorTransport", it) },
) {
    fun record(
        event: Enum<*>,
        generation: Long,
        delayMs: Long? = null,
        networkHandle: Long? = null,
        wifi: Boolean? = null,
        cellular: Boolean? = null,
        vpn: Boolean? = null,
        validated: Boolean? = null,
        accepted: Boolean? = null,
    ) {
        if (!enabled) return
        emit(event, generation, buildString {
            delayMs?.let { append(" delay_ms=$it") }
            networkHandle?.let { append(" network=$it") }
            wifi?.let { append(" wifi=$it") }
            cellular?.let { append(" cellular=$it") }
            vpn?.let { append(" vpn=$it") }
            validated?.let { append(" validated=$it") }
            accepted?.let { append(" accepted=$it") }
        })
    }

    fun <T> measure(event: CoordinatorDiagnosticEvent, generation: Long, operation: () -> T): T {
        if (!enabled) return operation()
        emit(event, generation, " phase=BEGIN")
        var completed = false
        try {
            return operation().also { completed = true }
        } finally {
            emit(event, generation, " phase=END completed=$completed")
        }
    }

    private fun emit(event: Enum<*>, generation: Long, fields: String) {
        write("t_ms=${clock()} gen=$generation event=${event.name} state=${state().name}$fields")
    }
}
