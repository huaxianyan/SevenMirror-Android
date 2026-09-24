package com.neko7ina.sevenmirror

import android.os.SystemClock
import android.util.Log

internal enum class CoordinatorDiagnosticEvent {
    NETWORK_AVAILABLE,
    NETWORK_LOST,
    NETWORK_CAPABILITIES_CHANGED,
    CONNECTION_NETWORK_REPLACED,
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

    /** A local failure parked the device on the recovery page, which no retry can leave. */
    SECURITY_ERROR_ENTERED,

    /** A local failure re-armed the connection instead of parking the device. */
    LOCAL_FAILURE_RETRY,
}

private const val MAX_FAILURE_LABEL_LENGTH = 120

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

    /**
     * Records a failure that parked or re-armed the transport, or that ended a relay socket.
     *
     * Only the exception's class name is written, never its message: the message may carry
     * payload, while the class name alone is what tells a transient Keystore, Binder, identity or
     * endpoint failure apart from a genuinely permanent local one, and a socket that went silent
     * apart from one the peer refused or reset. Without it a parked device can only be diagnosed
     * by guessing which of the coordinator's catch blocks fired, and a dropped socket only by its
     * event name.
     */
    fun recordFailure(
        event: Enum<*>,
        generation: Long,
        error: Throwable,
        recovery: AndroidSecurityRecovery? = null,
    ) {
        if (!enabled) return
        emit(event, generation, buildString {
            recovery?.let { append(" recovery=${it.name}") }
            append(" failure=")
            append(failureLabel(error))
        })
    }

    private fun failureLabel(error: Throwable): String = error.javaClass.name
        .filter { it.isLetterOrDigit() || it == '.' || it == '$' }
        .take(MAX_FAILURE_LABEL_LENGTH)

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
