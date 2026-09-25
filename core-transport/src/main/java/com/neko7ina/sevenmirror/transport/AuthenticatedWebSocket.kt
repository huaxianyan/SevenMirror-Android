package com.neko7ina.sevenmirror.transport

import java.net.URI
import java.util.Timer
import java.util.TimerTask
import java.util.concurrent.TimeUnit
import kotlin.concurrent.schedule
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString.Companion.toByteString

enum class TransportDiagnosticEvent {
    SOCKET_OPEN,
    AUTH_FRAME_SENT,
    AUTHENTICATED,
    SOCKET_FAILURE,
    SOCKET_CLOSED,
}

/**
 * How long the client may go without hearing anything from the relay before OkHttp calls the
 * socket dead.
 *
 * OkHttp arms a read timeout of this length around every ping it sends, so a socket whose TCP
 * connection stayed open while the peer stopped producing data is detected within one interval.
 * Without it the client only learns about such a socket through the server's own ping timing, and
 * until then every queued notification stays in the OkHttp send buffer while the transport still
 * reports ONLINE. Matches the relay's `pingInterval`.
 */
internal const val RELAY_SOCKET_PING_INTERVAL_MILLIS = 30_000L

/**
 * How often the client makes the relay's application layer answer, and how long it waits for it.
 *
 * [RELAY_SOCKET_PING_INTERVAL_MILLIS] only reaches the peer's WebSocket implementation: a relay
 * whose routing loop stopped progressing still answers protocol pings, so a socket can look healthy
 * from below while nothing above it moves. `SNH1`/`SNH2` is answered by the application layer
 * itself, which is what closes that gap. The cadence is the protocol's, and the same one the Chrome
 * extension already uses.
 */
internal const val TRANSPORT_HEARTBEAT_INTERVAL_MILLIS = 20_000L
internal const val TRANSPORT_HEARTBEAT_RESPONSE_TIMEOUT_MILLIS = 10_000L

/**
 * Sends SNA1 and validates the server's SNO1 before exposing application onOpen.
 *
 * `observe` stays the last parameter so existing call sites keep passing it as a trailing lambda.
 * The heartbeat timings sit in front of it and are only overridden in tests.
 */
class AuthenticatedWebSocketFactory(
    httpClient: OkHttpClient,
    private val heartbeatIntervalMillis: Long = TRANSPORT_HEARTBEAT_INTERVAL_MILLIS,
    private val heartbeatResponseTimeoutMillis: Long = TRANSPORT_HEARTBEAT_RESPONSE_TIMEOUT_MILLIS,
    private val observe: (TransportDiagnosticEvent, Throwable?) -> Unit = { _, _ -> },
) {
    private val webSocketClient = httpClient.newBuilder()
        .pingInterval(RELAY_SOCKET_PING_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()
    fun open(
        credential: StoredTransportCredential,
        listener: WebSocketListener,
    ): WebSocket {
        val canonicalOrigin = AndroidTransportCredentialStore.normalizeServerOrigin(
            credential.serverOrigin,
        )
        require(canonicalOrigin == credential.serverOrigin) { "serverOrigin must be canonical" }
        val origin = URI(canonicalOrigin)
        val webSocketScheme = if (origin.scheme == "https") "wss" else "ws"
        val relayUrl = URI(webSocketScheme, null, origin.host, origin.port, "/v1/relay", null, null)
        val request = Request.Builder().url(relayUrl.toString()).build()
        val authenticationFrame = DeviceAuthFrameCodecV1.encode(
            DeviceTransportCredential(
                credential.workspaceId,
                credential.deviceId,
                credential.authToken,
            ),
        )
        return try {
            webSocketClient.newWebSocket(
                request,
                object : WebSocketListener() {
                private var openingResponse: Response? = null
                @Volatile private var authenticated = false
                private var acknowledgementTimer: Timer? = null
                @Volatile private var heartbeatTimer: Timer? = null
                @Volatile private var heartbeatDeadline: TimerTask? = null

                override fun onOpen(webSocket: WebSocket, response: Response) {
                    observe(TransportDiagnosticEvent.SOCKET_OPEN, null)
                    if (response.request.url != request.url) {
                        authenticationFrame.fill(0)
                        webSocket.close(1008, "relay endpoint changed")
                        listener.onFailure(
                            webSocket,
                            IllegalStateException("WebSocket endpoint changed before authentication"),
                            response,
                        )
                        return
                    }
                    val accepted = try {
                        webSocket.send(authenticationFrame.toByteString())
                    } finally {
                        authenticationFrame.fill(0)
                    }
                    if (!accepted) {
                        webSocket.close(1008, "authentication send failed")
                        listener.onFailure(
                            webSocket,
                            IllegalStateException("Unable to enqueue authentication frame"),
                            response,
                        )
                        return
                    }
                    observe(TransportDiagnosticEvent.AUTH_FRAME_SENT, null)
                    openingResponse = response
                    acknowledgementTimer = Timer("transport-auth-ack", true).also { timer ->
                        timer.schedule(5_000L) {
                            if (!authenticated) {
                                webSocket.close(1008, "authentication acknowledgement timeout")
                            }
                        }
                    }
                }

                override fun onMessage(webSocket: WebSocket, text: String) {
                    if (!authenticated) {
                        rejectInvalidAcknowledgement(webSocket)
                    } else {
                        listener.onMessage(webSocket, text)
                    }
                }

                override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                    if (!authenticated) {
                        try {
                            TransportAuthenticationSuccessV1.requireCanonical(bytes.toByteArray())
                        } catch (_: IllegalArgumentException) {
                            rejectInvalidAcknowledgement(webSocket)
                            return
                        }
                        authenticated = true
                        acknowledgementTimer?.cancel()
                        acknowledgementTimer = null
                        observe(TransportDiagnosticEvent.AUTHENTICATED, null)
                        startHeartbeat(webSocket)
                        listener.onOpen(webSocket, requireNotNull(openingResponse))
                    } else if (isHeartbeatResponse(bytes)) {
                        // Consumed at the transport boundary, as the protocol requires: the
                        // envelope decoder would read these four bytes as a malformed frame.
                        heartbeatDeadline?.cancel()
                        heartbeatDeadline = null
                    } else {
                        listener.onMessage(webSocket, bytes)
                    }
                }

                /**
                 * Starts the periodic `SNH1`. The first one goes out after a full interval, so a
                 * connection that just authenticated is not asked to prove itself twice at once.
                 */
                private fun startHeartbeat(webSocket: WebSocket) {
                    val timer = Timer("transport-heartbeat", true)
                    heartbeatTimer = timer
                    timer.scheduleAtFixedRate(
                        object : TimerTask() {
                            override fun run() = sendHeartbeat(webSocket)
                        },
                        heartbeatIntervalMillis,
                        heartbeatIntervalMillis,
                    )
                }

                private fun sendHeartbeat(webSocket: WebSocket) {
                    // At most one outstanding heartbeat: a tick landing while the previous one is
                    // still unanswered must not arm a second, later deadline over the first.
                    if (!authenticated || heartbeatDeadline != null) return
                    val accepted = try {
                        webSocket.send(TransportHeartbeatV1.encodeRequest().toByteString())
                    } catch (_: Throwable) {
                        false
                    }
                    if (!accepted) {
                        failHeartbeat(webSocket, "heartbeat send failed")
                        return
                    }
                    val deadline = object : TimerTask() {
                        override fun run() {
                            heartbeatDeadline = null
                            failHeartbeat(webSocket, "heartbeat response timeout")
                        }
                    }
                    heartbeatDeadline = deadline
                    try {
                        heartbeatTimer?.schedule(deadline, heartbeatResponseTimeoutMillis)
                    } catch (_: IllegalStateException) {
                        // Teardown cancelled the timer between the send and this line. Nothing is
                        // left to arm, and there is no connection left to fail.
                        heartbeatDeadline = null
                    }
                }

                /**
                 * Ends a connection whose liveness proof failed.
                 *
                 * The failure is reported to the application listener rather than left to arrive
                 * through `onClosed`: the peer is exactly the one that stopped answering, so the
                 * close handshake may never complete and the reconnect path must not wait for it.
                 */
                private fun failHeartbeat(webSocket: WebSocket, reason: String) {
                    clearHeartbeat()
                    val error = TransportHeartbeatTimeoutException(reason)
                    observe(TransportDiagnosticEvent.SOCKET_FAILURE, error)
                    webSocket.close(1008, reason)
                    listener.onFailure(webSocket, error, openingResponse)
                }

                private fun clearHeartbeat() {
                    heartbeatDeadline?.cancel()
                    heartbeatDeadline = null
                    heartbeatTimer?.cancel()
                    heartbeatTimer = null
                }

                private fun isHeartbeatResponse(bytes: okio.ByteString): Boolean =
                    bytes.size == TransportHeartbeatV1.ENCODED_SIZE &&
                        TransportHeartbeatV1.isResponse(bytes.toByteArray())

                private fun rejectInvalidAcknowledgement(webSocket: WebSocket) {
                    acknowledgementTimer?.cancel()
                    acknowledgementTimer = null
                    webSocket.close(1008, "invalid authentication acknowledgement")
                    listener.onFailure(
                        webSocket,
                        IllegalStateException("Invalid transport authentication acknowledgement"),
                        openingResponse,
                    )
                }

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    // A peer that is already closing must not be asked to prove itself again; a
                    // tick landing here would be reported as a heartbeat failure on a connection
                    // that is merely shutting down.
                    clearHeartbeat()
                    listener.onClosing(webSocket, code, reason)
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    acknowledgementTimer?.cancel()
                    acknowledgementTimer = null
                    clearHeartbeat()
                    observe(TransportDiagnosticEvent.SOCKET_CLOSED, null)
                    listener.onClosed(webSocket, code, reason)
                }

                override fun onFailure(webSocket: WebSocket, error: Throwable, response: Response?) {
                    acknowledgementTimer?.cancel()
                    acknowledgementTimer = null
                    clearHeartbeat()
                    if (!authenticated) authenticationFrame.fill(0)
                    observe(TransportDiagnosticEvent.SOCKET_FAILURE, error)
                    listener.onFailure(webSocket, error, response)
                }
                },
            )
        } catch (error: Throwable) {
            authenticationFrame.fill(0)
            throw error
        }
    }
}
