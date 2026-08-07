package dev.notificationmirroring.transport

import java.net.URI
import java.util.Timer
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

/** Sends SNA1 and validates the server's SNO1 before exposing application onOpen. */
class AuthenticatedWebSocketFactory(
    httpClient: OkHttpClient,
    private val observe: (TransportDiagnosticEvent) -> Unit = {},
) {
    private val webSocketClient = httpClient.newBuilder()
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
        return webSocketClient.newWebSocket(
            request,
            object : WebSocketListener() {
                private var openingResponse: Response? = null
                @Volatile private var authenticated = false
                private var acknowledgementTimer: Timer? = null

                override fun onOpen(webSocket: WebSocket, response: Response) {
                    observe(TransportDiagnosticEvent.SOCKET_OPEN)
                    if (response.request.url != request.url) {
                        webSocket.close(1008, "relay endpoint changed")
                        listener.onFailure(
                            webSocket,
                            IllegalStateException("WebSocket endpoint changed before authentication"),
                            response,
                        )
                        return
                    }
                    val frame = DeviceAuthFrameCodecV1.encode(
                        DeviceTransportCredential(
                            credential.workspaceId,
                            credential.deviceId,
                            credential.authToken,
                        ),
                    )
                    val accepted = try {
                        webSocket.send(frame.toByteString())
                    } finally {
                        frame.fill(0)
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
                    observe(TransportDiagnosticEvent.AUTH_FRAME_SENT)
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
                        observe(TransportDiagnosticEvent.AUTHENTICATED)
                        listener.onOpen(webSocket, requireNotNull(openingResponse))
                    } else {
                        listener.onMessage(webSocket, bytes)
                    }
                }

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

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) =
                    listener.onClosing(webSocket, code, reason)

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    acknowledgementTimer?.cancel()
                    acknowledgementTimer = null
                    observe(TransportDiagnosticEvent.SOCKET_CLOSED)
                    listener.onClosed(webSocket, code, reason)
                }

                override fun onFailure(webSocket: WebSocket, error: Throwable, response: Response?) {
                    acknowledgementTimer?.cancel()
                    acknowledgementTimer = null
                    observe(TransportDiagnosticEvent.SOCKET_FAILURE)
                    listener.onFailure(webSocket, error, response)
                }
            },
        )
    }
}
