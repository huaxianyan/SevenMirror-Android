package dev.notificationmirroring.transport

import java.net.URI
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString.Companion.toByteString

enum class TransportDiagnosticEvent {
    SOCKET_OPEN,
    AUTH_FRAME_SENT,
    SOCKET_FAILURE,
    SOCKET_CLOSED,
}

/** Sends SNA1 before exposing onOpen to the application listener. */
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
                    listener.onOpen(webSocket, response)
                }

                override fun onMessage(webSocket: WebSocket, text: String) =
                    listener.onMessage(webSocket, text)

                override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) =
                    listener.onMessage(webSocket, bytes)

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) =
                    listener.onClosing(webSocket, code, reason)

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    observe(TransportDiagnosticEvent.SOCKET_CLOSED)
                    listener.onClosed(webSocket, code, reason)
                }

                override fun onFailure(webSocket: WebSocket, error: Throwable, response: Response?) {
                    observe(TransportDiagnosticEvent.SOCKET_FAILURE)
                    listener.onFailure(webSocket, error, response)
                }
            },
        )
    }
}
