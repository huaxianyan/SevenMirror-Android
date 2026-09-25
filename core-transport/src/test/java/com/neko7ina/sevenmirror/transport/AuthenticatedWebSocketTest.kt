package com.neko7ina.sevenmirror.transport

import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthenticatedWebSocketTest {
    @Test
    fun refusesRedirectBeforeAuthenticationCredentialDisclosure() {
        val server = MockWebServer()
        server.enqueue(
            MockResponse().setResponseCode(302).setHeader("Location", "https://attacker.example/relay"),
        )
        server.start()
        val failed = CountDownLatch(1)
        val events = mutableListOf<TransportDiagnosticEvent>()
        val client = OkHttpClient()
        try {
            AuthenticatedWebSocketFactory(client) { event, _ -> events += event }.open(
                credential(server),
                object : WebSocketListener() {
                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        failed.countDown()
                    }
                },
            )
            assertTrue(failed.await(5, TimeUnit.SECONDS))
            assertEquals(1, server.requestCount)
            assertFalse(events.contains(TransportDiagnosticEvent.AUTH_FRAME_SENT))
        } finally {
            client.dispatcher.executorService.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun sendsAuthenticationFrameBeforeApplicationOpenCallback() {
        val server = MockWebServer()
        val received = CountDownLatch(1)
        val applicationOpened = CountDownLatch(1)
        var firstMessage: ByteArray? = null
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        firstMessage = bytes.toByteArray()
                        webSocket.send(TransportAuthenticationSuccessV1.encode().toByteString())
                        received.countDown()
                    }
                },
            ),
        )
        server.start()
        val events = mutableListOf<String>()
        val credential = credential(server)
        val expectedAuthenticationFrame = DeviceAuthFrameCodecV1.encode(
            DeviceTransportCredential(
                credential.workspaceId,
                credential.deviceId,
                credential.authToken,
            ),
        )
        val client = OkHttpClient()
        try {
            val socket = AuthenticatedWebSocketFactory(client) { event, _ ->
                synchronized(events) { events += event.name }
            }.open(
                credential,
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        synchronized(events) { events += "APPLICATION_OPEN" }
                        applicationOpened.countDown()
                    }
                },
            )
            credential.authToken.fill(0)
            assertTrue(received.await(5, TimeUnit.SECONDS))
            assertTrue(applicationOpened.await(5, TimeUnit.SECONDS))
            assertArrayEquals(expectedAuthenticationFrame, firstMessage)
            synchronized(events) {
                assertEquals(
                    listOf("SOCKET_OPEN", "AUTH_FRAME_SENT", "AUTHENTICATED", "APPLICATION_OPEN"),
                    events.take(4),
                )
            }
            socket.cancel()
        } finally {
            client.dispatcher.executorService.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun rejectsMalformedAuthenticationAcknowledgementWithoutApplicationOpen() {
        val server = MockWebServer()
        val serverClosed = CountDownLatch(1)
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        webSocket.send(byteArrayOf(1, 2, 3, 4).toByteString())
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        serverClosed.countDown()
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        serverClosed.countDown()
                    }
                },
            ),
        )
        server.start()
        val failed = CountDownLatch(1)
        var applicationOpened = false
        val client = OkHttpClient()
        try {
            val socket = AuthenticatedWebSocketFactory(client).open(
                credential(server),
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        applicationOpened = true
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        failed.countDown()
                    }
                },
            )
            assertTrue(failed.await(5, TimeUnit.SECONDS))
            assertFalse(applicationOpened)
            socket.cancel()
            // This callback is teardown synchronization, not the behavior under test. Some
            // MockWebServer/OkHttp schedules never deliver the peer callback after cancellation.
            serverClosed.await(5, TimeUnit.SECONDS)
        } finally {
            client.dispatcher.executorService.shutdown()
            try {
                server.shutdown()
            } catch (_: IOException) {
                // The asserted client failure above is the security boundary. MockWebServer can
                // still race its internal WebSocket upgrade task while shutting the fixture down.
            }
        }
    }

    @Test
    fun reportsTheErrorTypeAlongsideTheSocketFailureEvent() {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(500))
        server.start()
        val observed = mutableListOf<Pair<TransportDiagnosticEvent, Throwable?>>()
        val failed = CountDownLatch(1)
        val client = OkHttpClient()
        try {
            AuthenticatedWebSocketFactory(client) { event, error ->
                synchronized(observed) { observed += event to error }
            }.open(
                credential(server),
                object : WebSocketListener() {
                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        failed.countDown()
                    }
                },
            )
            assertTrue(failed.await(5, TimeUnit.SECONDS))
            val collected = synchronized(observed) { observed.toList() }
            val failure = collected.firstOrNull { it.first == TransportDiagnosticEvent.SOCKET_FAILURE }
            assertNotNull("SOCKET_FAILURE must be observed", failure)
            assertNotNull(
                "SOCKET_FAILURE must carry the error that ended the socket",
                failure!!.second,
            )
            assertTrue(
                "only SOCKET_FAILURE carries an error",
                collected
                    .filter { it.first != TransportDiagnosticEvent.SOCKET_FAILURE }
                    .all { it.second == null },
            )
        } finally {
            client.dispatcher.executorService.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun answersTheHeartbeatAtTheTransportBoundaryOnly() {
        val server = MockWebServer()
        val heartbeatReceived = CountDownLatch(1)
        var heartbeatFrame: ByteArray? = null
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        if (bytes.size == TransportHeartbeatV1.ENCODED_SIZE) {
                            heartbeatFrame = bytes.toByteArray()
                            // The canonical SNH2, sent back only for the heartbeat.
                            webSocket.send(byteArrayOf(0x53, 0x4e, 0x48, 0x32).toByteString())
                            heartbeatReceived.countDown()
                        } else {
                            webSocket.send(
                                TransportAuthenticationSuccessV1.encode().toByteString(),
                            )
                        }
                    }
                },
            ),
        )
        server.start()
        val applicationMessages = mutableListOf<ByteArray>()
        val applicationFailed = CountDownLatch(1)
        val client = OkHttpClient()
        try {
            AuthenticatedWebSocketFactory(
                client,
                heartbeatIntervalMillis = 50,
                heartbeatResponseTimeoutMillis = 5_000,
            ).open(
                credential(server),
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        synchronized(applicationMessages) {
                            applicationMessages += bytes.toByteArray()
                        }
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        applicationFailed.countDown()
                    }
                },
            )
            assertTrue(heartbeatReceived.await(5, TimeUnit.SECONDS))
            assertArrayEquals(
                TransportHeartbeatV1.encodeRequest(),
                requireNotNull(heartbeatFrame),
            )
            // Let several intervals pass: a heartbeat that leaked to the application, or an SNH2
            // that was not consumed, would show up as a message or a failure well inside this.
            applicationFailed.await(300, TimeUnit.MILLISECONDS)
            assertFalse(
                "an answered heartbeat must not fail the socket",
                applicationFailed.count == 0L,
            )
            synchronized(applicationMessages) {
                assertTrue(
                    "the application listener must never see a heartbeat frame",
                    applicationMessages.isEmpty(),
                )
            }
        } finally {
            client.dispatcher.executorService.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun failsTheSocketWhenTheHeartbeatGoesUnanswered() {
        val server = MockWebServer()
        val heartbeatReceived = CountDownLatch(1)
        val serverClosed = CountDownLatch(1)
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        if (bytes.size == TransportHeartbeatV1.ENCODED_SIZE) {
                            // Deliberately unanswered: this is the half-dead relay.
                            heartbeatReceived.countDown()
                        } else {
                            webSocket.send(
                                TransportAuthenticationSuccessV1.encode().toByteString(),
                            )
                        }
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        serverClosed.countDown()
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        serverClosed.countDown()
                    }
                },
            ),
        )
        server.start()
        val failed = CountDownLatch(1)
        val observed = mutableListOf<Pair<TransportDiagnosticEvent, Throwable?>>()
        var failure: Throwable? = null
        val client = OkHttpClient()
        try {
            AuthenticatedWebSocketFactory(
                client,
                observe = { event, error -> synchronized(observed) { observed += event to error } },
                heartbeatIntervalMillis = 50,
                heartbeatResponseTimeoutMillis = 150,
            ).open(
                credential(server),
                object : WebSocketListener() {
                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        failure = t
                        failed.countDown()
                    }
                },
            )
            assertTrue(
                "an unanswered heartbeat must end the connection",
                failed.await(5, TimeUnit.SECONDS),
            )
            assertTrue(heartbeatReceived.await(1, TimeUnit.SECONDS))
            assertTrue(
                "the failure must be its own type so diagnostics can name it",
                failure is TransportHeartbeatTimeoutException,
            )
            val collected = synchronized(observed) { observed.toList() }
            val socketFailure = collected.firstOrNull {
                it.first == TransportDiagnosticEvent.SOCKET_FAILURE
            }
            assertTrue(
                "SOCKET_FAILURE must carry the heartbeat failure itself",
                socketFailure?.second is TransportHeartbeatTimeoutException,
            )
            // Teardown synchronization only. The peer that stopped answering is exactly the one
            // whose close handshake may never complete, so this must not gate the assertions.
            serverClosed.await(5, TimeUnit.SECONDS)
        } finally {
            client.dispatcher.executorService.shutdown()
            try {
                server.shutdown()
            } catch (_: IOException) {
                // Same MockWebServer shutdown race the malformed-acknowledgement case documents:
                // the asserted client failure is the boundary under test, and the fixture can
                // still be tearing its own WebSocket task down.
            }
        }
    }

    private fun credential(server: MockWebServer) = StoredTransportCredential(
        serverOrigin = server.url("/").toString().removeSuffix("/"),
        workspaceId = ByteArray(16) { 1 },
        deviceId = ByteArray(16) { 2 },
        authToken = ByteArray(32) { 3 },
        identityKeyId = ByteArray(32) { 4 },
    )
}
