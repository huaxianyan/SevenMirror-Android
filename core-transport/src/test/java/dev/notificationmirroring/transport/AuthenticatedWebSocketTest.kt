package dev.notificationmirroring.transport

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
            AuthenticatedWebSocketFactory(client) { events += it }.open(
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
            val socket = AuthenticatedWebSocketFactory(client) {
                synchronized(events) { events += it.name }
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
            assertTrue(serverClosed.await(5, TimeUnit.SECONDS))
        } finally {
            client.dispatcher.executorService.shutdown()
            server.shutdown()
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
