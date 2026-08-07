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
        var firstMessage: ByteArray? = null
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        firstMessage = bytes.toByteArray()
                        received.countDown()
                    }
                },
            ),
        )
        server.start()
        val events = mutableListOf<String>()
        val credential = credential(server)
        val client = OkHttpClient()
        try {
            val socket = AuthenticatedWebSocketFactory(client) {
                synchronized(events) { events += it.name }
            }.open(
                credential,
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        synchronized(events) { events += "APPLICATION_OPEN" }
                    }
                },
            )
            assertTrue(received.await(5, TimeUnit.SECONDS))
            assertArrayEquals(
                DeviceAuthFrameCodecV1.encode(
                    DeviceTransportCredential(
                        credential.workspaceId,
                        credential.deviceId,
                        credential.authToken,
                    ),
                ),
                firstMessage,
            )
            synchronized(events) {
                assertEquals(
                    listOf("SOCKET_OPEN", "AUTH_FRAME_SENT", "APPLICATION_OPEN"),
                    events.take(3),
                )
            }
            socket.cancel()
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
