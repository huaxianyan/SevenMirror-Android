package dev.notificationmirroring.transport

import java.io.IOException
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class TransportCredentialRotationClientTest {
    private lateinit var server: MockWebServer
    private lateinit var store: MemoryRotatingStore

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        store = MemoryRotatingStore(currentCredential())
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun persistsAttemptedBeforeRequestAndDoesNotPromoteOnHttpSuccess() {
        server.enqueue(successResponse())
        val client = TransportCredentialRotationClient(OkHttpClient(), store) { it.fill(9) }

        client.rotate("A".repeat(32))

        assertEquals(CredentialRotationPhase.ATTEMPTED, store.phase)
        assertArrayEquals(ByteArray(32) { 3 }, store.current.authToken)
        assertArrayEquals(ByteArray(32) { 9 }, store.pending)
        assertEquals(0, store.promotions)
        val request = server.takeRequest()
        assertEquals("/v1/devices/rotate", request.path)
        assertEquals("application/json", request.getHeader("Content-Type"))
        val body = request.body.readUtf8()
        check(body.contains("\"rotation_code\":\"${"A".repeat(32)}\""))
        check(body.contains("\"current_auth_token\":\"${b64(ByteArray(32) { 3 })}\""))
        check(body.contains("\"pending_auth_token\":\"${b64(ByteArray(32) { 9 })}\""))
    }

    @Test
    fun ambiguousResponseLossRetainsAndReusesExactPending() {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        var randomCalls = 0
        val client = TransportCredentialRotationClient(OkHttpClient(), store) {
            randomCalls += 1
            it.fill(7)
        }
        assertThrows(IOException::class.java) { client.rotate("B".repeat(32)) }
        val firstBody = server.takeRequest().body.readUtf8()
        assertEquals(CredentialRotationPhase.ATTEMPTED, store.phase)
        assertArrayEquals(ByteArray(32) { 7 }, store.pending)

        server.enqueue(successResponse())
        client.rotate("B".repeat(32))
        val secondBody = server.takeRequest().body.readUtf8()
        assertEquals(1, randomCalls)
        assertEquals(firstBody, secondBody)
        assertArrayEquals(ByteArray(32) { 3 }, store.current.authToken)
    }

    @Test
    fun malformedCodeAndResponseFailClosed() {
        val client = TransportCredentialRotationClient(OkHttpClient(), store) { it.fill(8) }
        assertThrows(IllegalArgumentException::class.java) { client.rotate("not a code") }
        assertEquals(0, server.requestCount)

        server.enqueue(
            MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                .setBody("""{"status":"rotated","extra":true}"""),
        )
        assertThrows(IllegalStateException::class.java) { client.rotate("C".repeat(32)) }
        assertEquals(CredentialRotationPhase.ATTEMPTED, store.phase)
        assertNotNull(store.pending)
        assertEquals(0, store.promotions)
    }

    private fun currentCredential() = StoredTransportCredential(
        serverOrigin = server.url("/").toString().removeSuffix("/"),
        workspaceId = ByteArray(16) { 1 },
        deviceId = ByteArray(16) { 2 },
        authToken = ByteArray(32) { 3 },
        identityKeyId = ByteArray(32) { 4 },
    )

    private fun successResponse() = MockResponse()
        .setResponseCode(200)
        .setHeader("Content-Type", "application/json")
        .setBody("""{"status":"rotated"}""")

    private fun b64(value: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private class MemoryRotatingStore(initial: StoredTransportCredential) :
        RotatingTransportCredentialStore {
        var current = initial.copy(
            workspaceId = initial.workspaceId.copyOf(),
            deviceId = initial.deviceId.copyOf(),
            authToken = initial.authToken.copyOf(),
            identityKeyId = initial.identityKeyId.copyOf(),
        )
        var pending: ByteArray? = null
        var phase: CredentialRotationPhase? = null
        var promotions = 0

        override fun load(): StoredTransportCredential = copyCredential(current)
        override fun saveNew(credential: StoredTransportCredential) = error("not used")

        override fun loadRotation(): StoredCredentialRotation? {
            val token = pending ?: return null
            return StoredCredentialRotation(copyCredential(current), token.copyOf(), checkNotNull(phase))
        }

        override fun loadConnectionCandidate(preferCurrentFallback: Boolean): TransportCredentialCandidate =
            error("not used")

        override fun prepareRotation(pendingAuthToken: ByteArray): StoredCredentialRotation {
            pending?.let {
                check(it.contentEquals(pendingAuthToken))
                return checkNotNull(loadRotation())
            }
            pending = pendingAuthToken.copyOf()
            phase = CredentialRotationPhase.PREPARED
            return checkNotNull(loadRotation())
        }

        override fun markRotationAttempted(pendingAuthToken: ByteArray) {
            check(pending?.contentEquals(pendingAuthToken) == true)
            phase = CredentialRotationPhase.ATTEMPTED
        }

        override fun promotePending(): StoredTransportCredential {
            promotions += 1
            current = current.copy(authToken = checkNotNull(pending).copyOf())
            pending = null
            phase = null
            return copyCredential(current)
        }

        private fun copyCredential(value: StoredTransportCredential) = value.copy(
            workspaceId = value.workspaceId.copyOf(),
            deviceId = value.deviceId.copyOf(),
            authToken = value.authToken.copyOf(),
            identityKeyId = value.identityKeyId.copyOf(),
        )
    }
}
