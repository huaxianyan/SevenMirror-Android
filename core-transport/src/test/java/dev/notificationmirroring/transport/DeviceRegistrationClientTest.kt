package dev.notificationmirroring.transport

import java.util.Base64
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class DeviceRegistrationClientTest {
    private lateinit var server: MockWebServer
    private lateinit var store: MemoryStore
    private lateinit var client: DeviceRegistrationClient

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        store = MemoryStore()
        client = DeviceRegistrationClient(OkHttpClient(), store)
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun persistsOneTimeCredentialBeforeReturningSuccess() {
        val workspace = ByteArray(16) { 1 }
        val device = ByteArray(16) { 2 }
        val token = ByteArray(32) { 3 }
        server.enqueue(
            MockResponse()
                .setResponseCode(201)
                .setHeader("Content-Type", "application/json; charset=utf-8")
                .setBody(
                    """{"workspace_id":"${b64(workspace)}","device_id":"${b64(device)}","auth_token":"${b64(token)}"}""",
                ),
        )

        val result = client.register(validRequest())
        assertArrayEquals(token, result.authToken)
        assertArrayEquals(token, store.value?.authToken)
        val recorded = server.takeRequest()
        assertEquals("/v1/devices/register", recorded.path)
        assertEquals("application/json; charset=utf-8", recorded.getHeader("Content-Type"))
        val requestBody = recorded.body.readUtf8()
        check(requestBody.contains("\"device_type\":\"android\""))
        check(requestBody.contains("\"pairing_code\":\"${"A".repeat(32)}\""))
    }

    @Test
    fun rejectsUnknownOrOversizedResponseWithoutPersistence() {
        server.enqueue(
            MockResponse().setResponseCode(201).setHeader("Content-Type", "application/json")
                .setBody("""{"workspace_id":"x","device_id":"x","auth_token":"x","extra":true}"""),
        )
        assertThrows(IllegalStateException::class.java) { client.register(validRequest()) }
        assertNull(store.value)

        server.enqueue(
            MockResponse().setResponseCode(201).setHeader("Content-Type", "application/json")
                .setBody("x".repeat(4097)),
        )
        assertThrows(IllegalStateException::class.java) { client.register(validRequest()) }
        assertNull(store.value)
    }

    @Test
    fun clearsReturnedTokenWhenPlatformPersistenceFails() {
        val token = ByteArray(32) { 3 }
        store.failSave = true
        server.enqueue(
            MockResponse().setResponseCode(201).setHeader("Content-Type", "application/json")
                .setBody(
                    """{"workspace_id":"${b64(ByteArray(16) { 1 })}","device_id":"${b64(ByteArray(16) { 2 })}","auth_token":"${b64(token)}"}""",
                ),
        )

        assertThrows(IllegalStateException::class.java) { client.register(validRequest()) }
        check(store.value?.authToken?.all { it == 0.toByte() } == true)
    }

    @Test
    fun refusesNetworkRegistrationWhenCredentialAlreadyExists() {
        store.value = StoredTransportCredential(
            serverOrigin = server.url("/").toString().removeSuffix("/"),
            workspaceId = ByteArray(16) { 1 },
            deviceId = ByteArray(16) { 2 },
            authToken = ByteArray(32) { 3 },
            identityKeyId = ByteArray(32) { 4 },
        )
        assertThrows(IllegalStateException::class.java) { client.register(validRequest()) }
        assertEquals(0, server.requestCount)
    }

    private fun validRequest(): AndroidDeviceRegistration {
        val publicKey = ByteArray(65) { 7 }.also { it[0] = 0x04 }
        return AndroidDeviceRegistration(
            serverOrigin = server.url("/").toString(),
            pairingCode = "A".repeat(32),
            deviceName = "Pixel",
            e2eePublicKey = publicKey,
            identityKeyId = ByteArray(32) { 4 },
        )
    }

    private fun b64(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private class MemoryStore : TransportCredentialStore {
        var value: StoredTransportCredential? = null
        var failSave = false
        override fun load(): StoredTransportCredential? = value
        override fun saveNew(credential: StoredTransportCredential) {
            check(value == null)
            value = credential
            check(!failSave) { "synthetic persistence failure" }
        }
    }
}
