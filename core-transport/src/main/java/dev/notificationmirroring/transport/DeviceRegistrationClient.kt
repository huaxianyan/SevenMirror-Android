package dev.notificationmirroring.transport

import com.squareup.moshi.JsonReader
import com.squareup.moshi.JsonWriter
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private const val MAX_RESPONSE_BYTES = 4096L

data class AndroidDeviceRegistration(
    val serverOrigin: String,
    val pairingCode: String,
    val deviceName: String,
    val e2eePublicKey: ByteArray,
    val identityKeyId: ByteArray,
)

/** Blocking registration boundary; callers must invoke it off the Android main thread. */
class DeviceRegistrationClient(
    httpClient: OkHttpClient,
    private val credentialStore: TransportCredentialStore,
) {
    private val registrationHttpClient = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()
    fun register(request: AndroidDeviceRegistration): StoredTransportCredential {
        check(credentialStore.load() == null) {
            "A transport credential already exists; unpair explicitly first"
        }
        val origin = AndroidTransportCredentialStore.normalizeServerOrigin(request.serverOrigin)
        require(request.pairingCode.matches(Regex("[A-Za-z0-9_-]{32}"))) {
            "pairingCode must be a 192-bit base64url value"
        }
        val nameSize = request.deviceName.encodeToByteArray().size
        require(request.deviceName.isNotBlank() && nameSize in 1..100) {
            "deviceName must be non-blank UTF-8 up to 100 bytes"
        }
        require(request.e2eePublicKey.size == 65 && request.e2eePublicKey[0] == 0x04.toByte()) {
            "e2eePublicKey must be a 65-byte uncompressed P-256 point"
        }
        require(request.identityKeyId.size == 32 && request.identityKeyId.any { it != 0.toByte() }) {
            "identityKeyId must be a non-zero 32-byte value"
        }

        val httpRequest = Request.Builder()
            .url("$origin/v1/devices/register")
            .post(registrationJson(request).toRequestBody(JSON_MEDIA_TYPE))
            .header("Cache-Control", "no-store")
            .header("Accept", "application/json")
            .build()
        val response = registrationHttpClient.newCall(httpRequest).execute()
        response.use {
            check(it.code == 201) { "Device registration failed with status ${it.code}" }
            check(it.body?.contentType()?.let { type ->
                type.type == "application" && type.subtype == "json"
            } == true) { "Device registration returned an unexpected content type" }
            val source = checkNotNull(it.body).source()
            val buffer = okio.Buffer()
            var total = 0L
            while (true) {
                val read = source.read(buffer, minOf(8192L, MAX_RESPONSE_BYTES + 1 - total))
                if (read == -1L) break
                total += read
                check(total <= MAX_RESPONSE_BYTES) {
                    "Device registration response exceeds 4096 bytes"
                }
            }
            val bytes = buffer.readByteArray()
            val parsed = parseResponse(decodeUtf8Strict(bytes))
            val credential = StoredTransportCredential(
                serverOrigin = origin,
                workspaceId = decodeBase64Url(parsed.workspaceId, 16, "workspace_id"),
                deviceId = decodeBase64Url(parsed.deviceId, 16, "device_id"),
                authToken = decodeBase64Url(parsed.authToken, 32, "auth_token"),
                identityKeyId = request.identityKeyId.copyOf(),
            )
            credentialStore.saveNew(credential)
            return credential
        }
    }

    private fun registrationJson(request: AndroidDeviceRegistration): String {
        val output = okio.Buffer()
        JsonWriter.of(output).use { writer ->
            writer.beginObject()
            writer.name("pairing_code").value(request.pairingCode)
            writer.name("device_type").value("android")
            writer.name("device_name").value(request.deviceName)
            writer.name("e2ee_public_key").value(encodeBase64Url(request.e2eePublicKey))
            writer.endObject()
        }
        return output.readUtf8()
    }

    private fun parseResponse(json: String): RegistrationResponse {
        val reader = JsonReader.of(okio.Buffer().writeUtf8(json))
        var workspace: String? = null
        var device: String? = null
        var token: String? = null
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "workspace_id" -> {
                    check(workspace == null) { "Duplicate workspace_id" }
                    workspace = reader.nextString()
                }
                "device_id" -> {
                    check(device == null) { "Duplicate device_id" }
                    device = reader.nextString()
                }
                "auth_token" -> {
                    check(token == null) { "Duplicate auth_token" }
                    token = reader.nextString()
                }
                else -> error("Device registration returned unexpected fields")
            }
        }
        reader.endObject()
        check(reader.peek() == JsonReader.Token.END_DOCUMENT) {
            "Device registration returned trailing JSON"
        }
        return RegistrationResponse(
            checkNotNull(workspace) { "Missing workspace_id" },
            checkNotNull(device) { "Missing device_id" },
            checkNotNull(token) { "Missing auth_token" },
        )
    }

    private data class RegistrationResponse(
        val workspaceId: String,
        val deviceId: String,
        val authToken: String,
    )

    private fun decodeUtf8Strict(value: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(value))
        .toString()

    private fun encodeBase64Url(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private fun decodeBase64Url(value: String, size: Int, name: String): ByteArray {
        require(value.matches(Regex("[A-Za-z0-9_-]+"))) { "$name is not base64url" }
        val decoded = try {
            Base64.getUrlDecoder().decode(value)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("$name is not base64url", error)
        }
        require(decoded.size == size && encodeBase64Url(decoded) == value) {
            "$name must canonically encode $size bytes"
        }
        return decoded
    }

    private companion object {
        val JSON_MEDIA_TYPE = "application/json".toMediaType()
    }
}
