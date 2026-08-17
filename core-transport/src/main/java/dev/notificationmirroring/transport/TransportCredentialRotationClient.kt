package dev.notificationmirroring.transport

import com.squareup.moshi.JsonReader
import com.squareup.moshi.JsonWriter
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private const val MAX_ROTATION_RESPONSE_BYTES = 1024L

data class CredentialRotationSubmission(
    val awaitingPendingAuthentication: Boolean = true,
)

/** Blocking recoverable rotation request; callers must invoke it off the main thread. */
class TransportCredentialRotationClient(
    httpClient: OkHttpClient,
    private val credentialStore: RotatingTransportCredentialStore,
    private val fillRandom: (ByteArray) -> Unit = { SecureRandom().nextBytes(it) },
) {
    private val rotationHttpClient = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    fun rotate(rotationCode: String): CredentialRotationSubmission {
        require(rotationCode.matches(Regex("[A-Za-z0-9_-]{32}"))) {
            "rotationCode must be a 192-bit base64url value"
        }
        var rotation = credentialStore.loadRotation()
        if (rotation == null) {
            val current = checkNotNull(credentialStore.load()) {
                "Transport credential is not configured"
            }
            val pending = ByteArray(DeviceAuthFrameCodecV1.AUTH_TOKEN_SIZE)
            try {
                fillRandom(pending)
                rotation = try {
                    credentialStore.prepareRotation(pending)
                } catch (error: Throwable) {
                    credentialStore.loadRotation() ?: throw error
                }
            } finally {
                current.authToken.fill(0)
                pending.fill(0)
            }
        }
        val exactRotation = checkNotNull(rotation)
        try {
            credentialStore.markRotationAttempted(exactRotation.pendingAuthToken)
            val endpoint = "${exactRotation.current.serverOrigin}/v1/devices/rotate"
            val request = Request.Builder()
                .url(endpoint)
                .post(
                    rotationJson(exactRotation, rotationCode)
                        .encodeToByteArray()
                        .toRequestBody(JSON_MEDIA_TYPE),
                )
                .header("Cache-Control", "no-store")
                .header("Accept", "application/json")
                .build()
            exactRotation.current.authToken.fill(0)
            exactRotation.pendingAuthToken.fill(0)
            rotationHttpClient.newCall(request).execute().use { response ->
                check(response.request.url == request.url) {
                    "Credential rotation response endpoint changed"
                }
                check(response.code == 200) {
                    "Credential rotation failed with status ${response.code}"
                }
                check(response.body?.contentType()?.toString() == "application/json") {
                    "Credential rotation returned an unexpected content type"
                }
                val source = checkNotNull(response.body).source()
                val buffer = okio.Buffer()
                var total = 0L
                while (true) {
                    val read = source.read(
                        buffer,
                        minOf(8192L, MAX_ROTATION_RESPONSE_BYTES + 1 - total),
                    )
                    if (read == -1L) break
                    total += read
                    check(total <= MAX_ROTATION_RESPONSE_BYTES) {
                        "Credential rotation response exceeds 1024 bytes"
                    }
                }
                parseResponse(decodeUtf8Strict(buffer.readByteArray()))
            }
            return CredentialRotationSubmission()
        } finally {
            exactRotation.current.authToken.fill(0)
            exactRotation.pendingAuthToken.fill(0)
        }
    }

    private fun rotationJson(rotation: StoredCredentialRotation, rotationCode: String): String {
        val output = okio.Buffer()
        JsonWriter.of(output).use { writer ->
            writer.beginObject()
            writer.name("workspace_id").value(encodeBase64Url(rotation.current.workspaceId))
            writer.name("device_id").value(encodeBase64Url(rotation.current.deviceId))
            writer.name("current_auth_token").value(encodeBase64Url(rotation.current.authToken))
            writer.name("rotation_code").value(rotationCode)
            writer.name("pending_auth_token").value(encodeBase64Url(rotation.pendingAuthToken))
            writer.endObject()
        }
        return output.readUtf8()
    }

    private fun parseResponse(json: String) {
        val reader = JsonReader.of(okio.Buffer().writeUtf8(json))
        var status: String? = null
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "status" -> {
                    check(status == null) { "Duplicate status" }
                    status = reader.nextString()
                }
                else -> error("Credential rotation returned unexpected fields")
            }
        }
        reader.endObject()
        check(reader.peek() == JsonReader.Token.END_DOCUMENT) {
            "Credential rotation returned trailing JSON"
        }
        check(status == "rotated") { "Credential rotation returned invalid status" }
    }

    private fun decodeUtf8Strict(value: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(value))
        .toString()

    private fun encodeBase64Url(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private companion object {
        val JSON_MEDIA_TYPE = "application/json".toMediaType()
    }
}
