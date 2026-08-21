package dev.notificationmirroring.transport

import com.squareup.moshi.JsonReader
import com.squareup.moshi.JsonWriter
import dev.notificationmirroring.crypto.AndroidWorkspaceMembershipStore
import dev.notificationmirroring.crypto.AuthenticatedHpke
import dev.notificationmirroring.crypto.WorkspaceMembershipTrustStore
import dev.notificationmirroring.crypto.WorkspaceMembershipV1
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private const val MAX_MEMBERSHIP_RESPONSE_BYTES = 2L * 1024 * 1024
private const val MAX_ROSTERS_PER_PAGE = 256

data class AndroidMembershipRegistration(
    val serverOrigin: String,
    val pairingCode: String,
    val deviceName: String,
    val identity: AuthenticatedHpke.KeyPair,
)

data class PendingAndroidMembership(
    val serverOrigin: String,
    val workspaceId: ByteArray,
    val deviceId: ByteArray,
    val authToken: ByteArray,
    val identityKeyId: ByteArray,
)

data class AndroidMembershipRefresh(
    val serverState: String,
    val transportEligible: Boolean,
    val state: AndroidWorkspaceMembershipStore.State,
)

/** Blocking ADR-005 enrollment boundary; callers must invoke it off the Android main thread. */
class WorkspaceMembershipClient(
    httpClient: OkHttpClient,
    private val trustStore: WorkspaceMembershipTrustStore,
    private val journal: PendingAndroidMembershipStore,
) {
    private val client = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    fun begin(request: AndroidMembershipRegistration): PendingAndroidMembership {
        journal.load()?.let { existing ->
            existing.pending.authToken.fill(0)
            existing.canonicalProof?.fill(0)
            error("A membership enrollment is already pending")
        }
        val origin = AndroidTransportCredentialStore.normalizeServerOrigin(request.serverOrigin)
        require(request.pairingCode.matches(Regex("[A-Za-z0-9_-]{32}"))) {
            "pairingCode must be a 192-bit base64url value"
        }
        require(request.deviceName.isNotBlank() && request.deviceName.encodeToByteArray().size in 1..100) {
            "deviceName must be non-blank UTF-8 up to 100 bytes"
        }
        AuthenticatedHpke.requireValidPublicKey(request.identity.publicKey)
        require(request.identity.privateKey.size == 32) { "Identity private key must be 32 bytes" }
        val identityKeyId = sha256(request.identity.publicKey)
        val registration = parseRegistration(
            post(origin, "/v1/membership/register", 201, jsonObject {
                name("pairing_code").value(request.pairingCode)
                name("device_type").value("android")
                name("device_name").value(request.deviceName)
                name("e2ee_public_key").value(encodeBase64Url(request.identity.publicKey))
            }),
        )
        val pending = PendingAndroidMembership(
            origin,
            decodeBase64Url(registration.workspaceId, 16, "workspace_id"),
            decodeBase64Url(registration.deviceId, 16, "device_id"),
            decodeBase64Url(registration.authToken, 32, "auth_token"),
            identityKeyId,
        )
        val authority = decodeBase64Url(registration.authorityPublicKey, 32, "authority_public_key")
        val challengeEnc = decodeBase64Url(registration.challengeEnc, 65, "challenge_enc")
        val challengeCiphertext = decodeBase64UrlVariable(registration.challengeCiphertext, "challenge_ciphertext")
        try {
            journal.prepareRegistration(pending, authority, challengeEnc, challengeCiphertext)
            trustStore.pinAuthority(pending.workspaceId, pending.deviceId, authority)
            val canonicalChallenge = WorkspaceMembershipV1.openChallengeCanonical(
                request.identity.publicKey,
                request.identity.privateKey,
                pending.workspaceId,
                pending.deviceId,
                identityKeyId,
                challengeEnc,
                challengeCiphertext,
            )
            val proof = WorkspaceMembershipV1.createProof(canonicalChallenge)
            try {
                journal.bindProof(pending, proof)
                journal.markProofAttempted(pending, proof)
                submitProof(pending, proof)
                journal.markPendingApproval(pending)
            } finally {
                canonicalChallenge.fill(0)
                proof.fill(0)
            }
            return pending.copyState()
        } catch (error: Throwable) {
            pending.authToken.fill(0)
            throw error
        }
    }

    fun resume(identity: AuthenticatedHpke.KeyPair): AndroidMembershipRefresh {
        val stored = checkNotNull(journal.load()) { "Pending membership enrollment is missing" }
        try {
            trustStore.pinAuthority(stored.pending.workspaceId, stored.pending.deviceId, stored.authorityPublicKey)
            val proof = recoverProof(stored, identity)
            try {
                var refreshed = refresh(stored.pending)
                if (refreshed.serverState == "pending_proof") {
                    check(stored.phase != PendingMembershipPhase.PENDING_APPROVAL) {
                        "Membership server rolled back completed identity proof"
                    }
                    journal.markProofAttempted(stored.pending, proof)
                    submitProof(stored.pending, proof)
                    journal.markPendingApproval(stored.pending)
                    refreshed = refresh(stored.pending)
                } else {
                    journal.markPendingApproval(stored.pending)
                }
                return refreshed
            } finally {
                proof.fill(0)
            }
        } finally {
            stored.pending.authToken.fill(0)
            stored.canonicalProof?.fill(0)
        }
    }

    /** Refreshes a promoted certified device without recreating enrollment state. */
    fun refreshActive(credential: StoredTransportCredential): AndroidMembershipRefresh? {
        if (trustStore.load(credential.workspaceId, credential.deviceId) == null) return null
        val request = PendingAndroidMembership(
            credential.serverOrigin,
            credential.workspaceId.copyOf(),
            credential.deviceId.copyOf(),
            credential.authToken.copyOf(),
            credential.identityKeyId.copyOf(),
        )
        return try {
            refresh(request)
        } finally {
            request.authToken.fill(0)
        }
    }

    fun refresh(pending: PendingAndroidMembership): AndroidMembershipRefresh {
        val origin = AndroidTransportCredentialStore.normalizeServerOrigin(pending.serverOrigin)
        requireId(pending.workspaceId, "workspaceId")
        requireId(pending.deviceId, "deviceId")
        requireBytes(pending.authToken, 32, "authToken")
        requireBytes(pending.identityKeyId, 32, "identityKeyId")
        repeat(4096) {
            val durable = checkNotNull(trustStore.load(pending.workspaceId, pending.deviceId)) {
                "Workspace authority pin is missing"
            }
            val response = parseState(
                post(origin, "/v1/membership/state", 200, jsonObject {
                    name("workspace_id").value(encodeBase64Url(pending.workspaceId))
                    name("device_id").value(encodeBase64Url(pending.deviceId))
                    name("auth_token").value(encodeBase64Url(pending.authToken))
                    name("after_roster_epoch").value(durable.rosterEpoch.toString())
                }),
            )
            trustStore.pinAuthority(
                pending.workspaceId,
                pending.deviceId,
                decodeBase64Url(response.authorityPublicKey, 32, "authority_public_key"),
            )
            if (response.state != "approved") {
                check(response.signedCertificate == null && response.rosters.isEmpty() && response.latestEpoch == 0L) {
                    "Pending membership state exposed approved membership data"
                }
                return AndroidMembershipRefresh(response.state, false, durable)
            }
            val certificate = decodeBase64UrlVariable(
                checkNotNull(response.signedCertificate) {
                    "Approved membership state is missing the device certificate"
                },
                "signed_certificate",
            )
            check(response.latestEpoch >= durable.rosterEpoch) {
                "Membership server attempted a roster rollback"
            }
            for (encoded in response.rosters) {
                trustStore.reconcileApproved(
                    pending.workspaceId,
                    pending.deviceId,
                    certificate,
                    decodeBase64UrlVariable(encoded, "roster"),
                )
            }
            val accepted = checkNotNull(trustStore.load(pending.workspaceId, pending.deviceId)) {
                "Membership state disappeared during reconciliation"
            }
            if (accepted.rosterEpoch == response.latestEpoch) {
                check(response.rosters.isNotEmpty() || durable.rosterEpoch == response.latestEpoch) {
                    "Membership roster response made no progress"
                }
                return AndroidMembershipRefresh("approved", accepted.localDeviceActive, accepted)
            }
            check(accepted.rosterEpoch > durable.rosterEpoch && accepted.rosterEpoch < response.latestEpoch) {
                "Membership roster pagination made invalid progress"
            }
        }
        error("Membership roster pagination did not converge")
    }

    private fun recoverProof(
        stored: StoredPendingAndroidMembership,
        identity: AuthenticatedHpke.KeyPair,
    ): ByteArray {
        val keyId = sha256(identity.publicKey)
        check(keyId.contentEquals(stored.pending.identityKeyId)) {
            "Pending enrollment identity no longer matches"
        }
        stored.canonicalProof?.let { return it.copyOf() }
        val challenge = WorkspaceMembershipV1.openChallengeCanonical(
            identity.publicKey,
            identity.privateKey,
            stored.pending.workspaceId,
            stored.pending.deviceId,
            stored.pending.identityKeyId,
            stored.challengeEnc,
            stored.challengeCiphertext,
        )
        return try {
            WorkspaceMembershipV1.createProof(challenge).also {
                journal.bindProof(stored.pending, it)
            }
        } finally {
            challenge.fill(0)
        }
    }

    private fun submitProof(pending: PendingAndroidMembership, canonicalProof: ByteArray) {
        check(
            parseProof(
                post(pending.serverOrigin, "/v1/membership/prove", 200, jsonObject {
                    name("workspace_id").value(encodeBase64Url(pending.workspaceId))
                    name("device_id").value(encodeBase64Url(pending.deviceId))
                    name("auth_token").value(encodeBase64Url(pending.authToken))
                    name("proof").value(encodeBase64Url(canonicalProof))
                }),
            ) == "pending_approval",
        ) { "Membership proof returned an invalid state" }
    }

    private fun post(origin: String, path: String, expectedStatus: Int, body: String): String {
        val request = Request.Builder()
            .url("$origin$path")
            .post(body.toRequestBody(JSON_MEDIA_TYPE))
            .header("Accept", "application/json")
            .header("Cache-Control", "no-store")
            .build()
        client.newCall(request).execute().use { response ->
            check(response.code == expectedStatus) {
                "Membership request failed with status ${response.code}"
            }
            check(response.body?.contentType()?.let {
                it.type == "application" && it.subtype == "json"
            } == true) { "Membership request returned an unexpected content type" }
            val source = checkNotNull(response.body).source()
            val buffer = okio.Buffer()
            var total = 0L
            while (true) {
                val read = source.read(
                    buffer,
                    minOf(8192L, MAX_MEMBERSHIP_RESPONSE_BYTES + 1 - total),
                )
                if (read == -1L) break
                total += read
                check(total <= MAX_MEMBERSHIP_RESPONSE_BYTES) {
                    "Membership response exceeds 2 MiB"
                }
            }
            return decodeUtf8Strict(buffer.readByteArray())
        }
    }

    private fun parseRegistration(json: String): RegistrationResponse {
        val values = readStringObject(json, setOf(
            "workspace_id", "device_id", "auth_token", "authority_public_key",
            "challenge_enc", "challenge_ciphertext",
        ))
        return RegistrationResponse(
            values.getValue("workspace_id"), values.getValue("device_id"),
            values.getValue("auth_token"), values.getValue("authority_public_key"),
            values.getValue("challenge_enc"), values.getValue("challenge_ciphertext"),
        )
    }

    private fun parseProof(json: String): String = readStringObject(json, setOf("state")).getValue("state")

    private fun parseState(json: String): StateResponse {
        val reader = JsonReader.of(okio.Buffer().writeUtf8(json))
        var state: String? = null
        var authority: String? = null
        var certificate: String? = null
        var rosters: List<String>? = null
        var latest: String? = null
        val seen = mutableSetOf<String>()
        reader.beginObject()
        while (reader.hasNext()) {
            val name = reader.nextName()
            check(seen.add(name)) { "Membership state contains duplicate fields" }
            when (name) {
                "state" -> state = reader.nextString()
                "authority_public_key" -> authority = reader.nextString()
                "signed_certificate" -> certificate = reader.nextString()
                "latest_roster_epoch" -> latest = reader.nextString()
                "rosters" -> {
                    val result = mutableListOf<String>()
                    reader.beginArray()
                    while (reader.hasNext()) {
                        check(result.size < MAX_ROSTERS_PER_PAGE) { "Membership roster page exceeds 256 entries" }
                        result += reader.nextString()
                    }
                    reader.endArray()
                    rosters = result
                }
                else -> error("Membership state returned unexpected fields")
            }
        }
        reader.endObject()
        check(reader.peek() == JsonReader.Token.END_DOCUMENT) { "Membership state returned trailing JSON" }
        val resolvedState = checkNotNull(state) { "Membership state is missing state" }
        check(resolvedState in setOf("pending_proof", "pending_approval", "approved")) {
            "Membership state is invalid"
        }
        return StateResponse(
            resolvedState,
            checkNotNull(authority) { "Membership state is missing authority_public_key" },
            certificate,
            checkNotNull(rosters) { "Membership state is missing rosters" },
            parseEpoch(checkNotNull(latest) { "Membership state is missing latest_roster_epoch" }),
        )
    }

    private fun readStringObject(json: String, expected: Set<String>): Map<String, String> {
        val reader = JsonReader.of(okio.Buffer().writeUtf8(json))
        val values = mutableMapOf<String, String>()
        reader.beginObject()
        while (reader.hasNext()) {
            val name = reader.nextName()
            check(name in expected && name !in values) { "Membership response returned unexpected fields" }
            values[name] = reader.nextString()
        }
        reader.endObject()
        check(reader.peek() == JsonReader.Token.END_DOCUMENT && values.keys == expected) {
            "Membership response returned missing or trailing fields"
        }
        return values
    }

    private fun jsonObject(write: JsonWriter.() -> Unit): String {
        val output = okio.Buffer()
        JsonWriter.of(output).use { writer -> writer.beginObject(); writer.write(); writer.endObject() }
        return output.readUtf8()
    }

    private data class RegistrationResponse(
        val workspaceId: String,
        val deviceId: String,
        val authToken: String,
        val authorityPublicKey: String,
        val challengeEnc: String,
        val challengeCiphertext: String,
    )
    private data class StateResponse(
        val state: String,
        val authorityPublicKey: String,
        val signedCertificate: String?,
        val rosters: List<String>,
        val latestEpoch: Long,
    )

    private fun parseEpoch(value: String): Long {
        require(value.matches(Regex("0|[1-9][0-9]*"))) { "Roster epoch is not canonical" }
        return value.toLong().also { require(it >= 0 && it.toString() == value) { "Roster epoch is invalid" } }
    }
    private fun requireId(value: ByteArray, name: String) { requireBytes(value, 16, name) }
    private fun requireBytes(value: ByteArray, size: Int, name: String) { require(value.size == size && value.any { it != 0.toByte() }) { "$name has invalid length or value" } }
    private fun encodeBase64Url(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun decodeBase64Url(value: String, size: Int, name: String): ByteArray = decodeBase64UrlVariable(value, name).also { require(it.size == size) { "$name must encode $size bytes" } }
    private fun decodeBase64UrlVariable(value: String, name: String): ByteArray { require(value.matches(Regex("[A-Za-z0-9_-]+"))) { "$name is not base64url" }; val decoded = try { Base64.getUrlDecoder().decode(value) } catch (error: IllegalArgumentException) { throw IllegalArgumentException("$name is not base64url", error) }; require(encodeBase64Url(decoded) == value) { "$name is not canonical base64url" }; return decoded }
    private fun decodeUtf8Strict(value: ByteArray): String = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(value)).toString()
    private fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)
    private fun PendingAndroidMembership.copyState() = copy(workspaceId = workspaceId.copyOf(), deviceId = deviceId.copyOf(), authToken = authToken.copyOf(), identityKeyId = identityKeyId.copyOf())

    private companion object { val JSON_MEDIA_TYPE = "application/json".toMediaType() }
}
