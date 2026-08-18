package dev.notificationmirroring.transport

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.net.URI
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class StoredTransportCredential(
    val serverOrigin: String,
    val workspaceId: ByteArray,
    val deviceId: ByteArray,
    val authToken: ByteArray,
    val identityKeyId: ByteArray,
)

enum class CredentialRotationPhase { PREPARED, ATTEMPTED }
enum class CredentialCandidateSource { CURRENT, PENDING }

data class StoredCredentialRotation(
    val current: StoredTransportCredential,
    val pendingAuthToken: ByteArray,
    val phase: CredentialRotationPhase,
)

data class TransportCredentialCandidate(
    val credential: StoredTransportCredential,
    val source: CredentialCandidateSource,
)

interface TransportCredentialStore {
    fun load(): StoredTransportCredential?
    fun saveNew(credential: StoredTransportCredential)
}

interface RotatingTransportCredentialStore : TransportCredentialStore {
    fun loadRotation(): StoredCredentialRotation?
    fun loadConnectionCandidate(preferCurrentFallback: Boolean = false): TransportCredentialCandidate?
    fun prepareRotation(pendingAuthToken: ByteArray): StoredCredentialRotation
    fun markRotationAttempted(pendingAuthToken: ByteArray)
    fun promotePending(): StoredTransportCredential
}

/** Android Keystore-wrapped current/pending storage with atomic SharedPreferences metadata. */
class AndroidTransportCredentialStore(
    context: Context,
    credentialName: String = "default",
) : RotatingTransportCredentialStore {
    private val appContext = context.applicationContext
    private val safeName = credentialName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "credentialName must be 1-64 URL-safe characters"
        }
    }
    private val preferences = appContext.getSharedPreferences(
        "syncnotifications.transport.$safeName",
        Context.MODE_PRIVATE,
    )
    private val keyAlias = "syncnotifications.transport.wrap.$safeName"

    @Synchronized
    override fun load(): StoredTransportCredential? {
        val state = loadState() ?: return null
        state.pendingAuthToken?.fill(0)
        return state.current
    }

    @Synchronized
    override fun loadRotation(): StoredCredentialRotation? {
        val state = loadState() ?: return null
        val pending = state.pendingAuthToken ?: run {
            state.current.authToken.fill(0)
            return null
        }
        return StoredCredentialRotation(state.current, pending, checkNotNull(state.phase))
    }

    @Synchronized
    override fun loadConnectionCandidate(preferCurrentFallback: Boolean): TransportCredentialCandidate? {
        val state = loadState() ?: return null
        if (!preferCurrentFallback && state.phase == CredentialRotationPhase.ATTEMPTED) {
            val pending = checkNotNull(state.pendingAuthToken)
            state.current.authToken.fill(0)
            return TransportCredentialCandidate(
                state.current.copy(authToken = pending),
                CredentialCandidateSource.PENDING,
            )
        }
        state.pendingAuthToken?.fill(0)
        return TransportCredentialCandidate(state.current, CredentialCandidateSource.CURRENT)
    }

    /** Persists once and refuses implicit credential or identity replacement. */
    @Synchronized
    override fun saveNew(credential: StoredTransportCredential) {
        val canonicalOrigin = validateCredential(credential)
        loadState()?.let { existing ->
            try {
                check(existing.current.sameAs(credential)) {
                    "Transport credential already exists; explicit clear is required"
                }
                return
            } finally {
                existing.current.authToken.fill(0)
                existing.pendingAuthToken?.fill(0)
            }
        }
        val wrapped = wrap(
            credential.authToken,
            currentAad(canonicalOrigin, credential.workspaceId, credential.deviceId, credential.identityKeyId),
        )
        val stored = preferences.edit()
            .putString(KEY_SERVER_ORIGIN, canonicalOrigin)
            .putString(KEY_WORKSPACE_ID, credential.workspaceId.encodeBase64())
            .putString(KEY_DEVICE_ID, credential.deviceId.encodeBase64())
            .putString(KEY_IDENTITY_KEY_ID, credential.identityKeyId.encodeBase64())
            .putString(KEY_TOKEN_CIPHERTEXT, wrapped.ciphertext.encodeBase64())
            .putString(KEY_IV, wrapped.iv.encodeBase64())
            .commit()
        check(stored) { "Failed to persist transport credential" }
    }

    @Synchronized
    override fun prepareRotation(pendingAuthToken: ByteArray): StoredCredentialRotation {
        require(pendingAuthToken.size == DeviceAuthFrameCodecV1.AUTH_TOKEN_SIZE) {
            "pendingAuthToken must be ${DeviceAuthFrameCodecV1.AUTH_TOKEN_SIZE} bytes"
        }
        val state = checkNotNull(loadState()) { "Transport credential is not configured" }
        try {
            check(!constantTimeEquals(state.current.authToken, pendingAuthToken)) {
                "Pending credential must differ from current"
            }
            state.pendingAuthToken?.let { existing ->
                check(constantTimeEquals(existing, pendingAuthToken)) {
                    "A different pending credential already exists"
                }
                return StoredCredentialRotation(
                    state.current.copy(authToken = state.current.authToken.copyOf()),
                    existing.copyOf(),
                    checkNotNull(state.phase),
                )
            }
            val wrapped = wrap(
                pendingAuthToken,
                pendingAad(
                    state.current.serverOrigin,
                    state.current.workspaceId,
                    state.current.deviceId,
                    state.current.identityKeyId,
                ),
            )
            check(
                preferences.edit()
                    .putString(KEY_PENDING_TOKEN_CIPHERTEXT, wrapped.ciphertext.encodeBase64())
                    .putString(KEY_PENDING_IV, wrapped.iv.encodeBase64())
                    .putString(KEY_ROTATION_PHASE, CredentialRotationPhase.PREPARED.name)
                    .commit(),
            ) { "Failed to persist pending transport credential" }
            return StoredCredentialRotation(
                state.current.copy(authToken = state.current.authToken.copyOf()),
                pendingAuthToken.copyOf(),
                CredentialRotationPhase.PREPARED,
            )
        } finally {
            state.current.authToken.fill(0)
            state.pendingAuthToken?.fill(0)
        }
    }

    @Synchronized
    override fun markRotationAttempted(pendingAuthToken: ByteArray) {
        require(pendingAuthToken.size == DeviceAuthFrameCodecV1.AUTH_TOKEN_SIZE) {
            "pendingAuthToken must be ${DeviceAuthFrameCodecV1.AUTH_TOKEN_SIZE} bytes"
        }
        val state = checkNotNull(loadState()) { "Transport credential is not configured" }
        try {
            val existing = checkNotNull(state.pendingAuthToken) { "Exact pending credential is not prepared" }
            check(constantTimeEquals(existing, pendingAuthToken)) {
                "Exact pending credential is not prepared"
            }
            if (state.phase != CredentialRotationPhase.ATTEMPTED) {
                check(
                    preferences.edit()
                        .putString(KEY_ROTATION_PHASE, CredentialRotationPhase.ATTEMPTED.name)
                        .commit(),
                ) { "Failed to persist attempted rotation state" }
            }
        } finally {
            state.current.authToken.fill(0)
            state.pendingAuthToken?.fill(0)
        }
    }

    /** Called only after this exact pending credential receives canonical SNO1. */
    @Synchronized
    override fun promotePending(): StoredTransportCredential {
        val state = checkNotNull(loadState()) { "Transport credential is not configured" }
        try {
            check(state.phase == CredentialRotationPhase.ATTEMPTED) {
                "No attempted pending credential can be promoted"
            }
            val pending = checkNotNull(state.pendingAuthToken)
            val wrapped = wrap(
                pending,
                currentAad(
                    state.current.serverOrigin,
                    state.current.workspaceId,
                    state.current.deviceId,
                    state.current.identityKeyId,
                ),
            )
            check(
                preferences.edit()
                    .putString(KEY_TOKEN_CIPHERTEXT, wrapped.ciphertext.encodeBase64())
                    .putString(KEY_IV, wrapped.iv.encodeBase64())
                    .remove(KEY_PENDING_TOKEN_CIPHERTEXT)
                    .remove(KEY_PENDING_IV)
                    .remove(KEY_ROTATION_PHASE)
                    .commit(),
            ) { "Failed to promote pending transport credential" }
            return state.current.copy(authToken = pending.copyOf())
        } finally {
            state.current.authToken.fill(0)
            state.pendingAuthToken?.fill(0)
        }
    }

    /** Idempotently rebinds identity metadata; requires no credential rotation in progress. */
    @Synchronized
    fun rebindIdentityKey(
        expectedCurrentKeyId: ByteArray,
        newIdentityKeyId: ByteArray,
    ): StoredTransportCredential {
        validateNonZero(expectedCurrentKeyId, 32, "expectedCurrentKeyId")
        validateNonZero(newIdentityKeyId, 32, "newIdentityKeyId")
        check(!constantTimeEquals(expectedCurrentKeyId, newIdentityKeyId)) {
            "Transport identity rebind keys must differ"
        }
        val state = checkNotNull(loadState()) { "Transport credential is not configured" }
        try {
            if (constantTimeEquals(state.current.identityKeyId, newIdentityKeyId)) {
                return state.current.copy(
                    authToken = state.current.authToken.copyOf(),
                    identityKeyId = state.current.identityKeyId.copyOf(),
                )
            }
            check(state.pendingAuthToken == null && state.phase == null) {
                "Transport credential rotation must finish before identity promotion"
            }
            check(constantTimeEquals(state.current.identityKeyId, expectedCurrentKeyId)) {
                "Transport identity rebind binding does not match"
            }
            val wrapped = wrap(
                state.current.authToken,
                currentAad(
                    state.current.serverOrigin,
                    state.current.workspaceId,
                    state.current.deviceId,
                    newIdentityKeyId,
                ),
            )
            check(
                preferences.edit()
                    .putString(KEY_IDENTITY_KEY_ID, newIdentityKeyId.encodeBase64())
                    .putString(KEY_TOKEN_CIPHERTEXT, wrapped.ciphertext.encodeBase64())
                    .putString(KEY_IV, wrapped.iv.encodeBase64())
                    .commit(),
            ) { "Failed to rebind transport identity metadata" }
            return state.current.copy(
                authToken = state.current.authToken.copyOf(),
                identityKeyId = newIdentityKeyId.copyOf(),
            )
        } finally {
            state.current.authToken.fill(0)
            state.pendingAuthToken?.fill(0)
        }
    }

    @Synchronized
    fun clear() {
        check(preferences.edit().clear().commit()) { "Failed to clear transport preferences" }
        val keyStore = androidKeyStore()
        if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
    }

    private fun loadState(): CredentialState? {
        val currentValues = listOf(
            preferences.getString(KEY_SERVER_ORIGIN, null),
            preferences.getString(KEY_WORKSPACE_ID, null),
            preferences.getString(KEY_DEVICE_ID, null),
            preferences.getString(KEY_IDENTITY_KEY_ID, null),
            preferences.getString(KEY_TOKEN_CIPHERTEXT, null),
            preferences.getString(KEY_IV, null),
        )
        val currentPresent = currentValues.count { it != null }
        val pendingValues = listOf(
            preferences.getString(KEY_PENDING_TOKEN_CIPHERTEXT, null),
            preferences.getString(KEY_PENDING_IV, null),
            preferences.getString(KEY_ROTATION_PHASE, null),
        )
        val pendingPresent = pendingValues.count { it != null }
        if (currentPresent == 0) {
            check(pendingPresent == 0) { "Pending credential exists without current; refusing recovery" }
            return null
        }
        check(currentPresent == currentValues.size) {
            "Partial transport credential state; refusing recovery"
        }
        check(pendingPresent == 0 || pendingPresent == pendingValues.size) {
            "Partial transport rotation state; refusing recovery"
        }

        val serverOrigin = normalizeServerOrigin(currentValues[0]!!)
        val workspaceId = currentValues[1]!!.decodeBase64()
        val deviceId = currentValues[2]!!.decodeBase64()
        val identityKeyId = currentValues[3]!!.decodeBase64()
        validateMetadata(serverOrigin, workspaceId, deviceId, identityKeyId)
        val currentToken = unwrap(
            currentValues[4]!!.decodeBase64(),
            currentValues[5]!!.decodeBase64(),
            currentAad(serverOrigin, workspaceId, deviceId, identityKeyId),
        )
        var pendingToken: ByteArray? = null
        try {
            val phase = if (pendingPresent == 0) {
                null
            } else {
                pendingToken = unwrap(
                    pendingValues[0]!!.decodeBase64(),
                    pendingValues[1]!!.decodeBase64(),
                    pendingAad(serverOrigin, workspaceId, deviceId, identityKeyId),
                )
                check(!constantTimeEquals(currentToken, pendingToken!!)) {
                    "Pending credential must differ from current"
                }
                runCatching { CredentialRotationPhase.valueOf(pendingValues[2]!!) }
                    .getOrElse { error("Transport credential rotation phase is invalid") }
            }
            return CredentialState(
                StoredTransportCredential(
                    serverOrigin,
                    workspaceId,
                    deviceId,
                    currentToken,
                    identityKeyId,
                ),
                pendingToken,
                phase,
            )
        } catch (error: Throwable) {
            currentToken.fill(0)
            pendingToken?.fill(0)
            throw error
        }
    }

    private fun wrap(token: ByteArray, aad: ByteArray): WrappedSecret {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrappingKey())
        cipher.updateAAD(aad)
        return WrappedSecret(cipher.doFinal(token), cipher.iv)
    }

    private fun unwrap(ciphertext: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray {
        val key = androidKeyStore().getKey(keyAlias, null) as? SecretKey
            ?: error("Transport wrapping key is missing; refusing credential loss")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        val token = cipher.doFinal(ciphertext)
        if (token.size != DeviceAuthFrameCodecV1.AUTH_TOKEN_SIZE) {
            token.fill(0)
            error("Stored transport token has invalid length")
        }
        return token
    }

    private fun getOrCreateWrappingKey(): SecretKey {
        val keyStore = androidKeyStore()
        (keyStore.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun currentAad(
        origin: String,
        workspace: ByteArray,
        device: ByteArray,
        identity: ByteArray,
    ): ByteArray = aad(AAD_PREFIX, origin, workspace, device, identity)

    private fun pendingAad(
        origin: String,
        workspace: ByteArray,
        device: ByteArray,
        identity: ByteArray,
    ): ByteArray = aad(PENDING_AAD_PREFIX, origin, workspace, device, identity)

    private fun aad(
        prefix: ByteArray,
        origin: String,
        workspace: ByteArray,
        device: ByteArray,
        identity: ByteArray,
    ): ByteArray {
        val originBytes = origin.encodeToByteArray()
        return ByteBuffer.allocate(prefix.size + 4 + originBytes.size + 16 + 16 + 32).apply {
            put(prefix)
            putInt(originBytes.size)
            put(originBytes)
            put(workspace)
            put(device)
            put(identity)
        }.array()
    }

    private fun validateCredential(credential: StoredTransportCredential): String {
        val canonicalOrigin = normalizeServerOrigin(credential.serverOrigin)
        require(canonicalOrigin == credential.serverOrigin) { "serverOrigin must be canonical" }
        validateMetadata(
            canonicalOrigin,
            credential.workspaceId,
            credential.deviceId,
            credential.identityKeyId,
        )
        require(credential.authToken.size == DeviceAuthFrameCodecV1.AUTH_TOKEN_SIZE) {
            "authToken must be ${DeviceAuthFrameCodecV1.AUTH_TOKEN_SIZE} bytes"
        }
        return canonicalOrigin
    }

    private fun validateMetadata(origin: String, workspace: ByteArray, device: ByteArray, identity: ByteArray) {
        require(normalizeServerOrigin(origin) == origin) { "serverOrigin must be canonical" }
        validateNonZero(workspace, 16, "workspaceId")
        validateNonZero(device, 16, "deviceId")
        validateNonZero(identity, 32, "identityKeyId")
    }

    private fun validateNonZero(value: ByteArray, size: Int, name: String) {
        require(value.size == size && value.any { it != 0.toByte() }) {
            "$name must be a non-zero $size-byte value"
        }
    }

    private fun StoredTransportCredential.sameAs(other: StoredTransportCredential): Boolean =
        serverOrigin == other.serverOrigin && workspaceId.contentEquals(other.workspaceId) &&
            deviceId.contentEquals(other.deviceId) && constantTimeEquals(authToken, other.authToken) &&
            identityKeyId.contentEquals(other.identityKeyId)

    private fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean {
        if (left.size != right.size) return false
        var difference = 0
        left.indices.forEach { difference = difference or (left[it].toInt() xor right[it].toInt()) }
        return difference == 0
    }

    private fun androidKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private fun ByteArray.encodeBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)
    private fun String.decodeBase64(): ByteArray = Base64.decode(this, Base64.NO_WRAP)

    private data class CredentialState(
        val current: StoredTransportCredential,
        val pendingAuthToken: ByteArray?,
        val phase: CredentialRotationPhase?,
    )

    private data class WrappedSecret(val ciphertext: ByteArray, val iv: ByteArray)

    companion object {
        fun normalizeServerOrigin(value: String): String {
            val uri = URI(value)
            require(uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) {
                "Server URL must contain only an origin"
            }
            require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") {
                "Server URL must contain only an origin"
            }
            val scheme = uri.scheme?.lowercase() ?: error("Server URL scheme is required")
            val host = uri.host?.lowercase() ?: error("Server URL host is required")
            val loopback = host == "localhost" || host == "127.0.0.1" || host == "::1"
            require(scheme == "https" || (scheme == "http" && loopback)) {
                "Server URL must use HTTPS outside loopback"
            }
            return URI(scheme, null, host, uri.port, null, null, null).toString()
        }

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private val AAD_PREFIX = "SyncNotifications-TransportCredential-v1".encodeToByteArray()
        private val PENDING_AAD_PREFIX =
            "SyncNotifications-TransportCredential-Pending-v1".encodeToByteArray()
        private const val KEY_SERVER_ORIGIN = "server_origin"
        private const val KEY_WORKSPACE_ID = "workspace_id"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_IDENTITY_KEY_ID = "identity_key_id"
        private const val KEY_TOKEN_CIPHERTEXT = "wrapped_auth_token"
        private const val KEY_IV = "iv"
        private const val KEY_PENDING_TOKEN_CIPHERTEXT = "wrapped_pending_auth_token"
        private const val KEY_PENDING_IV = "pending_iv"
        private const val KEY_ROTATION_PHASE = "rotation_phase"
    }
}
