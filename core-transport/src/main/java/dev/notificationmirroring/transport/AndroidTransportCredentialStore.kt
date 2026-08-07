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

interface TransportCredentialStore {
    fun load(): StoredTransportCredential?
    fun saveNew(credential: StoredTransportCredential)
}

/** Android Keystore-wrapped storage for the raw WebSocket bearer credential. */
class AndroidTransportCredentialStore(
    context: Context,
    credentialName: String = "default",
) : TransportCredentialStore {
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
        val values = listOf(
            preferences.getString(KEY_SERVER_ORIGIN, null),
            preferences.getString(KEY_WORKSPACE_ID, null),
            preferences.getString(KEY_DEVICE_ID, null),
            preferences.getString(KEY_IDENTITY_KEY_ID, null),
            preferences.getString(KEY_TOKEN_CIPHERTEXT, null),
            preferences.getString(KEY_IV, null),
        )
        val present = values.count { it != null }
        if (present == 0) return null
        check(present == values.size) { "Partial transport credential state; refusing recovery" }

        val serverOrigin = normalizeServerOrigin(values[0]!!)
        val workspaceId = values[1]!!.decodeBase64()
        val deviceId = values[2]!!.decodeBase64()
        val identityKeyId = values[3]!!.decodeBase64()
        val ciphertext = values[4]!!.decodeBase64()
        val iv = values[5]!!.decodeBase64()
        validateMetadata(serverOrigin, workspaceId, deviceId, identityKeyId)
        val keyStore = androidKeyStore()
        val key = keyStore.getKey(keyAlias, null) as? SecretKey
            ?: error("Transport wrapping key is missing; refusing credential loss")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad(serverOrigin, workspaceId, deviceId, identityKeyId))
        val token = cipher.doFinal(ciphertext)
        require(token.size == DeviceAuthFrameCodecV1.AUTH_TOKEN_SIZE) {
            "Stored transport token has invalid length"
        }
        return StoredTransportCredential(serverOrigin, workspaceId, deviceId, token, identityKeyId)
    }

    /** Persists once and refuses implicit credential or identity replacement. */
    @Synchronized
    override fun saveNew(credential: StoredTransportCredential) {
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
        load()?.let { existing ->
            check(existing.sameAs(credential)) {
                "Transport credential already exists; explicit clear is required"
            }
            return
        }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrappingKey())
        cipher.updateAAD(
            aad(canonicalOrigin, credential.workspaceId, credential.deviceId, credential.identityKeyId),
        )
        val ciphertext = cipher.doFinal(credential.authToken)
        val stored = preferences.edit()
            .putString(KEY_SERVER_ORIGIN, canonicalOrigin)
            .putString(KEY_WORKSPACE_ID, credential.workspaceId.encodeBase64())
            .putString(KEY_DEVICE_ID, credential.deviceId.encodeBase64())
            .putString(KEY_IDENTITY_KEY_ID, credential.identityKeyId.encodeBase64())
            .putString(KEY_TOKEN_CIPHERTEXT, ciphertext.encodeBase64())
            .putString(KEY_IV, cipher.iv.encodeBase64())
            .commit()
        check(stored) { "Failed to persist transport credential" }
    }

    @Synchronized
    fun clear() {
        check(preferences.edit().clear().commit()) { "Failed to clear transport preferences" }
        val keyStore = androidKeyStore()
        if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
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

    private fun aad(origin: String, workspace: ByteArray, device: ByteArray, identity: ByteArray): ByteArray {
        val originBytes = origin.encodeToByteArray()
        return ByteBuffer.allocate(AAD_PREFIX.size + 4 + originBytes.size + 16 + 16 + 32).apply {
            put(AAD_PREFIX)
            putInt(originBytes.size)
            put(originBytes)
            put(workspace)
            put(device)
            put(identity)
        }.array()
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
            deviceId.contentEquals(other.deviceId) && authToken.contentEquals(other.authToken) &&
            identityKeyId.contentEquals(other.identityKeyId)

    private fun androidKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private fun ByteArray.encodeBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)
    private fun String.decodeBase64(): ByteArray = Base64.decode(this, Base64.NO_WRAP)

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
        private const val KEY_SERVER_ORIGIN = "server_origin"
        private const val KEY_WORKSPACE_ID = "workspace_id"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_IDENTITY_KEY_ID = "identity_key_id"
        private const val KEY_TOKEN_CIPHERTEXT = "wrapped_auth_token"
        private const val KEY_IV = "iv"
    }
}
