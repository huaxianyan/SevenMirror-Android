package dev.notificationmirroring.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class StoredHpkeIdentityRotation(
    val current: AuthenticatedHpke.KeyPair,
    val pending: AuthenticatedHpke.KeyPair,
)

/**
 * Persists current and at most one pending HPKE identity encrypted by a
 * non-exportable Android Keystore AES key. Corrupt/partial state fails closed
 * instead of rotating or replacing either identity silently.
 */
class AndroidHpkeIdentityStore(
    context: Context,
    identityName: String = "default",
) {
    private val appContext = context.applicationContext
    private val safeName = identityName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "identityName must be 1-64 URL-safe characters"
        }
    }
    private val preferences = appContext.getSharedPreferences(
        "syncnotifications.hpke.$safeName",
        Context.MODE_PRIVATE,
    )
    private val keyAlias = "syncnotifications.hpke.wrap.$safeName"

    @Synchronized
    fun loadExisting(): AuthenticatedHpke.KeyPair? {
        val state = loadState() ?: return null
        state.pending?.privateKey?.fill(0)
        return state.current
    }

    @Synchronized
    fun loadRotation(): StoredHpkeIdentityRotation? {
        val state = loadState() ?: return null
        val pending = state.pending ?: run {
            state.current.privateKey.fill(0)
            return null
        }
        return StoredHpkeIdentityRotation(state.current, pending)
    }

    @Synchronized
    fun loadOrCreate(): AuthenticatedHpke.KeyPair = loadExisting() ?: createAndPersist()

    /** Creates one pending identity without replacing current; later calls reuse it exactly. */
    @Synchronized
    fun prepareRotation(): StoredHpkeIdentityRotation {
        val state = checkNotNull(loadState()) { "HPKE identity is not configured" }
        state.pending?.let { return StoredHpkeIdentityRotation(state.current, it) }

        val pending = AuthenticatedHpke.generateKeyPair()
        check(!pending.publicKey.contentEquals(state.current.publicKey)) {
            "Pending HPKE identity must differ from current"
        }
        val wrapped = wrapPending(pending)
        check(
            preferences.edit()
                .putString(KEY_PENDING_PUBLIC, pending.publicKey.encodeBase64())
                .putString(KEY_PENDING_PRIVATE_CIPHERTEXT, wrapped.ciphertext.encodeBase64())
                .putString(KEY_PENDING_IV, wrapped.iv.encodeBase64())
                .commit(),
        ) { "Failed to persist pending HPKE identity" }
        return StoredHpkeIdentityRotation(state.current, pending)
    }

    /** Idempotently promotes the exact pending identity after a durable external journal exists. */
    @Synchronized
    fun promotePending(
        expectedCurrentKeyId: ByteArray,
        expectedPendingKeyId: ByteArray,
    ): AuthenticatedHpke.KeyPair {
        validateKeyId(expectedCurrentKeyId, "expectedCurrentKeyId")
        validateKeyId(expectedPendingKeyId, "expectedPendingKeyId")
        check(!expectedCurrentKeyId.contentEquals(expectedPendingKeyId)) {
            "Identity promotion keys must differ"
        }
        val state = checkNotNull(loadState()) { "HPKE identity is not configured" }
        val currentKeyId = sha256(state.current.publicKey)
        if (state.pending == null) {
            check(currentKeyId.contentEquals(expectedPendingKeyId)) {
                "HPKE identity has no exact pending key to promote"
            }
            return state.current
        }
        val pending = state.pending
        try {
            check(currentKeyId.contentEquals(expectedCurrentKeyId) &&
                sha256(pending.publicKey).contentEquals(expectedPendingKeyId)) {
                "HPKE identity promotion binding does not match"
            }
            val wrapped = wrap(pending.privateKey, currentAad(pending.publicKey))
            check(
                preferences.edit()
                    .putString(KEY_PUBLIC, pending.publicKey.encodeBase64())
                    .putString(KEY_PRIVATE_CIPHERTEXT, wrapped.ciphertext.encodeBase64())
                    .putString(KEY_IV, wrapped.iv.encodeBase64())
                    .remove(KEY_PENDING_PUBLIC)
                    .remove(KEY_PENDING_PRIVATE_CIPHERTEXT)
                    .remove(KEY_PENDING_IV)
                    .commit(),
            ) { "Failed to promote pending HPKE identity" }
            return AuthenticatedHpke.KeyPair(
                pending.publicKey.copyOf(),
                pending.privateKey.copyOf(),
            )
        } finally {
            state.current.privateKey.fill(0)
            pending.privateKey.fill(0)
        }
    }

    @Synchronized
    fun clear() {
        check(preferences.edit().clear().commit()) { "Failed to clear HPKE identity preferences" }
        val keyStore = androidKeyStore()
        if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
    }

    private fun loadState(): IdentityState? {
        val currentValues = listOf(
            preferences.getString(KEY_PUBLIC, null),
            preferences.getString(KEY_PRIVATE_CIPHERTEXT, null),
            preferences.getString(KEY_IV, null),
        )
        val pendingValues = listOf(
            preferences.getString(KEY_PENDING_PUBLIC, null),
            preferences.getString(KEY_PENDING_PRIVATE_CIPHERTEXT, null),
            preferences.getString(KEY_PENDING_IV, null),
        )
        val currentPresent = currentValues.count { it != null }
        val pendingPresent = pendingValues.count { it != null }
        if (currentPresent == 0) {
            check(pendingPresent == 0) { "Pending HPKE identity exists without current" }
            return null
        }
        check(currentPresent == currentValues.size) {
            "Partial HPKE identity state; refusing silent rotation"
        }
        check(pendingPresent == 0 || pendingPresent == pendingValues.size) {
            "Partial pending HPKE identity state; refusing recovery"
        }

        val currentPublic = currentValues[0]!!.decodeBase64()
        AuthenticatedHpke.requireValidPublicKey(currentPublic)
        val current = AuthenticatedHpke.KeyPair(
            currentPublic,
            decryptPrivate(
                currentPublic,
                currentValues[2]!!.decodeBase64(),
                currentValues[1]!!.decodeBase64(),
                currentAad(currentPublic),
            ),
        )
        if (pendingPresent == 0) return IdentityState(current, null)

        var pendingPrivate: ByteArray? = null
        try {
            val pendingPublic = pendingValues[0]!!.decodeBase64()
            AuthenticatedHpke.requireValidPublicKey(pendingPublic)
            check(!pendingPublic.contentEquals(currentPublic)) {
                "Pending HPKE identity must differ from current"
            }
            pendingPrivate = decryptPrivate(
                pendingPublic,
                pendingValues[2]!!.decodeBase64(),
                pendingValues[1]!!.decodeBase64(),
                pendingAad(pendingPublic),
            )
            return IdentityState(
                current,
                AuthenticatedHpke.KeyPair(pendingPublic, checkNotNull(pendingPrivate)),
            )
        } catch (error: Throwable) {
            current.privateKey.fill(0)
            pendingPrivate?.fill(0)
            throw error
        }
    }

    private fun createAndPersist(): AuthenticatedHpke.KeyPair {
        val identity = AuthenticatedHpke.generateKeyPair()
        val wrapped = wrap(identity.privateKey, currentAad(identity.publicKey))
        val stored = preferences.edit()
            .putString(KEY_PUBLIC, identity.publicKey.encodeBase64())
            .putString(KEY_PRIVATE_CIPHERTEXT, wrapped.ciphertext.encodeBase64())
            .putString(KEY_IV, wrapped.iv.encodeBase64())
            .commit()
        check(stored) { "Failed to persist wrapped HPKE identity" }
        return identity
    }

    private fun wrapPending(identity: AuthenticatedHpke.KeyPair): WrappedSecret =
        wrap(identity.privateKey, pendingAad(identity.publicKey))

    private fun wrap(privateKey: ByteArray, aad: ByteArray): WrappedSecret {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrappingKey())
        cipher.updateAAD(aad)
        return WrappedSecret(cipher.doFinal(privateKey), cipher.iv)
    }

    private fun decryptPrivate(
        publicKey: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        val keyStore = androidKeyStore()
        val key = keyStore.getKey(keyAlias, null) as? SecretKey
            ?: error("HPKE wrapping key is missing; refusing silent identity rotation")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        val privateKey = cipher.doFinal(ciphertext)
        check(privateKey.size == PRIVATE_KEY_SIZE) { "Stored HPKE private key has invalid length" }
        AuthenticatedHpke.requireValidPublicKey(publicKey)
        return privateKey
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

    private fun currentAad(publicKey: ByteArray): ByteArray = publicKey

    private fun pendingAad(publicKey: ByteArray): ByteArray =
        PENDING_AAD_DOMAIN + publicKey

    private fun validateKeyId(value: ByteArray, name: String) {
        require(value.size == 32 && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero 32-byte value"
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(value)

    private fun androidKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    private fun ByteArray.encodeBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)
    private fun String.decodeBase64(): ByteArray = Base64.decode(this, Base64.NO_WRAP)

    private data class IdentityState(
        val current: AuthenticatedHpke.KeyPair,
        val pending: AuthenticatedHpke.KeyPair?,
    )

    private data class WrappedSecret(val ciphertext: ByteArray, val iv: ByteArray)

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val PRIVATE_KEY_SIZE = 32
        const val KEY_PUBLIC = "public_key"
        const val KEY_PRIVATE_CIPHERTEXT = "wrapped_private_key"
        const val KEY_IV = "iv"
        const val KEY_PENDING_PUBLIC = "pending_public_key"
        const val KEY_PENDING_PRIVATE_CIPHERTEXT = "wrapped_pending_private_key"
        const val KEY_PENDING_IV = "pending_iv"
        val PENDING_AAD_DOMAIN = "SyncNotifications-HPKE-pending-v1\u0000".encodeToByteArray()
    }
}
