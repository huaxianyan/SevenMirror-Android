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

/** Persists the HPKE identity encrypted by a non-exportable Android Keystore AES key. */
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
        checkNoRetiredPendingIdentity()
        val values = listOf(
            preferences.getString(KEY_PUBLIC, null),
            preferences.getString(KEY_PRIVATE_CIPHERTEXT, null),
            preferences.getString(KEY_IV, null),
        )
        val present = values.count { it != null }
        if (present == 0) return null
        check(present == values.size) { "Partial HPKE identity state; refusing silent replacement" }

        val publicKey = values[0]!!.decodeBase64()
        AuthenticatedHpke.requireValidPublicKey(publicKey)
        return AuthenticatedHpke.KeyPair(
            publicKey,
            decryptPrivate(
                publicKey,
                values[2]!!.decodeBase64(),
                values[1]!!.decodeBase64(),
            ),
        )
    }

    @Synchronized
    fun loadOrCreate(): AuthenticatedHpke.KeyPair = loadExisting() ?: createAndPersist()

    @Synchronized
    fun clear() {
        check(preferences.edit().clear().commit()) { "Failed to clear HPKE identity preferences" }
        val keyStore = androidKeyStore()
        if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
    }

    private fun checkNoRetiredPendingIdentity() {
        val pendingPresent = listOf(
            preferences.getString(KEY_PENDING_PUBLIC, null),
            preferences.getString(KEY_PENDING_PRIVATE_CIPHERTEXT, null),
            preferences.getString(KEY_PENDING_IV, null),
        ).count { it != null }
        check(pendingPresent == 0) {
            "Retired pending HPKE identity state requires administrator revocation and re-enrollment"
        }
    }

    private fun createAndPersist(): AuthenticatedHpke.KeyPair {
        val identity = AuthenticatedHpke.generateKeyPair()
        val wrapped = wrap(identity.privateKey, identity.publicKey)
        check(
            preferences.edit()
                .putString(KEY_PUBLIC, identity.publicKey.encodeBase64())
                .putString(KEY_PRIVATE_CIPHERTEXT, wrapped.ciphertext.encodeBase64())
                .putString(KEY_IV, wrapped.iv.encodeBase64())
                .commit(),
        ) { "Failed to persist wrapped HPKE identity" }
        return identity
    }

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
    ): ByteArray {
        val key = androidKeyStore().getKey(keyAlias, null) as? SecretKey
            ?: error("HPKE wrapping key is missing; refusing silent identity replacement")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(publicKey)
        val privateKey = cipher.doFinal(ciphertext)
        check(privateKey.size == PRIVATE_KEY_SIZE) { "Stored HPKE private key has invalid length" }
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

    private fun androidKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    private fun ByteArray.encodeBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)
    private fun String.decodeBase64(): ByteArray = Base64.decode(this, Base64.NO_WRAP)

    private data class WrappedSecret(val ciphertext: ByteArray, val iv: ByteArray)

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val PRIVATE_KEY_SIZE = 32
        const val KEY_PUBLIC = "public_key"
        const val KEY_PRIVATE_CIPHERTEXT = "wrapped_private_key"
        const val KEY_IV = "iv"

        // Read-only compatibility sentinels. These persisted names remain frozen.
        const val KEY_PENDING_PUBLIC = "pending_public_key"
        const val KEY_PENDING_PRIVATE_CIPHERTEXT = "wrapped_pending_private_key"
        const val KEY_PENDING_IV = "pending_iv"
    }
}
