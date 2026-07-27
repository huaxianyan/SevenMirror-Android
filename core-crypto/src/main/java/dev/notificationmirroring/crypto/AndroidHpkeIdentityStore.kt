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

/**
 * Persists HPKE identity material encrypted by a non-exportable Android
 * Keystore AES key. Corrupt/partial state fails closed instead of rotating the
 * identity silently.
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
    fun loadOrCreate(): AuthenticatedHpke.KeyPair {
        val publicEncoded = preferences.getString(KEY_PUBLIC, null)
        val privateCiphertextEncoded = preferences.getString(KEY_PRIVATE_CIPHERTEXT, null)
        val ivEncoded = preferences.getString(KEY_IV, null)
        val presentCount = listOf(publicEncoded, privateCiphertextEncoded, ivEncoded).count { it != null }

        if (presentCount == 0) return createAndPersist()
        check(presentCount == 3) { "Partial HPKE identity state; refusing silent rotation" }

        val publicKey = publicEncoded!!.decodeBase64()
        val privateCiphertext = privateCiphertextEncoded!!.decodeBase64()
        val iv = ivEncoded!!.decodeBase64()
        val privateKey = decryptPrivate(publicKey, iv, privateCiphertext)
        return AuthenticatedHpke.KeyPair(publicKey, privateKey)
    }

    @Synchronized
    fun clear() {
        check(preferences.edit().clear().commit()) { "Failed to clear HPKE identity preferences" }
        val keyStore = androidKeyStore()
        if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
    }

    private fun createAndPersist(): AuthenticatedHpke.KeyPair {
        val identity = AuthenticatedHpke.generateKeyPair()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrappingKey())
        cipher.updateAAD(identity.publicKey)
        val privateCiphertext = cipher.doFinal(identity.privateKey)

        val stored = preferences.edit()
            .putString(KEY_PUBLIC, identity.publicKey.encodeBase64())
            .putString(KEY_PRIVATE_CIPHERTEXT, privateCiphertext.encodeBase64())
            .putString(KEY_IV, cipher.iv.encodeBase64())
            .commit()
        check(stored) { "Failed to persist wrapped HPKE identity" }
        return identity
    }

    private fun decryptPrivate(
        publicKey: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val keyStore = androidKeyStore()
        val key = keyStore.getKey(keyAlias, null) as? SecretKey
            ?: error("HPKE wrapping key is missing; refusing silent identity rotation")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(publicKey)
        return cipher.doFinal(ciphertext)
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

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val KEY_PUBLIC = "public_key"
        const val KEY_PRIVATE_CIPHERTEXT = "wrapped_private_key"
        const val KEY_IV = "iv"
    }
}
