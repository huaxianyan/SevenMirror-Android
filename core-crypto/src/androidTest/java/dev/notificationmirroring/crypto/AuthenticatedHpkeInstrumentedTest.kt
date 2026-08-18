package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.bouncycastle.crypto.InvalidCipherTextException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AuthenticatedHpkeInstrumentedTest {
    @Test
    fun keystoreWrappedIdentitySurvivesStoreRecreation() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val identityName = "instrumented-${System.nanoTime()}"
        val firstStore = AndroidHpkeIdentityStore(context, identityName)
        firstStore.clear()

        try {
            assertNull(firstStore.loadExisting())
            val first = firstStore.loadOrCreate()
            assertNotNull(firstStore.loadExisting())
            val restored = AndroidHpkeIdentityStore(context, identityName).loadOrCreate()
            assertArrayEquals(first.publicKey, restored.publicKey)
            assertArrayEquals(first.privateKey, restored.privateKey)

            val sender = AuthenticatedHpke.generateKeyPair()
            val plaintext = "restored identity".encodeToByteArray()
            val encrypted = AuthenticatedHpke.seal(
                restored.publicKey,
                sender,
                plaintext,
                "keystore-aad".encodeToByteArray(),
            )
            assertArrayEquals(
                plaintext,
                AuthenticatedHpke.open(
                    restored,
                    sender.publicKey,
                    encrypted,
                    "keystore-aad".encodeToByteArray(),
                ),
            )
        } finally {
            firstStore.clear()
        }
    }

    @Test
    fun pendingIdentitySurvivesRecreationWithoutReplacingCurrent() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val identityName = "identity-rotation-${System.nanoTime()}"
        val store = AndroidHpkeIdentityStore(context, identityName)
        store.clear()

        try {
            val current = store.loadOrCreate()
            val prepared = store.prepareRotation()
            val restored = AndroidHpkeIdentityStore(context, identityName).loadRotation()
            requireNotNull(restored)

            assertArrayEquals(current.publicKey, prepared.current.publicKey)
            assertArrayEquals(current.privateKey, prepared.current.privateKey)
            assertFalse(current.publicKey.contentEquals(prepared.pending.publicKey))
            assertArrayEquals(prepared.pending.publicKey, restored.pending.publicKey)
            assertArrayEquals(prepared.pending.privateKey, restored.pending.privateKey)
            assertArrayEquals(
                prepared.pending.publicKey,
                AndroidHpkeIdentityStore(context, identityName).prepareRotation().pending.publicKey,
            )
            assertArrayEquals(current.publicKey, store.loadExisting()!!.publicKey)

            val sender = AuthenticatedHpke.generateKeyPair()
            val plaintext = "pending identity survived process recreation".encodeToByteArray()
            val aad = "identity-transition-pending-recipient".encodeToByteArray()
            val encrypted = AuthenticatedHpke.seal(restored.pending.publicKey, sender, plaintext, aad)
            assertArrayEquals(
                plaintext,
                AuthenticatedHpke.open(restored.pending, sender.publicKey, encrypted, aad),
            )

            val preferences = context.getSharedPreferences(
                "syncnotifications.hpke.$identityName",
                android.content.Context.MODE_PRIVATE,
            )
            val storedStrings = preferences.all.values.filterIsInstance<String>()
            val rawPrivateValues = listOf(current.privateKey, restored.pending.privateKey)
                .map { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) }
            assertFalse(rawPrivateValues.any(storedStrings::contains))

            val pendingPublic = preferences.getString("pending_public_key", null)
            val pendingCiphertext = preferences.getString("wrapped_pending_private_key", null)
            val pendingIv = preferences.getString("pending_iv", null)
            check(
                preferences.edit()
                    .putString("public_key", pendingPublic)
                    .putString("wrapped_private_key", pendingCiphertext)
                    .putString("iv", pendingIv)
                    .remove("pending_public_key")
                    .remove("wrapped_pending_private_key")
                    .remove("pending_iv")
                    .commit(),
            )
            assertThrows(Exception::class.java) {
                AndroidHpkeIdentityStore(context, identityName).loadExisting()
            }
        } finally {
            store.clear()
        }
    }

    @Test
    fun partialPendingIdentityFailsClosed() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val identityName = "identity-partial-${System.nanoTime()}"
        val store = AndroidHpkeIdentityStore(context, identityName)
        store.clear()
        try {
            store.loadOrCreate()
            store.prepareRotation()
            val preferences = context.getSharedPreferences(
                "syncnotifications.hpke.$identityName",
                android.content.Context.MODE_PRIVATE,
            )
            check(preferences.edit().remove("pending_iv").commit())
            assertThrows(IllegalStateException::class.java) {
                AndroidHpkeIdentityStore(context, identityName).loadExisting()
            }
        } finally {
            store.clear()
        }
    }

    @Test
    fun authenticatedHpkeRunsOnAndroidRuntime() {
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val attacker = AuthenticatedHpke.generateKeyPair()
        val plaintext = "Android runtime HPKE payload".encodeToByteArray()
        val aad = "workspace|sender|recipient|message|sequence".encodeToByteArray()
        val encrypted = AuthenticatedHpke.seal(
            recipient.publicKey,
            sender,
            plaintext,
            aad,
        )

        assertArrayEquals(
            plaintext,
            AuthenticatedHpke.open(recipient, sender.publicKey, encrypted, aad),
        )
        assertThrows(InvalidCipherTextException::class.java) {
            AuthenticatedHpke.open(recipient, attacker.publicKey, encrypted, aad)
        }
    }
}
