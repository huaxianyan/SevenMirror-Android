package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.bouncycastle.crypto.InvalidCipherTextException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
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
    fun retiredPendingIdentityStateFailsClosed() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val identityName = "retired-pending-${System.nanoTime()}"
        val store = AndroidHpkeIdentityStore(context, identityName)
        store.clear()
        try {
            store.loadOrCreate()
            val preferences = context.getSharedPreferences(
                "syncnotifications.hpke.$identityName",
                android.content.Context.MODE_PRIVATE,
            )
            check(preferences.edit().putString("pending_public_key", "retired").commit())
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
