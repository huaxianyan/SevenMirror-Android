package dev.notificationmirroring.transport

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidTransportCredentialStoreInstrumentedTest {
    @Test
    fun keystoreWrappedCredentialSurvivesRecreationAndRefusesReplacement() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val name = "instrumented-${System.nanoTime()}"
        val store = AndroidTransportCredentialStore(context, name)
        store.clear()
        val credential = StoredTransportCredential(
            serverOrigin = "https://notify.example",
            workspaceId = ByteArray(16) { 1 },
            deviceId = ByteArray(16) { 2 },
            authToken = ByteArray(32) { 3 },
            identityKeyId = ByteArray(32) { 4 },
        )
        try {
            store.saveNew(credential)
            val restored = AndroidTransportCredentialStore(context, name).load()
            assertArrayEquals(credential.workspaceId, restored?.workspaceId)
            assertArrayEquals(credential.deviceId, restored?.deviceId)
            assertArrayEquals(credential.authToken, restored?.authToken)
            assertArrayEquals(credential.identityKeyId, restored?.identityKeyId)

            val preferences = context.getSharedPreferences(
                "syncnotifications.transport.$name",
                Context.MODE_PRIVATE,
            )
            assertFalse(preferences.all.values.filterIsInstance<String>().any { value ->
                value == credential.authToken.toString(Charsets.ISO_8859_1) || runCatching {
                    Base64.decode(value, Base64.NO_WRAP).contentEquals(credential.authToken)
                }.getOrDefault(false)
            })
            assertThrows(IllegalStateException::class.java) {
                store.saveNew(credential.copy(authToken = ByteArray(32) { 9 }))
            }
        } finally {
            store.clear()
        }
    }
}
