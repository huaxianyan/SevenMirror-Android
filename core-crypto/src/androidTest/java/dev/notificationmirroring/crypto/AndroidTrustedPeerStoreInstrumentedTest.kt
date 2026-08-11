package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidTrustedPeerStoreInstrumentedTest {
    @Test
    fun approvedPinIsImmutableUntilExplicitRemoval() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val store = AndroidTrustedPeerStore(context, "test-${UUID.randomUUID()}")
        val workspaceId = ByteArray(16) { 1 }
        val deviceId = ByteArray(16) { 2 }
        val first = AuthenticatedHpke.generateKeyPair().publicKey
        val replacement = AuthenticatedHpke.generateKeyPair().publicKey
        try {
            assertEquals(
                AndroidTrustedPeerStore.PinResult.PINNED,
                store.pinApproved(workspaceId, deviceId, first),
            )
            assertEquals(
                AndroidTrustedPeerStore.PinResult.ALREADY_PINNED,
                store.pinApproved(workspaceId, deviceId, first),
            )
            assertThrows(IllegalStateException::class.java) {
                store.pinApproved(workspaceId, deviceId, replacement)
            }
            assertArrayEquals(
                first,
                store.findApproved(workspaceId, deviceId, sha256(first)),
            )
            assertNull(store.findApproved(workspaceId, deviceId, sha256(replacement)))

            store.remove(workspaceId, deviceId)
            assertNull(store.findApproved(workspaceId, deviceId, sha256(first)))
            assertEquals(
                AndroidTrustedPeerStore.PinResult.PINNED,
                store.pinApproved(workspaceId, deviceId, replacement),
            )
        } finally {
            store.clear()
        }
    }

    @Test
    fun malformedPointIsRejectedBeforePersistence() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val store = AndroidTrustedPeerStore(context, "test-${UUID.randomUUID()}")
        val malformed = ByteArray(65).apply { this[0] = 4 }
        try {
            assertThrows(RuntimeException::class.java) {
                store.pinApproved(ByteArray(16) { 1 }, ByteArray(16) { 2 }, malformed)
            }
        } finally {
            store.clear()
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
