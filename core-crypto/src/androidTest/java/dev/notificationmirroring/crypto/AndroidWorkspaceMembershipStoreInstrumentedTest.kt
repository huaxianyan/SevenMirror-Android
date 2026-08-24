package dev.notificationmirroring.crypto

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidWorkspaceMembershipStoreInstrumentedTest {
    @Test
    fun authorityCertificateAndRosterFloorSurviveReconstruction() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val vector = Vector.load(context)
        val name = "test-${UUID.randomUUID()}"
        val store = AndroidWorkspaceMembershipStore(context, name)
        var recovered: AndroidWorkspaceMembershipStore? = null
        try {
            assertEquals(
                AndroidWorkspaceMembershipStore.PinResult.PINNED,
                store.pinAuthority(vector.workspaceId, vector.deviceId, vector.authorityPublicKey),
            )
            assertEquals(
                AndroidWorkspaceMembershipStore.PinResult.ALREADY_PINNED,
                store.pinAuthority(vector.workspaceId, vector.deviceId, vector.authorityPublicKey),
            )
            assertThrows(IllegalStateException::class.java) {
                store.pinAuthority(vector.workspaceId, vector.deviceId, ByteArray(32) { 9 })
            }
            assertThrows(IllegalStateException::class.java) {
                store.reconcileApproved(
                    vector.workspaceId,
                    vector.deviceId,
                    vector.certificate,
                    vector.revokedRoster,
                )
            }
            assertEquals(
                AndroidWorkspaceMembershipStore.ReconcileResult.APPLIED,
                store.reconcileApproved(
                    vector.workspaceId,
                    vector.deviceId,
                    vector.certificate,
                    vector.initialRoster,
                ),
            )
            assertEquals(
                AndroidWorkspaceMembershipStore.ReconcileResult.ALREADY_APPLIED,
                store.reconcileApproved(
                    vector.workspaceId,
                    vector.deviceId,
                    vector.certificate,
                    vector.initialRoster,
                ),
            )
            store.close()

            recovered = AndroidWorkspaceMembershipStore(context, name)
            val initial = checkNotNull(recovered.load(vector.workspaceId, vector.deviceId))
            assertEquals(1L, initial.rosterEpoch)
            assertTrue(initial.localDeviceActive)
            assertArrayEquals(vector.authorityPublicKey, initial.authorityPublicKey)
            assertArrayEquals(vector.certificate, initial.signedCertificate)
            assertTrue(
                recovered.listNotificationRecipients(
                    vector.workspaceId,
                    vector.deviceId,
                    1_800_000_000_000,
                ).isEmpty(),
            )
            assertEquals(
                AndroidWorkspaceMembershipStore.ReconcileResult.APPLIED,
                recovered.reconcileApproved(
                    vector.workspaceId,
                    vector.deviceId,
                    vector.certificate,
                    vector.revokedRoster,
                ),
            )
            val revoked = checkNotNull(recovered.load(vector.workspaceId, vector.deviceId))
            assertEquals(2L, revoked.rosterEpoch)
            assertFalse(revoked.localDeviceActive)
            assertThrows(IllegalStateException::class.java) {
                recovered.reconcileApproved(
                    vector.workspaceId,
                    vector.deviceId,
                    vector.certificate,
                    vector.initialRoster,
                )
            }
        } finally {
            recovered?.clear()
            recovered?.close()
            runCatching { store.clear() }
            runCatching { store.close() }
        }
    }

    @Test
    fun authorityTransitionAdvancesBothRollbackFloorsAtomically() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val vector = Vector.load(context)
        val store = AndroidWorkspaceMembershipStore(context, "test-${UUID.randomUUID()}")
        try {
            store.pinAuthority(vector.workspaceId, vector.deviceId, vector.authorityPublicKey)
            store.reconcileApproved(vector.workspaceId, vector.deviceId, vector.certificate, vector.initialRoster)
            assertEquals(
                AndroidWorkspaceMembershipStore.ReconcileResult.APPLIED,
                store.reconcileAuthorityTransition(
                    vector.workspaceId, vector.deviceId, vector.authorityTransition, vector.authorityActivationRoster,
                ),
            )
            val rotated = checkNotNull(store.load(vector.workspaceId, vector.deviceId))
            assertEquals(2L, rotated.authorityEpoch)
            assertEquals(2L, rotated.rosterEpoch)
            assertTrue(rotated.localDeviceActive)
            assertArrayEquals(vector.newAuthorityPublicKey, rotated.authorityPublicKey)
            assertEquals(
                AndroidWorkspaceMembershipStore.ReconcileResult.ALREADY_APPLIED,
                store.reconcileAuthorityTransition(
                    vector.workspaceId, vector.deviceId, vector.authorityTransition, vector.authorityActivationRoster,
                ),
            )
            val differentRoster = vector.authorityActivationRoster.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }
            assertThrows(IllegalStateException::class.java) {
                store.reconcileAuthorityTransition(vector.workspaceId, vector.deviceId, vector.authorityTransition, differentRoster)
            }
            val tampered = vector.authorityTransition.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }
            assertThrows(IllegalArgumentException::class.java) {
                store.reconcileAuthorityTransition(vector.workspaceId, vector.deviceId, tampered, vector.authorityActivationRoster)
            }
            assertEquals(2L, store.load(vector.workspaceId, vector.deviceId)?.authorityEpoch)
        } finally { store.clear(); store.close() }
    }

    private data class Vector(
        val authorityPublicKey: ByteArray,
        val workspaceId: ByteArray,
        val deviceId: ByteArray,
        val certificate: ByteArray,
        val initialRoster: ByteArray,
        val revokedRoster: ByteArray,
        val newAuthorityPublicKey: ByteArray,
        val authorityTransition: ByteArray,
        val authorityActivationRoster: ByteArray,
    ) {
        companion object {
            fun load(context: Context): Vector {
                val text = context.assets.open("workspace-membership-v1.json")
                    .bufferedReader().use { it.readText() }
                fun hex(name: String): ByteArray {
                    val value = checkNotNull(
                        Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
                            .find(text)?.groupValues?.get(1),
                    )
                    return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                }
                return Vector(
                    hex("authorityPublicKeyHex"),
                    hex("workspaceIdHex"),
                    hex("deviceIdHex"),
                    hex("certificateEncodedHex"),
                    hex("initialRosterEncodedHex"),
                    hex("revokedRosterEncodedHex"),
                    hex("newAuthorityPublicKeyHex"),
                    hex("authorityTransitionEncodedHex"),
                    hex("authorityActivationRosterEncodedHex"),
                )
            }
        }
    }
}
