package dev.notificationmirroring.transport

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidPendingMembershipStoreInstrumentedTest {
    @Test
    fun exactWrappedEnrollmentAndPhaseSurviveReconstruction() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val vector = Vector.load(context)
        val name = "test-${UUID.randomUUID()}"
        val store = AndroidPendingMembershipStore(context, name)
        val pending = PendingAndroidMembership(
            "https://membership.example",
            vector.workspaceId,
            vector.deviceId,
            ByteArray(32) { 3 },
            vector.identityKeyId,
        )
        try {
            assertEquals(
                PendingMembershipPhase.REGISTERED,
                store.prepareRegistration(
                    pending, ByteArray(32) { 6 }, ByteArray(65) { 7 }, ByteArray(48) { 8 },
                ).phase,
            )
            store.bindProof(pending, vector.proof)
            store.markProofAttempted(pending, vector.proof)
            val recovered = AndroidPendingMembershipStore(context, name).load()!!
            assertEquals(PendingMembershipPhase.PROOF_ATTEMPTED, recovered.phase)
            assertArrayEquals(pending.authToken, recovered.pending.authToken)
            assertArrayEquals(vector.proof, recovered.canonicalProof)
            recovered.pending.authToken.fill(0)
            recovered.canonicalProof!!.fill(0)

            store.markPendingApproval(pending)
            assertEquals(PendingMembershipPhase.PENDING_APPROVAL, store.load()!!.phase)
            assertThrows(IllegalStateException::class.java) {
                store.prepareRegistration(
                    pending.copy(authToken = ByteArray(32) { 9 }),
                    ByteArray(32) { 6 }, ByteArray(65) { 7 }, ByteArray(48) { 8 },
                )
            }
        } finally {
            store.clear()
        }
    }

    private data class Vector(
        val workspaceId: ByteArray,
        val deviceId: ByteArray,
        val identityKeyId: ByteArray,
        val proof: ByteArray,
    ) {
        companion object {
            fun load(context: Context): Vector {
                val text = context.assets.open("workspace-membership-v1.json").bufferedReader().use { it.readText() }
                fun hex(name: String): ByteArray {
                    val value = checkNotNull(Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"").find(text)?.groupValues?.get(1))
                    return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                }
                return Vector(hex("workspaceIdHex"), hex("deviceIdHex"), hex("identityKeyIdHex"), hex("proofEncodedHex"))
            }
        }
    }
}
