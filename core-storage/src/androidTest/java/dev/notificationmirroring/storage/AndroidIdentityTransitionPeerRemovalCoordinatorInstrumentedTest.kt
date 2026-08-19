package dev.notificationmirroring.storage

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.notificationmirroring.crypto.AndroidHpkeIdentityStore
import dev.notificationmirroring.crypto.AndroidLocalIdentityTransitionStore
import dev.notificationmirroring.crypto.AndroidTrustedPeerStore
import dev.notificationmirroring.crypto.AuthenticatedHpke
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import dev.notificationmirroring.transport.StoredTransportCredential
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidIdentityTransitionPeerRemovalCoordinatorInstrumentedTest {
    @Test
    fun recoversAfterTrustRemovalCommittedBeforeSnapshotExclusion() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val suffix = UUID.randomUUID().toString()
        val identities = AndroidHpkeIdentityStore(context, "removal-$suffix")
        val credentials = AndroidTransportCredentialStore(context, "removal-$suffix")
        val peers = AndroidTrustedPeerStore(context, "removal-$suffix")
        val transitions = AndroidLocalIdentityTransitionStore(context, "removal-$suffix")
        val workspaceId = ByteArray(16) { 1 }
        val localDeviceId = ByteArray(16) { 2 }
        val peerDeviceId = ByteArray(16) { 3 }
        val peer = AuthenticatedHpke.generateKeyPair()
        try {
            val current = identities.loadOrCreate()
            credentials.saveNew(StoredTransportCredential(
                "https://relay.example",
                workspaceId,
                localDeviceId,
                ByteArray(32) { 9 },
                sha256(current.publicKey),
            ))
            current.privateKey.fill(0)
            peers.pinApproved(workspaceId, peerDeviceId, peer.publicKey)
            AndroidIdentityTransitionInitiator(
                credentials,
                identities,
                peers,
                transitions,
                { 1_800_000_000_000L },
                object : SecureRandom() {
                    override fun nextBytes(bytes: ByteArray) = bytes.fill(4)
                },
            ).prepare()

            peers.remove(workspaceId, peerDeviceId)
            assertEquals(
                AndroidIdentityTransitionPeerRemovalCoordinator.Result.RECOVERED,
                AndroidIdentityTransitionPeerRemovalCoordinator(
                    credentials,
                    peers,
                    transitions,
                    { 1_800_000_000_001L },
                ).remove(peerDeviceId),
            )
            assertNull(transitions.loadPeer(peerDeviceId, 1_800_000_000_001L))
            assertEquals(
                AndroidLocalIdentityTransitionStore.SessionPhase.BLOCKED,
                transitions.loadSession(1_800_000_000_001L)!!.phase,
            )
        } finally {
            peer.privateKey.fill(0)
            transitions.clear()
            peers.clear()
            credentials.clear()
            identities.clear()
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
