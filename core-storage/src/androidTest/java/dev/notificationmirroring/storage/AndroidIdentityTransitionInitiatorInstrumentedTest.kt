package dev.notificationmirroring.storage

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.notificationmirroring.crypto.AndroidHpkeIdentityStore
import dev.notificationmirroring.crypto.AndroidLocalIdentityTransitionStore
import dev.notificationmirroring.crypto.AndroidTrustedPeerStore
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import dev.notificationmirroring.transport.StoredTransportCredential
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidIdentityTransitionInitiatorInstrumentedTest {
    @Test
    fun reusesExactPendingAndSessionAfterProcessStyleReconstruction() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val suffix = UUID.randomUUID().toString()
        val identities = AndroidHpkeIdentityStore(context, "initiator-$suffix")
        val credentials = AndroidTransportCredentialStore(context, "initiator-$suffix")
        val peers = AndroidTrustedPeerStore(context, "initiator-$suffix")
        val transitions = AndroidLocalIdentityTransitionStore(context, "initiator-$suffix")
        val workspaceId = ByteArray(16) { 1 }
        val deviceId = ByteArray(16) { 2 }
        val peerDeviceId = ByteArray(16) { 3 }
        val peer = dev.notificationmirroring.crypto.AuthenticatedHpke.generateKeyPair()
        try {
            val current = identities.loadOrCreate()
            credentials.saveNew(
                StoredTransportCredential(
                    "https://relay.example",
                    workspaceId,
                    deviceId,
                    ByteArray(32) { 9 },
                    sha256(current.publicKey),
                ),
            )
            current.privateKey.fill(0)
            peers.pinApproved(workspaceId, peerDeviceId, peer.publicKey)
            var next = 4
            fun initiator() = AndroidIdentityTransitionInitiator(
                credentials,
                identities,
                peers,
                transitions,
                { 1_800_000_000_000L },
                object : SecureRandom() {
                    override fun nextBytes(bytes: ByteArray) = bytes.fill(next++.toByte())
                },
            )
            val first = initiator().prepare()
            val recovered = AndroidIdentityTransitionInitiator(
                AndroidTransportCredentialStore(context, "initiator-$suffix"),
                AndroidHpkeIdentityStore(context, "initiator-$suffix"),
                AndroidTrustedPeerStore(context, "initiator-$suffix"),
                AndroidLocalIdentityTransitionStore(context, "initiator-$suffix"),
                { 1_800_000_000_001L },
                object : SecureRandom() {
                    override fun nextBytes(bytes: ByteArray) = bytes.fill(next++.toByte())
                },
            ).prepare()
            assertArrayEquals(first.transitionId, recovered.transitionId)
            assertArrayEquals(first.canonicalTransition, recovered.canonicalTransition)
            assertArrayEquals(first.newKeyId, recovered.newKeyId)
            assertEquals(5, next)
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
