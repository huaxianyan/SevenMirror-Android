package dev.notificationmirroring.storage

import dev.notificationmirroring.crypto.AndroidLocalIdentityTransitionStore
import dev.notificationmirroring.crypto.AndroidTrustedPeerStore
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import java.security.MessageDigest

/** Removes trust first, then excludes the exact peer from the local transition snapshot. */
class AndroidIdentityTransitionPeerRemovalCoordinator(
    private val credentials: AndroidTransportCredentialStore,
    private val trustedPeers: AndroidTrustedPeerStore,
    private val localTransitions: AndroidLocalIdentityTransitionStore,
    private val now: () -> Long = System::currentTimeMillis,
) {
    enum class Result { REMOVED, RECOVERED }

    @Synchronized
    fun remove(peerDeviceId: ByteArray): Result {
        val credential = credentials.load() ?: error("Transport is not configured")
        try {
            val session = localTransitions.loadSession(now())
                ?: error("No local identity transition is active")
            check(MessageDigest.isEqual(session.workspaceId, credential.workspaceId) &&
                MessageDigest.isEqual(session.localDeviceId, credential.deviceId)) {
                "Local identity transition does not match transport registration"
            }
            val peer = localTransitions.loadPeer(peerDeviceId, now())
                ?: error("Peer is not in the active identity transition snapshot")
            check(MessageDigest.isEqual(peer.transitionId, session.transitionId)) {
                "Peer transition binding does not match active transition"
            }
            val approved = trustedPeers.listApproved(credential.workspaceId)
            val active = approved.find { candidate ->
                MessageDigest.isEqual(candidate.deviceId, peer.deviceId)
            }
            if (active != null) {
                check(MessageDigest.isEqual(active.keyId, peer.keyId)) {
                    "Approved peer key changed after identity transition snapshot"
                }
                trustedPeers.remove(credential.workspaceId, peer.deviceId)
            }
            val removed = localTransitions.removePeerFromSnapshot(
                peer.deviceId,
                peer.keyId,
                session.transitionId,
            )
            return if (removed && active != null) Result.REMOVED else Result.RECOVERED
        } finally {
            credential.authToken.fill(0)
        }
    }
}
