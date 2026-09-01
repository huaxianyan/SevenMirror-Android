package dev.notificationmirroring.transport

import dev.notificationmirroring.crypto.WorkspaceMembershipTrustStore
import dev.notificationmirroring.crypto.WorkspaceMembershipV1
import java.security.MessageDigest

/**
 * Recoverably promotes one authority-approved enrollment into the write-once
 * transport credential store. The pending journal is deleted only after the
 * exact current credential can be read back.
 */
class MembershipTransportPromotionCoordinator(
    private val pendingStore: PendingAndroidMembershipStore,
    private val membershipStore: WorkspaceMembershipTrustStore,
    private val transportStore: TransportCredentialStore,
    private val nowUnixMs: () -> Long = System::currentTimeMillis,
) {
    fun promoteApproved(): StoredTransportCredential {
        val enrollment = checkNotNull(pendingStore.load()) {
            "No pending membership enrollment can be promoted"
        }
        try {
            check(enrollment.phase == PendingMembershipPhase.PENDING_APPROVAL) {
                "Membership proof is not pending approval"
            }
            val pending = enrollment.pending
            val membership = checkNotNull(membershipStore.load(pending.workspaceId, pending.deviceId)) {
                "Durable membership state is unavailable"
            }
            check(
                membership.workspaceId.contentEquals(pending.workspaceId) &&
                    membership.deviceId.contentEquals(pending.deviceId) &&
                    MessageDigest.isEqual(membership.authorityPublicKey, enrollment.authorityPublicKey),
            ) { "Durable membership state does not match the pending enrollment" }
            check(membership.localDeviceActive && membership.rosterEpoch > 0) {
                "Local device is not active in the durable workspace roster"
            }
            val signedCertificate = checkNotNull(membership.signedCertificate) {
                "Durable local device certificate is unavailable"
            }
            WorkspaceMembershipV1.requireTransportCertificateBinding(
                signedCertificate,
                enrollment.authorityPublicKey,
                pending.workspaceId,
                pending.deviceId,
                pending.identityKeyId,
                WorkspaceMembershipV1.TransportDeviceType.ANDROID,
                nowUnixMs(),
            )

            val proposed = StoredTransportCredential(
                pending.serverOrigin,
                pending.workspaceId.copyOf(),
                pending.deviceId.copyOf(),
                pending.authToken.copyOf(),
                pending.identityKeyId.copyOf(),
            )
            try {
                transportStore.saveNew(proposed)
                val durable = checkNotNull(transportStore.load()) {
                    "Transport credential disappeared during promotion"
                }
                check(durable.sameAs(proposed)) {
                    durable.authToken.fill(0)
                    "Durable transport credential does not match the approved enrollment"
                }
                pendingStore.clear()
                return durable
            } finally {
                proposed.authToken.fill(0)
            }
        } finally {
            enrollment.pending.authToken.fill(0)
            enrollment.canonicalProof?.fill(0)
        }
    }

    private fun StoredTransportCredential.sameAs(other: StoredTransportCredential): Boolean =
        serverOrigin == other.serverOrigin &&
            workspaceId.contentEquals(other.workspaceId) &&
            deviceId.contentEquals(other.deviceId) &&
            MessageDigest.isEqual(authToken, other.authToken) &&
            identityKeyId.contentEquals(other.identityKeyId)
}
