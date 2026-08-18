package dev.notificationmirroring.storage

import com.google.protobuf.ByteString
import dev.notificationmirroring.crypto.AndroidHpkeIdentityStore
import dev.notificationmirroring.crypto.AndroidLocalIdentityTransitionStore
import dev.notificationmirroring.crypto.AndroidTrustedPeerStore
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransition
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import java.security.MessageDigest
import java.security.SecureRandom

class IdentityTransitionPreconditionException(message: String) : IllegalStateException(message)

/** Durably prepares one exact local transition while reusing an orphaned pending identity after crash. */
class AndroidIdentityTransitionInitiator(
    private val credentials: AndroidTransportCredentialStore,
    private val identities: AndroidHpkeIdentityStore,
    private val trustedPeers: AndroidTrustedPeerStore,
    private val localTransitions: AndroidLocalIdentityTransitionStore,
    private val now: () -> Long = System::currentTimeMillis,
    private val random: SecureRandom = SecureRandom(),
) {
    @Synchronized
    fun prepare(): AndroidLocalIdentityTransitionStore.Session {
        val nowUnixMs = now()
        val credential = credentials.load()
            ?: throw IdentityTransitionPreconditionException("Transport is not configured")
        try {
            credentials.loadRotation()?.let { rotation ->
                rotation.current.authToken.fill(0)
                rotation.pendingAuthToken.fill(0)
                throw IdentityTransitionPreconditionException(
                    "Transport credential rotation must finish before identity transition",
                )
            }
            val existing = localTransitions.loadSession(nowUnixMs)
            val rotation = identities.loadRotation() ?: identities.prepareRotation()
            try {
                val currentKeyId = sha256(rotation.current.publicKey)
                val pendingKeyId = sha256(rotation.pending.publicKey)
                check(MessageDigest.isEqual(currentKeyId, credential.identityKeyId)) {
                    "Transport credential E2EE identity binding does not match current identity"
                }
                if (existing != null) {
                    check(
                        MessageDigest.isEqual(existing.workspaceId, credential.workspaceId) &&
                            MessageDigest.isEqual(existing.localDeviceId, credential.deviceId) &&
                            MessageDigest.isEqual(existing.previousKeyId, currentKeyId) &&
                            MessageDigest.isEqual(existing.newKeyId, pendingKeyId) &&
                            MessageDigest.isEqual(existing.newPublicKey, rotation.pending.publicKey),
                    ) { "Existing identity transition does not match current/pending identity slots" }
                    return existing
                }
                val peers = trustedPeers.listApproved(credential.workspaceId)
                if (peers.isEmpty()) {
                    throw IdentityTransitionPreconditionException(
                        "At least one approved peer is required",
                    )
                }
                val canonicalTransition = EncryptedPayloadCodecV1.encode(
                    EncryptedPayload.newBuilder()
                        .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                        .setIdentityKeyTransition(
                            IdentityKeyTransition.newBuilder()
                                .setTransitionId(ByteString.copyFrom(nextIdentifier()))
                                .setPreviousKeyId(ByteString.copyFrom(currentKeyId))
                                .setNewPublicKey(ByteString.copyFrom(rotation.pending.publicKey))
                                .setNewKeyId(ByteString.copyFrom(pendingKeyId)),
                        )
                        .build(),
                )
                return localTransitions.create(
                    credential.workspaceId,
                    credential.deviceId,
                    canonicalTransition,
                    peers.map { peer ->
                        AndroidLocalIdentityTransitionStore.PeerSnapshot(
                            peer.deviceId,
                            peer.keyId,
                        )
                    },
                    nowUnixMs,
                )
            } finally {
                rotation.current.privateKey.fill(0)
                rotation.pending.privateKey.fill(0)
            }
        } finally {
            credential.authToken.fill(0)
        }
    }

    private fun nextIdentifier(): ByteArray = ByteArray(16).also { value ->
        do random.nextBytes(value) while (value.all { it.toInt() == 0 })
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
