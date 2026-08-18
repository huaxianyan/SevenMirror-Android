package dev.notificationmirroring.crypto

import java.security.MessageDigest
import java.security.SecureRandom

/** Sends exact commits with the proposed identity; socket acceptance never implies peer promotion. */
class IdentityTransitionCommitOutboxDrainer(
    workspaceId: ByteArray,
    senderDeviceId: ByteArray,
    currentIdentity: AuthenticatedHpke.KeyPair,
    pendingIdentity: AuthenticatedHpke.KeyPair?,
    transportIdentityKeyId: ByteArray,
    private val localTransitions: AndroidLocalIdentityTransitionStore,
    private val trustedPeers: AndroidTrustedPeerStore,
    private val random: SecureRandom = SecureRandom(),
) {
    data class DrainResult(
        val acceptedSends: Int,
        val attemptedEntries: Int,
        val nextWakeDelayMs: Long?,
    )

    private val workspaceId = workspaceId.copyOf()
    private val senderDeviceId = senderDeviceId.copyOf()
    private val currentIdentity = currentIdentity.copyKeyPair()
    private val pendingIdentity = pendingIdentity?.copyKeyPair()
    private val currentKeyId = sha256(this.currentIdentity.publicKey)
    private val senderIdentity = this.pendingIdentity ?: this.currentIdentity
    private val senderKeyId = sha256(senderIdentity.publicKey)

    init {
        require(this.workspaceId.size == 16 && this.workspaceId.any { it.toInt() != 0 }) {
            "workspaceId must be a non-zero 16-byte value"
        }
        require(this.senderDeviceId.size == 16 && this.senderDeviceId.any { it.toInt() != 0 }) {
            "senderDeviceId must be a non-zero 16-byte value"
        }
        require(MessageDigest.isEqual(currentKeyId, transportIdentityKeyId)) {
            "Transport credential E2EE identity binding does not match current identity"
        }
        this.pendingIdentity?.let {
            require(!MessageDigest.isEqual(currentKeyId, senderKeyId)) {
                "Pending E2EE identity must differ from current identity"
            }
        }
    }

    @Synchronized
    fun drainDue(nowUnixMs: Long, send: (ByteArray) -> Boolean): DrainResult {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        var accepted = 0
        var attempted = 0
        var nextWakeDelayMs: Long? = null
        for ((session, peer) in localTransitions.dueCommits(workspaceId, nowUnixMs)) {
            attempted += 1
            check(
                MessageDigest.isEqual(session.workspaceId, workspaceId) &&
                    MessageDigest.isEqual(session.localDeviceId, senderDeviceId) &&
                    if (pendingIdentity != null) {
                        MessageDigest.isEqual(session.previousKeyId, currentKeyId) &&
                            MessageDigest.isEqual(session.newKeyId, senderKeyId)
                    } else {
                        MessageDigest.isEqual(session.newKeyId, senderKeyId)
                    },
            ) { "Local identity transition does not match current/pending identity slots" }
            val recipientPublicKey = trustedPeers.findApproved(
                workspaceId,
                peer.deviceId,
                peer.keyId,
            ) ?: error("Identity transition commit recipient is no longer approved")
            val frame = try {
                IdentityTransitionEnvelopeSender.createCommit(
                    IdentityTransitionEnvelopeContext(
                        workspaceId = workspaceId,
                        senderDeviceId = senderDeviceId,
                        recipientDeviceId = peer.deviceId,
                        senderIdentity = senderIdentity,
                        recipientPublicKey = recipientPublicKey,
                        messageId = nextMessageId(),
                        sequence = localTransitions.allocateCommitSequence(peer.keyId),
                        createdAtUnixMs = nowUnixMs,
                        expiresAtUnixMs = Math.addExact(nowUnixMs, ENVELOPE_TTL_MS),
                    ),
                    checkNotNull(peer.canonicalCommit) {
                        "Identity transition canonical commit is missing"
                    },
                )
            } finally {
                recipientPublicKey.fill(0)
            }
            val wasAccepted = try {
                send(frame)
            } finally {
                frame.fill(0)
            }
            if (!wasAccepted) break
            accepted += 1
            val delayMs = retryDelayMs(peer.commitAttemptCount)
            localTransitions.recordCommitSendAttempt(
                peerDeviceId = peer.deviceId,
                transitionId = peer.transitionId,
                ackSha256 = checkNotNull(peer.ackSha256),
                nextAttemptAtUnixMs = Math.addExact(nowUnixMs, delayMs),
                maximumAttempts = MAXIMUM_ATTEMPTS,
            )
            if (peer.commitAttemptCount + 1 < MAXIMUM_ATTEMPTS) {
                nextWakeDelayMs = minOf(nextWakeDelayMs ?: delayMs, delayMs)
            }
        }
        return DrainResult(accepted, attempted, nextWakeDelayMs)
    }

    @Synchronized
    fun clearIdentities() {
        currentIdentity.privateKey.fill(0)
        pendingIdentity?.privateKey?.fill(0)
    }

    private fun nextMessageId(): ByteArray = ByteArray(16).also { value ->
        do {
            random.nextBytes(value)
        } while (value.all { it.toInt() == 0 })
    }

    private fun retryDelayMs(attemptCount: Int): Long =
        (BASE_RETRY_MS shl attemptCount.coerceAtMost(3)).coerceAtMost(MAX_RETRY_MS)

    private fun AuthenticatedHpke.KeyPair.copyKeyPair(): AuthenticatedHpke.KeyPair =
        AuthenticatedHpke.KeyPair(publicKey.copyOf(), privateKey.copyOf())

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private companion object {
        const val ENVELOPE_TTL_MS = 60_000L
        const val BASE_RETRY_MS = 1_000L
        const val MAX_RETRY_MS = 8_000L
        const val MAXIMUM_ATTEMPTS = 5
    }
}
