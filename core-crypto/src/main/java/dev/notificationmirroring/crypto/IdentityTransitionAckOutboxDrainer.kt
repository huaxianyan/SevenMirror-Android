package dev.notificationmirroring.crypto

import java.security.MessageDigest
import java.security.SecureRandom

/** Sends exact durable transition ACK intents; local socket acceptance never deletes them. */
class IdentityTransitionAckOutboxDrainer(
    workspaceId: ByteArray,
    senderDeviceId: ByteArray,
    senderIdentity: AuthenticatedHpke.KeyPair,
    transportIdentityKeyId: ByteArray,
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
    private val senderIdentity = AuthenticatedHpke.KeyPair(
        senderIdentity.publicKey.copyOf(),
        senderIdentity.privateKey.copyOf(),
    )

    init {
        require(this.workspaceId.size == 16 && this.workspaceId.any { it.toInt() != 0 }) {
            "workspaceId must be a non-zero 16-byte value"
        }
        require(this.senderDeviceId.size == 16 && this.senderDeviceId.any { it.toInt() != 0 }) {
            "senderDeviceId must be a non-zero 16-byte value"
        }
        require(
            transportIdentityKeyId.size == 32 &&
                MessageDigest.isEqual(sha256(this.senderIdentity.publicKey), transportIdentityKeyId),
        ) { "Transport credential E2EE identity binding does not match" }
    }

    @Synchronized
    fun drainDue(
        nowUnixMs: Long,
        send: (ByteArray) -> Boolean,
    ): DrainResult {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        var accepted = 0
        var attempted = 0
        var nextWakeDelayMs: Long? = null
        trustedPeers.dueIdentityTransitionAcks(workspaceId, nowUnixMs).forEach { entry ->
            attempted += 1
            val frame = IdentityTransitionEnvelopeSender.createAck(
                IdentityTransitionEnvelopeContext(
                    workspaceId = workspaceId,
                    senderDeviceId = senderDeviceId,
                    recipientDeviceId = entry.peerDeviceId,
                    senderIdentity = senderIdentity,
                    recipientPublicKey = entry.newPublicKey,
                    messageId = nextMessageId(),
                    sequence = trustedPeers.allocateIdentityTransitionSequence(entry.newKeyId),
                    createdAtUnixMs = nowUnixMs,
                    expiresAtUnixMs = Math.addExact(nowUnixMs, ENVELOPE_TTL_MS),
                ),
                entry.canonicalAck,
            )
            val wasAccepted = try {
                send(frame)
            } finally {
                frame.fill(0)
            }
            if (!wasAccepted) return@forEach
            accepted += 1
            val delayMs = retryDelayMs(entry.ackAttemptCount)
            trustedPeers.recordIdentityTransitionAckSendAttempt(
                workspaceId = workspaceId,
                peerDeviceId = entry.peerDeviceId,
                transitionId = entry.transitionId,
                ackSha256 = entry.ackSha256,
                nextAttemptAtUnixMs = Math.addExact(nowUnixMs, delayMs),
                maximumAttempts = MAXIMUM_ATTEMPTS,
            )
            if (entry.ackAttemptCount + 1 < MAXIMUM_ATTEMPTS) {
                nextWakeDelayMs = minOf(nextWakeDelayMs ?: delayMs, delayMs)
            }
        }
        return DrainResult(accepted, attempted, nextWakeDelayMs)
    }

    private fun nextMessageId(): ByteArray = ByteArray(16).also { value ->
        do {
            random.nextBytes(value)
        } while (value.all { it.toInt() == 0 })
    }

    private fun retryDelayMs(attemptCount: Int): Long =
        (BASE_RETRY_MS shl attemptCount.coerceAtMost(3)).coerceAtMost(MAX_RETRY_MS)

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private companion object {
        const val ENVELOPE_TTL_MS = 60_000L
        const val BASE_RETRY_MS = 1_000L
        const val MAX_RETRY_MS = 8_000L
        const val MAXIMUM_ATTEMPTS = 5
    }
}
