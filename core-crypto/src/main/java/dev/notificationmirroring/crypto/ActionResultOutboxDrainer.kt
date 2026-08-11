package dev.notificationmirroring.crypto

import java.security.SecureRandom

/** Encrypts due durable results for their still-approved recipient and performs bounded sends. */
class ActionResultOutboxDrainer(
    workspaceId: ByteArray,
    senderDeviceId: ByteArray,
    senderIdentity: AuthenticatedHpke.KeyPair,
    private val trustedPeers: AndroidTrustedPeerStore,
    private val outbox: AndroidActionResultOutbox,
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
        AuthenticatedHpke.requireValidPublicKey(this.senderIdentity.publicKey)
    }

    /**
     * [send] returning true means only that the authenticated WebSocket accepted the frame locally.
     * It does not acknowledge Chrome reconciliation, so the durable entry remains for retries.
     */
    @Synchronized
    fun drainDue(
        nowUnixMs: Long,
        send: (ByteArray) -> Boolean,
    ): DrainResult {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        var accepted = 0
        var attempted = 0
        var nextWakeDelayMs: Long? = null
        outbox.due(nowUnixMs).forEach { entry ->
            val recipientPublicKey = trustedPeers.findApproved(
                workspaceId = workspaceId,
                deviceId = entry.recipientDeviceId,
                keyId = entry.recipientKeyId,
            ) ?: return@forEach // Revocation must immediately prevent further encryption.
            attempted += 1
            val frame = ActionResultEnvelopeSender.create(
                ActionResultEnvelopeContext(
                    workspaceId = workspaceId,
                    senderDeviceId = senderDeviceId,
                    recipientDeviceId = entry.recipientDeviceId,
                    senderIdentity = senderIdentity,
                    recipientPublicKey = recipientPublicKey,
                    messageId = nextMessageId(),
                    sequence = outbox.allocateSequence(entry.recipientKeyId),
                    createdAtUnixMs = nowUnixMs,
                    expiresAtUnixMs = Math.addExact(nowUnixMs, ENVELOPE_TTL_MS),
                ),
                entry.resultPayload,
            )
            val wasAccepted = try {
                send(frame)
            } finally {
                frame.fill(0)
                recipientPublicKey.fill(0)
            }
            if (wasAccepted) {
                accepted += 1
                val delayMs = retryDelayMs(entry.attemptCount)
                outbox.recordSendAttempt(
                    rowId = entry.rowId,
                    nextAttemptAtUnixMs = Math.addExact(nowUnixMs, delayMs),
                    maximumAttempts = MAXIMUM_ATTEMPTS,
                )
                if (entry.attemptCount + 1 < MAXIMUM_ATTEMPTS) {
                    nextWakeDelayMs = minOf(nextWakeDelayMs ?: delayMs, delayMs)
                }
            }
        }
        return DrainResult(
            acceptedSends = accepted,
            attemptedEntries = attempted,
            nextWakeDelayMs = nextWakeDelayMs,
        )
    }

    private fun nextMessageId(): ByteArray = ByteArray(16).also { value ->
        do {
            random.nextBytes(value)
        } while (value.all { it.toInt() == 0 })
    }

    private fun retryDelayMs(completedAttempts: Int): Long =
        (BASE_RETRY_MS shl completedAttempts.coerceAtMost(6)).coerceAtMost(MAX_RETRY_MS)

    private companion object {
        const val ENVELOPE_TTL_MS = 5 * 60 * 1000L
        const val BASE_RETRY_MS = 1_000L
        const val MAX_RETRY_MS = 60_000L
        const val MAXIMUM_ATTEMPTS = 5
    }
}
