package dev.notificationmirroring.crypto

/**
 * Bounded SPIKE-004 replay ledger. Production code must persist equivalent
 * state before applying a decrypted side effect.
 */
class ReplayGuard(private val maxEntries: Int = 4096) {
    enum class Decision { ACCEPTED, DUPLICATE, EXPIRED }

    data class Token(
        val senderKeyId: String,
        val messageId: String,
        val expiresAtUnixMs: Long,
    )

    private val seen = linkedMapOf<String, Long>()

    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
    }

    @Synchronized
    fun checkAndRecord(token: Token, nowUnixMs: Long): Decision {
        seen.entries.removeAll { it.value <= nowUnixMs }
        if (token.expiresAtUnixMs <= nowUnixMs) return Decision.EXPIRED

        val key = "${token.senderKeyId.length}:${token.senderKeyId}${token.messageId}"
        if (seen.containsKey(key)) return Decision.DUPLICATE

        while (seen.size >= maxEntries) {
            seen.remove(seen.keys.first())
        }
        seen[key] = token.expiresAtUnixMs
        return Decision.ACCEPTED
    }
}
