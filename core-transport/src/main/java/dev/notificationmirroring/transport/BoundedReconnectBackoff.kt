package dev.notificationmirroring.transport

import kotlin.math.min
import kotlin.math.pow

/** Jittered exponential delay bounded to prevent both retry storms and unbounded outages. */
class BoundedReconnectBackoff(
    private val initialDelayMs: Long = 1_000L,
    private val maximumDelayMs: Long = 60_000L,
    private val multiplier: Double = 2.0,
    private val jitterRatio: Double = 0.2,
    private val random: () -> Double = Math::random,
) {
    private var attempt = 0

    init {
        require(initialDelayMs > 0) { "initialDelayMs must be positive" }
        require(maximumDelayMs >= initialDelayMs) {
            "maximumDelayMs must not be less than initialDelayMs"
        }
        require(multiplier >= 1.0 && multiplier.isFinite()) {
            "multiplier must be finite and at least one"
        }
        require(jitterRatio in 0.0..1.0 && jitterRatio.isFinite()) {
            "jitterRatio must be finite and between zero and one"
        }
    }

    @Synchronized
    fun nextDelayMs(): Long {
        val base = min(
            maximumDelayMs.toDouble(),
            initialDelayMs.toDouble() * multiplier.pow(attempt.toDouble()),
        )
        if (attempt < MAX_EXPONENT) attempt += 1
        val sample = random()
        require(sample in 0.0..1.0 && sample.isFinite()) {
            "random must return a finite value between zero and one"
        }
        val jitter = base * jitterRatio * ((sample * 2.0) - 1.0)
        return (base + jitter).coerceIn(0.0, maximumDelayMs.toDouble()).toLong()
    }

    @Synchronized
    fun reset() {
        attempt = 0
    }

    private companion object {
        const val MAX_EXPONENT = 62
    }
}
