package dev.notificationmirroring.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Routing metadata visible to the relay and authenticated as exact HPKE AAD bytes. */
data class RoutingHeaderV1(
    val workspaceId: ByteArray,
    val senderDeviceId: ByteArray,
    val recipientDeviceId: ByteArray,
    val senderKeyId: ByteArray,
    val recipientKeyId: ByteArray,
    val messageId: ByteArray,
    val sequence: Long,
    val createdAtUnixMs: Long,
    val expiresAtUnixMs: Long,
)

object RoutingHeaderCodecV1 {
    const val ENCODED_SIZE = 160
    const val SUITE_ID = 1
    const val MAX_TTL_MILLIS = 24 * 60 * 60 * 1000L
    private val magic = byteArrayOf(0x53, 0x4e, 0x48, 0x31) // SNH1
    private const val MAX_SAFE_MILLIS = 9_007_199_254_740_991L

    /** Encodes the sole canonical 160-byte representation used directly as HPKE AAD. */
    fun encode(header: RoutingHeaderV1): ByteArray {
        validate(header)
        return ByteBuffer.allocate(ENCODED_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(magic)
            putShort(SUITE_ID.toShort())
            putShort(0)
            put(header.workspaceId)
            put(header.senderDeviceId)
            put(header.recipientDeviceId)
            put(header.senderKeyId)
            put(header.recipientKeyId)
            put(header.messageId)
            putLong(header.sequence)
            putLong(header.createdAtUnixMs)
            putLong(header.expiresAtUnixMs)
        }.array()
    }

    /**
     * Parses exact received AAD bytes. Callers must authenticate [encoded]
     * itself and must never replace it with bytes produced by re-encoding.
     */
    fun decode(encoded: ByteArray): RoutingHeaderV1 {
        require(encoded.size == ENCODED_SIZE) {
            "routing header must be $ENCODED_SIZE bytes"
        }
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        val actualMagic = ByteArray(magic.size).also(buffer::get)
        require(actualMagic.contentEquals(magic)) {
            "unsupported routing header magic/version"
        }
        require((buffer.short.toInt() and 0xffff) == SUITE_ID) {
            "unsupported E2EE suite"
        }
        require((buffer.short.toInt() and 0xffff) == 0) {
            "reserved routing flags must be zero"
        }

        val header = RoutingHeaderV1(
            workspaceId = buffer.readBytes(16),
            senderDeviceId = buffer.readBytes(16),
            recipientDeviceId = buffer.readBytes(16),
            senderKeyId = buffer.readBytes(32),
            recipientKeyId = buffer.readBytes(32),
            messageId = buffer.readBytes(16),
            sequence = buffer.long,
            createdAtUnixMs = buffer.long,
            expiresAtUnixMs = buffer.long,
        )
        validate(header)
        return header
    }

    fun validate(header: RoutingHeaderV1) {
        validateId(header.workspaceId, 16, "workspaceId")
        validateId(header.senderDeviceId, 16, "senderDeviceId")
        validateId(header.recipientDeviceId, 16, "recipientDeviceId")
        validateId(header.senderKeyId, 32, "senderKeyId")
        validateId(header.recipientKeyId, 32, "recipientKeyId")
        validateId(header.messageId, 16, "messageId")
        require(header.sequence > 0) { "sequence must be in 1..2^63-1" }
        validateTimestamp(header.createdAtUnixMs, "createdAtUnixMs")
        validateTimestamp(header.expiresAtUnixMs, "expiresAtUnixMs")
        require(header.expiresAtUnixMs > header.createdAtUnixMs) {
            "expiry must be greater than creation time"
        }
        require(header.expiresAtUnixMs - header.createdAtUnixMs <= MAX_TTL_MILLIS) {
            "routing header TTL exceeds 24 hours"
        }
    }

    private fun validateId(value: ByteArray, size: Int, name: String) {
        require(value.size == size) { "$name must be $size bytes" }
        require(value.any { it != 0.toByte() }) { "$name must not be zero" }
    }

    private fun validateTimestamp(value: Long, name: String) {
        require(value in 0..MAX_SAFE_MILLIS) { "$name must be in 0..2^53-1" }
    }

    private fun ByteBuffer.readBytes(size: Int): ByteArray = ByteArray(size).also(::get)
}
