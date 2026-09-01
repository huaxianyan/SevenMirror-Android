package dev.notificationmirroring.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class EncryptedEnvelopeV1(
    val routingHeaderBytes: ByteArray,
    val routingHeader: RoutingHeaderV1,
    val encapsulatedKey: ByteArray,
    val ciphertext: ByteArray,
)

data class EncryptedEnvelopePartsV1(
    val routingHeader: ByteArray,
    val encapsulatedKey: ByteArray,
    val ciphertext: ByteArray,
)

object EncryptedEnvelopeCodecV1 {
    const val PREFIX_SIZE = 233
    const val ENCAPSULATED_KEY_SIZE = 65
    const val MIN_CIPHERTEXT_SIZE = 16
    const val MAX_CIPHERTEXT_SIZE = 512 * 1024
    const val MIN_FRAME_SIZE = PREFIX_SIZE + MIN_CIPHERTEXT_SIZE
    const val MAX_FRAME_SIZE = PREFIX_SIZE + MAX_CIPHERTEXT_SIZE
    private val magic = byteArrayOf(0x53, 0x4e, 0x45, 0x31) // SNE1

    fun encode(parts: EncryptedEnvelopePartsV1): ByteArray {
        validate(parts)
        return ByteBuffer.allocate(PREFIX_SIZE + parts.ciphertext.size)
            .order(ByteOrder.BIG_ENDIAN)
            .apply {
                put(magic)
                put(parts.routingHeader)
                put(parts.encapsulatedKey)
                putInt(parts.ciphertext.size)
                put(parts.ciphertext)
            }.array()
    }

    fun decode(encoded: ByteArray): EncryptedEnvelopeV1 {
        require(encoded.size in MIN_FRAME_SIZE..MAX_FRAME_SIZE) {
            "encrypted envelope must be $MIN_FRAME_SIZE..$MAX_FRAME_SIZE bytes"
        }
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        val actualMagic = buffer.readBytes(magic.size)
        require(actualMagic.contentEquals(magic)) {
            "unsupported encrypted envelope magic/version"
        }
        val routingHeaderBytes = buffer.readBytes(RoutingHeaderCodecV1.ENCODED_SIZE)
        val encapsulatedKey = buffer.readBytes(ENCAPSULATED_KEY_SIZE)
        val ciphertextSize = buffer.int
        require(ciphertextSize in MIN_CIPHERTEXT_SIZE..MAX_CIPHERTEXT_SIZE) {
            "ciphertext length is out of range"
        }
        require(buffer.remaining() == ciphertextSize) {
            "encrypted envelope length does not match ciphertext length"
        }
        val ciphertext = buffer.readBytes(ciphertextSize)
        require(encapsulatedKey[0] == 0x04.toByte()) {
            "encapsulated key must be an uncompressed P-256 point"
        }
        return EncryptedEnvelopeV1(
            routingHeaderBytes = routingHeaderBytes,
            routingHeader = RoutingHeaderCodecV1.decode(routingHeaderBytes),
            encapsulatedKey = encapsulatedKey,
            ciphertext = ciphertext,
        )
    }

    private fun validate(parts: EncryptedEnvelopePartsV1) {
        require(parts.routingHeader.size == RoutingHeaderCodecV1.ENCODED_SIZE) {
            "routing header must be ${RoutingHeaderCodecV1.ENCODED_SIZE} bytes"
        }
        RoutingHeaderCodecV1.decode(parts.routingHeader)
        require(
            parts.encapsulatedKey.size == ENCAPSULATED_KEY_SIZE &&
                parts.encapsulatedKey[0] == 0x04.toByte(),
        ) {
            "encapsulated key must be a 65-byte uncompressed P-256 point"
        }
        require(parts.ciphertext.size in MIN_CIPHERTEXT_SIZE..MAX_CIPHERTEXT_SIZE) {
            "ciphertext length is out of range"
        }
    }

    private fun ByteBuffer.readBytes(size: Int): ByteArray = ByteArray(size).also(::get)
}
