package dev.notificationmirroring.transport

import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import java.nio.ByteBuffer
import java.nio.ByteOrder

sealed interface RelayServerMessageV1 {
    data class OnlineEnvelope(val envelope: ByteArray) : RelayServerMessageV1
    data class Delivery(val deliveryId: Long, val envelope: ByteArray) : RelayServerMessageV1
    data class CaughtUp(val highWater: Long) : RelayServerMessageV1
    data class SnapshotRequired(val highWater: Long) : RelayServerMessageV1
}

object RelayDeliveryCodecV1 {
    const val CONTROL_SIZE = 12
    const val DELIVERY_PREFIX_SIZE = 12
    private val onlineMagic = "SNE1".toByteArray(Charsets.US_ASCII)
    private val submissionMagic = "SNQ1".toByteArray(Charsets.US_ASCII)
    private val resumeMagic = "SNC1".toByteArray(Charsets.US_ASCII)
    private val acknowledgementMagic = "SNC2".toByteArray(Charsets.US_ASCII)
    private val deliveryMagic = "SND1".toByteArray(Charsets.US_ASCII)
    private val caughtUpMagic = "SND2".toByteArray(Charsets.US_ASCII)
    private val resetMagic = "SNR1".toByteArray(Charsets.US_ASCII)

    fun encodeDurableSubmission(envelope: ByteArray): ByteArray {
        EncryptedEnvelopeCodecV1.decode(envelope)
        return ByteArray(submissionMagic.size + envelope.size).also { encoded ->
            submissionMagic.copyInto(encoded)
            envelope.copyInto(encoded, submissionMagic.size)
        }
    }

    fun encodeResume(cursor: Long): ByteArray = encodeControl(resumeMagic, cursor, true)

    fun encodeAcknowledgement(cursor: Long): ByteArray =
        encodeControl(acknowledgementMagic, cursor, false)

    fun decodeServerMessage(encoded: ByteArray): RelayServerMessageV1 {
        if (encoded.startsWith(onlineMagic)) {
            EncryptedEnvelopeCodecV1.decode(encoded)
            return RelayServerMessageV1.OnlineEnvelope(encoded.copyOf())
        }
        if (encoded.startsWith(deliveryMagic)) {
            require(encoded.size > DELIVERY_PREFIX_SIZE) {
                "Relay delivery is missing its encrypted envelope"
            }
            val deliveryId = decodeCursor(encoded, false)
            val envelope = encoded.copyOfRange(DELIVERY_PREFIX_SIZE, encoded.size)
            EncryptedEnvelopeCodecV1.decode(envelope)
            return RelayServerMessageV1.Delivery(deliveryId, envelope)
        }
        require(encoded.size == CONTROL_SIZE) { "Unsupported relay server message" }
        return when {
            encoded.startsWith(caughtUpMagic) ->
                RelayServerMessageV1.CaughtUp(decodeCursor(encoded, true))
            encoded.startsWith(resetMagic) ->
                RelayServerMessageV1.SnapshotRequired(decodeCursor(encoded, true))
            else -> throw IllegalArgumentException("Unsupported relay server message")
        }
    }

    private fun encodeControl(magic: ByteArray, cursor: Long, allowZero: Boolean): ByteArray {
        require(cursor >= 0 && (allowZero || cursor > 0)) {
            "Relay delivery cursor is out of range"
        }
        return ByteBuffer.allocate(CONTROL_SIZE)
            .order(ByteOrder.BIG_ENDIAN)
            .put(magic)
            .putLong(cursor)
            .array()
    }

    private fun decodeCursor(encoded: ByteArray, allowZero: Boolean): Long {
        val cursor = ByteBuffer.wrap(encoded, 4, java.lang.Long.BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .long
        require(cursor >= 0 && (allowZero || cursor > 0)) {
            "Relay delivery cursor is out of range"
        }
        return cursor
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
        size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
}
