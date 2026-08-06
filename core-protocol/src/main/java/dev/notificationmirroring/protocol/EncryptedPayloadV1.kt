package dev.notificationmirroring.protocol

import com.google.protobuf.CodedInputStream
import dev.notificationmirroring.protocol.generated.v1.ActionInvoke
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload

object EncryptedPayloadCodecV1 {
    const val SCHEMA_VERSION = 1
    const val MAX_PLAINTEXT_SIZE = 524_272
    const val MAX_NOTIFICATION_ID_BYTES = 512
    const val MAX_REPLY_TEXT_BYTES = 4_000
    const val IDENTIFIER_SIZE = 16
    const val MAX_NOTIFICATION_REVISION = Long.MAX_VALUE

    fun encode(payload: EncryptedPayload): ByteArray {
        validate(payload)
        val encoded = payload.toByteArray()
        require(encoded.isNotEmpty() && encoded.size <= MAX_PLAINTEXT_SIZE) {
            "Encrypted payload size is out of range"
        }
        return encoded
    }

    fun decode(encoded: ByteArray): EncryptedPayload {
        require(encoded.isNotEmpty() && encoded.size <= MAX_PLAINTEXT_SIZE) {
            "Encrypted payload size is out of range"
        }
        validateWireFields(encoded, topLevel = true)
        val payload = EncryptedPayload.parseFrom(encoded)
        validate(payload)
        require(payload.toByteArray().contentEquals(encoded)) {
            "Encrypted payload is not canonically encoded"
        }
        return payload
    }

    fun validate(payload: EncryptedPayload) {
        require(payload.schemaVersion == SCHEMA_VERSION) {
            "Unsupported encrypted payload schema version"
        }
        require(payload.bodyCase == EncryptedPayload.BodyCase.ACTION_INVOKE) {
            "Exactly one supported encrypted payload body is required"
        }
        validateAction(payload.actionInvoke)
    }

    private fun validateAction(action: ActionInvoke) {
        require(action.notificationId.isNotEmpty() && action.notificationId.toByteArray().size <= MAX_NOTIFICATION_ID_BYTES) {
            "Notification id is out of range"
        }
        require(action.notificationRevision in 1..MAX_NOTIFICATION_REVISION) {
            "Notification revision is out of range"
        }
        require(action.actionId.size() == IDENTIFIER_SIZE) { "Action id must be 16 bytes" }
        require(action.idempotencyKey.size() == IDENTIFIER_SIZE && action.idempotencyKey.any { it.toInt() != 0 }) {
            "Idempotency key must be a non-zero 16-byte value"
        }
        if (action.hasReplyText()) {
            val size = action.replyText.toByteArray().size
            require(size in 1..MAX_REPLY_TEXT_BYTES) { "Reply text is out of range" }
        }
    }

    // protobuf-javalite intentionally hides unknown fields. Scan the small v1
    // wire schema first so unsupported and duplicate fields fail closed.
    private fun validateWireFields(encoded: ByteArray, topLevel: Boolean) {
        val input = CodedInputStream.newInstance(encoded)
        var seen = 0
        while (!input.isAtEnd) {
            val tag = input.readTag()
            val bit = when {
                topLevel && tag == 8 -> {
                    input.readUInt32()
                    1
                }
                topLevel && tag == 82 -> {
                    validateWireFields(input.readByteArray(), topLevel = false)
                    2
                }
                !topLevel && tag == 10 -> {
                    input.readByteArray()
                    1
                }
                !topLevel && tag == 16 -> {
                    input.readUInt64()
                    2
                }
                !topLevel && tag == 26 -> {
                    input.readByteArray()
                    4
                }
                !topLevel && tag == 34 -> {
                    input.readByteArray()
                    8
                }
                !topLevel && tag == 42 -> {
                    input.readByteArray()
                    16
                }
                else -> throw IllegalArgumentException("Encrypted payload contains an unknown field")
            }
            require(seen and bit == 0) { "Encrypted payload contains a duplicate field" }
            seen = seen or bit
        }
    }
}
