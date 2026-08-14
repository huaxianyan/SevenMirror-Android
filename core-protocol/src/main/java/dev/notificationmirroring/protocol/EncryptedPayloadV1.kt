package dev.notificationmirroring.protocol

import com.google.protobuf.CodedInputStream
import dev.notificationmirroring.protocol.generated.v1.ActionInvoke
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultAck
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload

object EncryptedPayloadCodecV1 {
    const val SCHEMA_VERSION = 1
    const val MAX_PLAINTEXT_SIZE = 524_272
    const val MAX_NOTIFICATION_ID_BYTES = 512
    const val MAX_REPLY_TEXT_BYTES = 4_000
    const val MAX_RESULT_DETAIL_BYTES = 256
    const val IDENTIFIER_SIZE = 16
    const val SHA256_SIZE = 32
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
        validateWireFields(encoded, WireMessage.TOP_LEVEL)
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
        when (payload.bodyCase) {
            EncryptedPayload.BodyCase.ACTION_INVOKE -> validateAction(payload.actionInvoke)
            EncryptedPayload.BodyCase.ACTION_RESULT -> validateResult(payload.actionResult)
            EncryptedPayload.BodyCase.ACTION_RESULT_ACK -> validateResultAck(payload.actionResultAck)
            else -> throw IllegalArgumentException(
                "Exactly one supported encrypted payload body is required",
            )
        }
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

    private fun validateResult(result: ActionResult) {
        require(result.idempotencyKey.size() == IDENTIFIER_SIZE && result.idempotencyKey.any { it.toInt() != 0 }) {
            "Idempotency key must be a non-zero 16-byte value"
        }
        require(
            result.statusValue in
                ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED_VALUE..
                ActionResultStatus.ACTION_RESULT_STATUS_OUTCOME_UNKNOWN_VALUE,
        ) { "Action result status is unsupported" }
        if (result.hasDetail()) {
            val size = result.detail.toByteArray().size
            require(size in 1..MAX_RESULT_DETAIL_BYTES) { "Action result detail is out of range" }
        }
    }

    private fun validateResultAck(ack: ActionResultAck) {
        require(ack.idempotencyKey.size() == IDENTIFIER_SIZE && ack.idempotencyKey.any { it.toInt() != 0 }) {
            "Idempotency key must be a non-zero 16-byte value"
        }
        require(ack.resultSha256.size() == SHA256_SIZE && ack.resultSha256.any { it.toInt() != 0 }) {
            "Result SHA-256 must be a non-zero 32-byte value"
        }
    }

    // protobuf-javalite intentionally hides unknown fields. Scan the small v1
    // wire schema first so unsupported and duplicate fields fail closed.
    private fun validateWireFields(encoded: ByteArray, message: WireMessage) {
        val input = CodedInputStream.newInstance(encoded)
        var seen = 0
        while (!input.isAtEnd) {
            val tag = input.readTag()
            val bit = when (message) {
                WireMessage.TOP_LEVEL -> when (tag) {
                    8 -> { input.readUInt32(); 1 }
                    82 -> { validateWireFields(input.readByteArray(), WireMessage.ACTION_INVOKE); 2 }
                    90 -> { validateWireFields(input.readByteArray(), WireMessage.ACTION_RESULT); 4 }
                    98 -> { validateWireFields(input.readByteArray(), WireMessage.ACTION_RESULT_ACK); 8 }
                    else -> invalidWireField()
                }
                WireMessage.ACTION_INVOKE -> when (tag) {
                    10 -> { input.readByteArray(); 1 }
                    16 -> { input.readUInt64(); 2 }
                    26 -> { input.readByteArray(); 4 }
                    34 -> { input.readByteArray(); 8 }
                    42 -> { input.readByteArray(); 16 }
                    else -> invalidWireField()
                }
                WireMessage.ACTION_RESULT -> when (tag) {
                    10 -> { input.readByteArray(); 1 }
                    16 -> { input.readEnum(); 2 }
                    26 -> { input.readByteArray(); 4 }
                    else -> invalidWireField()
                }
                WireMessage.ACTION_RESULT_ACK -> when (tag) {
                    10 -> { input.readByteArray(); 1 }
                    18 -> { input.readByteArray(); 2 }
                    else -> invalidWireField()
                }
            }
            require(seen and bit == 0) { "Encrypted payload contains a duplicate field" }
            seen = seen or bit
        }
    }

    private fun invalidWireField(): Nothing =
        throw IllegalArgumentException("Encrypted payload contains an unknown field")

    private enum class WireMessage { TOP_LEVEL, ACTION_INVOKE, ACTION_RESULT, ACTION_RESULT_ACK }
}
