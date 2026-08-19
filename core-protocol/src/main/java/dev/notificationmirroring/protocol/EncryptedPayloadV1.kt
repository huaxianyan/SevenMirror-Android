package dev.notificationmirroring.protocol

import com.google.protobuf.CodedInputStream
import dev.notificationmirroring.protocol.generated.v1.ActionInvoke
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultAck
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransition
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionAck
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionCommit
import dev.notificationmirroring.protocol.generated.v1.NotificationRemoved
import dev.notificationmirroring.protocol.generated.v1.NotificationUpsert
import java.math.BigInteger
import java.security.MessageDigest

object EncryptedPayloadCodecV1 {
    const val SCHEMA_VERSION = 1
    const val IDENTITY_LIFECYCLE_SCHEMA_VERSION = 2
    const val NOTIFICATION_SCHEMA_VERSION = 3
    const val MAX_PLAINTEXT_SIZE = 524_272
    const val MAX_NOTIFICATION_ID_BYTES = 512
    const val MAX_NOTIFICATION_TITLE_BYTES = 512
    const val MAX_NOTIFICATION_BODY_BYTES = 4_000
    const val MAX_REPLY_TEXT_BYTES = 4_000
    const val MAX_RESULT_DETAIL_BYTES = 256
    const val IDENTIFIER_SIZE = 16
    const val SHA256_SIZE = 32
    const val P256_PUBLIC_KEY_SIZE = 65
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
        when (payload.bodyCase) {
            EncryptedPayload.BodyCase.ACTION_INVOKE -> {
                requireSchema(payload, SCHEMA_VERSION)
                validateAction(payload.actionInvoke)
            }
            EncryptedPayload.BodyCase.ACTION_RESULT -> {
                requireSchema(payload, SCHEMA_VERSION)
                validateResult(payload.actionResult)
            }
            EncryptedPayload.BodyCase.ACTION_RESULT_ACK -> {
                requireSchema(payload, SCHEMA_VERSION)
                validateResultAck(payload.actionResultAck)
            }
            EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION -> {
                requireSchema(payload, IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                validateIdentityKeyTransition(payload.identityKeyTransition)
            }
            EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_ACK -> {
                requireSchema(payload, IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                validateIdentityKeyTransitionAck(payload.identityKeyTransitionAck)
            }
            EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_COMMIT -> {
                requireSchema(payload, IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                validateIdentityKeyTransitionCommit(payload.identityKeyTransitionCommit)
            }
            EncryptedPayload.BodyCase.NOTIFICATION_UPSERT -> {
                requireSchema(payload, NOTIFICATION_SCHEMA_VERSION)
                validateNotificationUpsert(payload.notificationUpsert)
            }
            EncryptedPayload.BodyCase.NOTIFICATION_REMOVED -> {
                requireSchema(payload, NOTIFICATION_SCHEMA_VERSION)
                validateNotificationRemoved(payload.notificationRemoved)
            }
            else -> throw IllegalArgumentException(
                "Exactly one supported encrypted payload body is required",
            )
        }
    }

    private fun validateNotificationUpsert(notification: NotificationUpsert) {
        validateNotificationBinding(notification.notificationId, notification.notificationRevision)
        require(notification.hasTitle() || notification.hasBody()) {
            "Notification upsert requires title or body"
        }
        if (notification.hasTitle()) {
            validateText(notification.title, MAX_NOTIFICATION_TITLE_BYTES, "Notification title")
        }
        if (notification.hasBody()) {
            validateText(notification.body, MAX_NOTIFICATION_BODY_BYTES, "Notification body")
        }
    }

    private fun validateNotificationRemoved(notification: NotificationRemoved) {
        validateNotificationBinding(notification.notificationId, notification.notificationRevision)
    }

    private fun validateNotificationBinding(notificationId: String, revision: Long) {
        require(notificationId.isNotEmpty() && notificationId.toByteArray().size <= MAX_NOTIFICATION_ID_BYTES) {
            "Notification id is out of range"
        }
        require(revision in 1..MAX_NOTIFICATION_REVISION) {
            "Notification revision is out of range"
        }
    }

    private fun validateText(value: String, maximumBytes: Int, name: String) {
        require(value.toByteArray().size in 1..maximumBytes) { "$name is out of range" }
    }

    private fun validateAction(action: ActionInvoke) {
        validateNotificationBinding(action.notificationId, action.notificationRevision)
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

    private fun requireSchema(payload: EncryptedPayload, expected: Int) {
        require(payload.schemaVersion == expected) {
            "Encrypted payload schema version does not match body"
        }
    }

    private fun validateIdentityKeyTransition(transition: IdentityKeyTransition) {
        validateTransitionBinding(
            transition.transitionId.toByteArray(),
            transition.previousKeyId.toByteArray(),
            transition.newKeyId.toByteArray(),
        )
        val publicKey = transition.newPublicKey.toByteArray()
        validateP256PublicKey(publicKey)
        require(
            MessageDigest.getInstance("SHA-256").digest(publicKey)
                .contentEquals(transition.newKeyId.toByteArray()),
        ) { "New identity key id must equal SHA-256 of public key" }
    }

    private fun validateIdentityKeyTransitionAck(ack: IdentityKeyTransitionAck) {
        validateTransitionBinding(
            ack.transitionId.toByteArray(),
            ack.previousKeyId.toByteArray(),
            ack.newKeyId.toByteArray(),
        )
        validateNonZeroSha256(ack.transitionSha256.toByteArray(), "Transition SHA-256")
    }

    private fun validateIdentityKeyTransitionCommit(commit: IdentityKeyTransitionCommit) {
        validateTransitionBinding(
            commit.transitionId.toByteArray(),
            commit.previousKeyId.toByteArray(),
            commit.newKeyId.toByteArray(),
        )
        validateNonZeroSha256(commit.transitionSha256.toByteArray(), "Transition SHA-256")
        validateNonZeroSha256(commit.ackSha256.toByteArray(), "Transition acknowledgement SHA-256")
    }

    private fun validateTransitionBinding(
        transitionId: ByteArray,
        previousKeyId: ByteArray,
        newKeyId: ByteArray,
    ) {
        require(transitionId.size == IDENTIFIER_SIZE && transitionId.any { it.toInt() != 0 }) {
            "Transition id must be a non-zero 16-byte value"
        }
        validateNonZeroSha256(previousKeyId, "Previous identity key id")
        validateNonZeroSha256(newKeyId, "New identity key id")
        require(!previousKeyId.contentEquals(newKeyId)) {
            "New identity key must differ from previous key"
        }
    }

    private fun validateNonZeroSha256(value: ByteArray, name: String) {
        require(value.size == SHA256_SIZE && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero 32-byte value"
        }
    }

    private fun validateP256PublicKey(value: ByteArray) {
        require(value.size == P256_PUBLIC_KEY_SIZE && value[0] == 4.toByte()) {
            "New identity public key must be an uncompressed P-256 point"
        }
        val x = BigInteger(1, value.copyOfRange(1, 33))
        val y = BigInteger(1, value.copyOfRange(33, 65))
        require(
            x < P256_P && y < P256_P &&
                y.modPow(TWO, P256_P) == x.modPow(THREE, P256_P)
                .subtract(THREE.multiply(x)).add(P256_B).mod(P256_P),
        ) { "New identity public key must be a valid P-256 point" }
    }

    // protobuf-javalite intentionally hides unknown fields. Scan the small v1/v2
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
                    106 -> { validateWireFields(input.readByteArray(), WireMessage.IDENTITY_KEY_TRANSITION); 16 }
                    114 -> { validateWireFields(input.readByteArray(), WireMessage.IDENTITY_KEY_TRANSITION_ACK); 32 }
                    122 -> { validateWireFields(input.readByteArray(), WireMessage.IDENTITY_KEY_TRANSITION_COMMIT); 64 }
                    130 -> { validateWireFields(input.readByteArray(), WireMessage.NOTIFICATION_UPSERT); 128 }
                    138 -> { validateWireFields(input.readByteArray(), WireMessage.NOTIFICATION_REMOVED); 256 }
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
                WireMessage.IDENTITY_KEY_TRANSITION,
                WireMessage.IDENTITY_KEY_TRANSITION_ACK -> when (tag) {
                    10 -> { input.readByteArray(); 1 }
                    18 -> { input.readByteArray(); 2 }
                    26 -> { input.readByteArray(); 4 }
                    34 -> { input.readByteArray(); 8 }
                    else -> invalidWireField()
                }
                WireMessage.IDENTITY_KEY_TRANSITION_COMMIT -> when (tag) {
                    10 -> { input.readByteArray(); 1 }
                    18 -> { input.readByteArray(); 2 }
                    26 -> { input.readByteArray(); 4 }
                    34 -> { input.readByteArray(); 8 }
                    42 -> { input.readByteArray(); 16 }
                    else -> invalidWireField()
                }
                WireMessage.NOTIFICATION_UPSERT -> when (tag) {
                    10 -> { input.readByteArray(); 1 }
                    16 -> { input.readUInt64(); 2 }
                    26 -> { input.readByteArray(); 4 }
                    34 -> { input.readByteArray(); 8 }
                    else -> invalidWireField()
                }
                WireMessage.NOTIFICATION_REMOVED -> when (tag) {
                    10 -> { input.readByteArray(); 1 }
                    16 -> { input.readUInt64(); 2 }
                    else -> invalidWireField()
                }
            }
            require(seen and bit == 0) { "Encrypted payload contains a duplicate field" }
            seen = seen or bit
        }
    }

    private fun invalidWireField(): Nothing =
        throw IllegalArgumentException("Encrypted payload contains an unknown field")

    private enum class WireMessage {
        TOP_LEVEL,
        ACTION_INVOKE,
        ACTION_RESULT,
        ACTION_RESULT_ACK,
        IDENTITY_KEY_TRANSITION,
        IDENTITY_KEY_TRANSITION_ACK,
        IDENTITY_KEY_TRANSITION_COMMIT,
        NOTIFICATION_UPSERT,
        NOTIFICATION_REMOVED,
    }

    private val TWO = BigInteger.valueOf(2)
    private val THREE = BigInteger.valueOf(3)
    private val P256_P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val P256_B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
}
