package dev.notificationmirroring.protocol

import com.google.protobuf.ByteString
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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class EncryptedPayloadV1Test {
    private val vector = Vector.load()
    private val identityVector = IdentityVector.load()

    @Test
    fun matchesCanonicalCrossPlatformVector() {
        val encoded = EncryptedPayloadCodecV1.encode(validPayload())
        assertArrayEquals(vector.encoded, encoded)
        val decoded = EncryptedPayloadCodecV1.decode(encoded)
        assertEquals(7L, decoded.actionInvoke.notificationRevision)
        assertEquals("acknowledged", decoded.actionInvoke.replyText)
    }

    @Test
    fun roundTripsCanonicalActionResult() {
        val encoded = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(1)
                .setActionResult(
                    ActionResult.newBuilder()
                        .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { 0xb2.toByte() }))
                        .setStatus(ActionResultStatus.ACTION_RESULT_STATUS_STALE_NOTIFICATION_VERSION)
                        .setDetail("revision changed"),
                )
                .build(),
        )
        assertArrayEquals(vector.actionResultEncoded, encoded)
        val decoded = EncryptedPayloadCodecV1.decode(encoded)
        assertEquals(
            ActionResultStatus.ACTION_RESULT_STATUS_STALE_NOTIFICATION_VERSION,
            decoded.actionResult.status,
        )
    }

    @Test
    fun roundTripsCanonicalActionResultAck() {
        val payload = EncryptedPayload.newBuilder()
            .setSchemaVersion(1)
            .setActionResultAck(
                ActionResultAck.newBuilder()
                    .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { 0xb2.toByte() }))
                    .setResultSha256(ByteString.copyFrom(vector.actionResultSha256)),
            )
            .build()
        val encoded = EncryptedPayloadCodecV1.encode(payload)
        assertArrayEquals(vector.actionResultAckEncoded, encoded)
        assertArrayEquals(
            vector.actionResultSha256,
            EncryptedPayloadCodecV1.decode(encoded).actionResultAck.resultSha256.toByteArray(),
        )

        assertThrows(IllegalArgumentException::class.java) {
            EncryptedPayloadCodecV1.encode(
                payload.toBuilder()
                    .setActionResultAck(
                        payload.actionResultAck.toBuilder().setResultSha256(
                            ByteString.copyFrom(ByteArray(32)),
                        ),
                    )
                    .build(),
            )
        }
    }

    @Test
    fun matchesCanonicalNotificationVectors() {
        val upsert = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
            .setNotificationUpsert(
                NotificationUpsert.newBuilder()
                    .setNotificationId(vector.notificationPayloadId)
                    .setNotificationRevision(vector.notificationUpsertRevision)
                    .setTitle(vector.notificationTitle)
                    .setBody(vector.notificationBody),
            )
            .build()
        assertArrayEquals(vector.notificationUpsertEncoded, EncryptedPayloadCodecV1.encode(upsert))
        assertEquals(
            EncryptedPayload.BodyCase.NOTIFICATION_UPSERT,
            EncryptedPayloadCodecV1.decode(vector.notificationUpsertEncoded).bodyCase,
        )

        val removed = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
            .setNotificationRemoved(
                NotificationRemoved.newBuilder()
                    .setNotificationId(vector.notificationPayloadId)
                    .setNotificationRevision(vector.notificationRemovedRevision),
            )
            .build()
        assertArrayEquals(vector.notificationRemovedEncoded, EncryptedPayloadCodecV1.encode(removed))
        assertEquals(
            EncryptedPayload.BodyCase.NOTIFICATION_REMOVED,
            EncryptedPayloadCodecV1.decode(vector.notificationRemovedEncoded).bodyCase,
        )
    }

    @Test
    fun rejectsInvalidNotificationFieldsAndSchema() {
        val valid = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
            .setNotificationUpsert(
                NotificationUpsert.newBuilder()
                    .setNotificationId(vector.notificationPayloadId)
                    .setNotificationRevision(vector.notificationUpsertRevision)
                    .setTitle(vector.notificationTitle),
            )
            .build()
        listOf(
            valid.toBuilder().setSchemaVersion(1).build(),
            valid.toBuilder().setNotificationUpsert(
                valid.notificationUpsert.toBuilder().clearNotificationId(),
            ).build(),
            valid.toBuilder().setNotificationUpsert(
                valid.notificationUpsert.toBuilder().setNotificationRevision(0),
            ).build(),
            valid.toBuilder().setNotificationUpsert(
                valid.notificationUpsert.toBuilder().clearTitle(),
            ).build(),
            valid.toBuilder().setNotificationUpsert(
                valid.notificationUpsert.toBuilder().setTitle(""),
            ).build(),
        ).forEach { invalid ->
            assertThrows(IllegalArgumentException::class.java) {
                EncryptedPayloadCodecV1.encode(invalid)
            }
        }
    }

    @Test
    fun matchesCanonicalIdentityKeyTransitionVector() {
        val transition = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
            .setIdentityKeyTransition(
                IdentityKeyTransition.newBuilder()
                    .setTransitionId(ByteString.copyFrom(identityVector.transitionId))
                    .setPreviousKeyId(ByteString.copyFrom(identityVector.previousKeyId))
                    .setNewPublicKey(ByteString.copyFrom(identityVector.newPublicKey))
                    .setNewKeyId(ByteString.copyFrom(identityVector.newKeyId)),
            )
            .build()
        assertArrayEquals(identityVector.transitionEncoded, EncryptedPayloadCodecV1.encode(transition))
        EncryptedPayloadCodecV1.decode(identityVector.transitionEncoded)

        val ack = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
            .setIdentityKeyTransitionAck(
                IdentityKeyTransitionAck.newBuilder()
                    .setTransitionId(ByteString.copyFrom(identityVector.transitionId))
                    .setPreviousKeyId(ByteString.copyFrom(identityVector.previousKeyId))
                    .setNewKeyId(ByteString.copyFrom(identityVector.newKeyId))
                    .setTransitionSha256(ByteString.copyFrom(identityVector.transitionSha256)),
            )
            .build()
        assertArrayEquals(identityVector.ackEncoded, EncryptedPayloadCodecV1.encode(ack))

        val commit = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
            .setIdentityKeyTransitionCommit(
                IdentityKeyTransitionCommit.newBuilder()
                    .setTransitionId(ByteString.copyFrom(identityVector.transitionId))
                    .setPreviousKeyId(ByteString.copyFrom(identityVector.previousKeyId))
                    .setNewKeyId(ByteString.copyFrom(identityVector.newKeyId))
                    .setTransitionSha256(ByteString.copyFrom(identityVector.transitionSha256))
                    .setAckSha256(ByteString.copyFrom(identityVector.ackSha256)),
            )
            .build()
        assertArrayEquals(identityVector.commitEncoded, EncryptedPayloadCodecV1.encode(commit))
    }

    @Test
    fun rejectsInvalidIdentityTransitionAndSchemaMismatch() {
        val valid = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
            .setIdentityKeyTransition(
                IdentityKeyTransition.newBuilder()
                    .setTransitionId(ByteString.copyFrom(identityVector.transitionId))
                    .setPreviousKeyId(ByteString.copyFrom(identityVector.previousKeyId))
                    .setNewPublicKey(ByteString.copyFrom(identityVector.newPublicKey))
                    .setNewKeyId(ByteString.copyFrom(identityVector.newKeyId)),
            )
            .build()
        listOf(
            valid.toBuilder().setSchemaVersion(1).build(),
            valid.toBuilder().setIdentityKeyTransition(
                valid.identityKeyTransition.toBuilder().setTransitionId(ByteString.copyFrom(ByteArray(16))),
            ).build(),
            valid.toBuilder().setIdentityKeyTransition(
                valid.identityKeyTransition.toBuilder().setNewKeyId(valid.identityKeyTransition.previousKeyId),
            ).build(),
            valid.toBuilder().setIdentityKeyTransition(
                valid.identityKeyTransition.toBuilder().setNewPublicKey(
                    ByteString.copyFrom(identityVector.newPublicKey.copyOf().also { it[0] = 5 }),
                ),
            ).build(),
            valid.toBuilder().setIdentityKeyTransition(
                valid.identityKeyTransition.toBuilder().setNewKeyId(
                    ByteString.copyFrom(identityVector.newKeyId.copyOf().also { it[0] = (it[0].toInt() xor 0xff).toByte() }),
                ),
            ).build(),
        ).forEach { invalid ->
            assertThrows(IllegalArgumentException::class.java) {
                EncryptedPayloadCodecV1.encode(invalid)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            EncryptedPayloadCodecV1.encode(validPayload().toBuilder().setSchemaVersion(2).build())
        }
    }

    @Test
    fun rejectsDuplicateUnknownAndInvalidSemanticFields() {
        val valid = vector.encoded
        listOf(
            byteArrayOf(8, 1) + valid,
            valid + byteArrayOf(0x78, 1),
        ).forEach {
            assertThrows(IllegalArgumentException::class.java) {
                EncryptedPayloadCodecV1.decode(it)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            EncryptedPayloadCodecV1.encode(
                validPayload().toBuilder()
                    .setActionInvoke(validPayload().actionInvoke.toBuilder().setNotificationRevision(0))
                    .build(),
            )
        }
    }

    private fun validPayload(): EncryptedPayload = EncryptedPayload.newBuilder()
        .setSchemaVersion(1)
        .setActionInvoke(
            ActionInvoke.newBuilder()
                .setNotificationId("test.notification/42")
                .setNotificationRevision(7)
                .setActionId(ByteString.copyFrom(ByteArray(16) { 0xa1.toByte() }))
                .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { 0xb2.toByte() }))
                .setReplyText("acknowledged"),
        )
        .build()

    private class IdentityVector(private val json: String) {
        val transitionId: ByteArray get() = hex("transitionIdHex")
        val previousKeyId: ByteArray get() = hex("previousKeyIdHex")
        val newPublicKey: ByteArray get() = hex("newPublicKeyHex")
        val newKeyId: ByteArray get() = hex("newKeyIdHex")
        val transitionEncoded: ByteArray get() = hex("transitionEncodedHex")
        val transitionSha256: ByteArray get() = hex("transitionSha256Hex")
        val ackEncoded: ByteArray get() = hex("ackEncodedHex")
        val ackSha256: ByteArray get() = hex("ackSha256Hex")
        val commitEncoded: ByteArray get() = hex("commitEncodedHex")

        private fun hex(name: String): ByteArray {
            val value = Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
                .find(json)?.groupValues?.get(1)
                ?: error("Missing $name")
            return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }

        companion object {
            fun load(): IdentityVector {
                val stream = requireNotNull(
                    EncryptedPayloadV1Test::class.java.classLoader
                        ?.getResourceAsStream("e2ee-identity-key-transition-v1.json"),
                )
                return IdentityVector(stream.bufferedReader().use { it.readText() })
            }
        }
    }

    private class Vector(private val json: String) {
        val encoded: ByteArray get() = hex("encodedHex")
        val actionResultEncoded: ByteArray get() = hex("actionResultEncodedHex")
        val actionResultSha256: ByteArray get() = hex("actionResultSha256Hex")
        val actionResultAckEncoded: ByteArray get() = hex("actionResultAckEncodedHex")
        val notificationPayloadId: String get() = string("notificationPayloadId")
        val notificationUpsertRevision: Long get() = string("notificationUpsertRevision").toLong()
        val notificationRemovedRevision: Long get() = string("notificationRemovedRevision").toLong()
        val notificationTitle: String get() = string("notificationTitle")
        val notificationBody: String get() = string("notificationBody")
        val notificationUpsertEncoded: ByteArray get() = hex("notificationUpsertEncodedHex")
        val notificationRemovedEncoded: ByteArray get() = hex("notificationRemovedEncodedHex")

        private fun string(name: String): String =
            Regex("\\\"$name\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"")
                .find(json)?.groupValues?.get(1)
                ?: error("Missing $name")

        private fun hex(name: String): ByteArray {
            val value = Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
                .find(json)?.groupValues?.get(1)
                ?: error("Missing $name")
            return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }

        companion object {
            fun load(): Vector {
                val stream = requireNotNull(
                    EncryptedPayloadV1Test::class.java.classLoader
                        ?.getResourceAsStream("encrypted-payload-v1.json"),
                )
                return Vector(stream.bufferedReader().use { it.readText() })
            }
        }
    }
}
