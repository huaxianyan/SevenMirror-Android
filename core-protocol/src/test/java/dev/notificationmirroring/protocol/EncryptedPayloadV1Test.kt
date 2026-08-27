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
import dev.notificationmirroring.protocol.generated.v1.NotificationActionDescriptor
import dev.notificationmirroring.protocol.generated.v1.NotificationMedia
import dev.notificationmirroring.protocol.generated.v1.NotificationMediaMimeType
import dev.notificationmirroring.protocol.generated.v1.NotificationRemoved
import dev.notificationmirroring.protocol.generated.v1.NotificationSnapshotEntry
import dev.notificationmirroring.protocol.generated.v1.NotificationSnapshotManifest
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
    fun decodesLegacyDurableActionButDoesNotEmitItOrAcceptLegacyDismiss() {
        val legacy = validPayload().toBuilder().setSchemaVersion(1).build()
        EncryptedPayloadCodecV1.decode(legacy.toByteArray())
        assertThrows(IllegalArgumentException::class.java) {
            EncryptedPayloadCodecV1.encode(legacy)
        }

        val legacyDismiss = legacy.toBuilder().setActionInvoke(
            legacy.actionInvoke.toBuilder()
                .clearActionId()
                .clearReplyText()
                .setDismissNotification(true),
        ).build()
        assertThrows(IllegalArgumentException::class.java) {
            EncryptedPayloadCodecV1.decode(legacyDismiss.toByteArray())
        }
    }

    @Test
    fun roundTripsCanonicalActionResult() {
        val encoded = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
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
            .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
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
                    .setSourceApplicationId(vector.notificationSourceApplicationId)
                    .setSourceApplicationName(vector.notificationSourceApplicationName)
                    .setTitle(vector.notificationTitle)
                    .setBody(vector.notificationBody)
                    .setAppIcon(vector.notificationAppIcon.toProto())
                    .setAvatar(vector.notificationAvatar.toProto())
                    .setContainsContentImage(vector.notificationContainsContentImage)
                    .addAllActions(vector.notificationActions.map(ActionVector::toProto)),
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

        val manifest = validSnapshotManifest()
        assertArrayEquals(
            vector.notificationSnapshotManifestEncoded,
            EncryptedPayloadCodecV1.encode(manifest),
        )
        assertEquals(
            EncryptedPayload.BodyCase.NOTIFICATION_SNAPSHOT_MANIFEST,
            EncryptedPayloadCodecV1.decode(vector.notificationSnapshotManifestEncoded).bodyCase,
        )
    }

    @Test
    fun rejectsInvalidNotificationSnapshotManifest() {
        val valid = validSnapshotManifest()
        val manifest = valid.notificationSnapshotManifest
        listOf(
            valid.toBuilder().setSchemaVersion(1).build(),
            valid.toBuilder().setNotificationSnapshotManifest(
                manifest.toBuilder().setHighWaterRevision(6),
            ).build(),
            valid.toBuilder().setNotificationSnapshotManifest(
                manifest.toBuilder().setActiveNotifications(
                    1,
                    manifest.getActiveNotifications(1).toBuilder()
                        .setNotificationId("synthetic.notification/42"),
                ),
            ).build(),
            valid.toBuilder().setNotificationSnapshotManifest(
                manifest.toBuilder().setActiveNotifications(
                    0,
                    manifest.getActiveNotifications(0).toBuilder()
                        .setNotificationId("synthetic.notification/zz"),
                ),
            ).build(),
        ).forEach { invalid ->
            assertThrows(IllegalArgumentException::class.java) {
                EncryptedPayloadCodecV1.encode(invalid)
            }
        }

        val empty = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
            .setNotificationSnapshotManifest(
                NotificationSnapshotManifest.getDefaultInstance(),
            )
            .build()
        EncryptedPayloadCodecV1.decode(EncryptedPayloadCodecV1.encode(empty))
    }

    @Test
    fun rejectsInvalidNotificationFieldsAndSchema() {
        val valid = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
            .setNotificationUpsert(
                NotificationUpsert.newBuilder()
                    .setNotificationId(vector.notificationPayloadId)
                    .setNotificationRevision(vector.notificationUpsertRevision)
                    .setSourceApplicationId(vector.notificationSourceApplicationId)
                    .setSourceApplicationName(vector.notificationSourceApplicationName)
                    .setTitle(vector.notificationTitle)
                    .addActions(
                        NotificationActionDescriptor.newBuilder()
                            .setActionId(ByteString.copyFrom(ByteArray(16) { 1 }))
                            .setTitle("Mark handled"),
                    ),
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
                valid.notificationUpsert.toBuilder().clearSourceApplicationId(),
            ).build(),
            valid.toBuilder().setNotificationUpsert(
                valid.notificationUpsert.toBuilder().clearSourceApplicationName(),
            ).build(),
            valid.toBuilder().setNotificationUpsert(
                valid.notificationUpsert.toBuilder().clearTitle(),
            ).build(),
            valid.toBuilder().setNotificationUpsert(
                valid.notificationUpsert.toBuilder().setTitle(""),
            ).build(),
            valid.toBuilder().setNotificationUpsert(
                valid.notificationUpsert.toBuilder().setActions(
                    0,
                    valid.notificationUpsert.getActions(0).toBuilder().clearActionId(),
                ),
            ).build(),
            valid.toBuilder().setNotificationUpsert(
                valid.notificationUpsert.toBuilder().setActions(
                    0,
                    valid.notificationUpsert.getActions(0).toBuilder()
                        .setRequiresTextInput(false)
                        .setAllowsFreeFormInput(true),
                ),
            ).build(),
        ).forEach { invalid ->
            assertThrows(IllegalArgumentException::class.java) {
                EncryptedPayloadCodecV1.encode(invalid)
            }
        }
    }

    @Test
    fun rejectsInvalidNotificationMedia() {
        val valid = NotificationUpsert.newBuilder()
            .setNotificationId(vector.notificationPayloadId)
            .setNotificationRevision(vector.notificationUpsertRevision)
            .setSourceApplicationId(vector.notificationSourceApplicationId)
            .setSourceApplicationName(vector.notificationSourceApplicationName)
            .setTitle(vector.notificationTitle)
            .setAppIcon(vector.notificationAppIcon.toProto())
            .build()
        fun payload(upsert: NotificationUpsert) = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
            .setNotificationUpsert(upsert)
            .build()

        val invalidMedia = listOf(
            valid.appIcon.toBuilder().setContentSha256(ByteString.copyFrom(ByteArray(32))).build(),
            valid.appIcon.toBuilder()
                .setMimeType(NotificationMediaMimeType.NOTIFICATION_MEDIA_MIME_TYPE_UNSPECIFIED)
                .build(),
            valid.appIcon.toBuilder().setWidth(0).build(),
            valid.appIcon.toBuilder()
                .setHeight(EncryptedPayloadCodecV1.MAX_NOTIFICATION_MEDIA_DIMENSION + 1)
                .build(),
            valid.appIcon.toBuilder()
                .setEncodedBytes(ByteString.copyFrom(ByteArray(EncryptedPayloadCodecV1.MAX_NOTIFICATION_MEDIA_BYTES + 1)))
                .build(),
            valid.appIcon.toBuilder()
                .setMimeType(NotificationMediaMimeType.NOTIFICATION_MEDIA_MIME_TYPE_WEBP)
                .build(),
        )
        invalidMedia.forEach { media ->
            assertThrows(IllegalArgumentException::class.java) {
                EncryptedPayloadCodecV1.encode(payload(valid.toBuilder().setAppIcon(media).build()))
            }
        }

        assertThrows(IllegalArgumentException::class.java) {
            EncryptedPayloadCodecV1.encode(
                payload(valid.toBuilder().setContainsContentImage(true).build()),
            )
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
    }

    @Test
    fun matchesCanonicalDismissAndRejectsMixedOperations() {
        val dismiss = EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
            .setActionInvoke(
                ActionInvoke.newBuilder()
                    .setNotificationId("test.notification/42")
                    .setNotificationRevision(8)
                    .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { 0xc3.toByte() }))
                    .setDismissNotification(true),
            )
            .build()
        assertArrayEquals(vector.dismissEncoded, EncryptedPayloadCodecV1.encode(dismiss))
        assertEquals(true, EncryptedPayloadCodecV1.decode(vector.dismissEncoded).actionInvoke.dismissNotification)

        listOf(
            dismiss.toBuilder().setActionInvoke(
                dismiss.actionInvoke.toBuilder().setActionId(ByteString.copyFrom(ByteArray(16) { 1 })),
            ).build(),
            dismiss.toBuilder().setActionInvoke(
                dismiss.actionInvoke.toBuilder().setReplyText("reply"),
            ).build(),
        ).forEach { invalid ->
            assertThrows(IllegalArgumentException::class.java) {
                EncryptedPayloadCodecV1.encode(invalid)
            }
        }
    }

    @Test
    fun rejectsDuplicateUnknownAndInvalidSemanticFields() {
        val valid = vector.encoded
        listOf(
            byteArrayOf(8, EncryptedPayloadCodecV1.SCHEMA_VERSION.toByte()) + valid,
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

    private fun validSnapshotManifest(): EncryptedPayload = EncryptedPayload.newBuilder()
        .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
        .setNotificationSnapshotManifest(
            NotificationSnapshotManifest.newBuilder()
                .setHighWaterRevision(vector.notificationSnapshotHighWaterRevision)
                .addActiveNotifications(
                    NotificationSnapshotEntry.newBuilder()
                        .setNotificationId("synthetic.notification/42")
                        .setNotificationRevision(7),
                )
                .addActiveNotifications(
                    NotificationSnapshotEntry.newBuilder()
                        .setNotificationId("synthetic.notification/99")
                        .setNotificationRevision(9),
                ),
        )
        .build()

    private fun validPayload(): EncryptedPayload = EncryptedPayload.newBuilder()
        .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
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
        val dismissEncoded: ByteArray get() = hex("dismissEncodedHex")
        val actionResultEncoded: ByteArray get() = hex("actionResultEncodedHex")
        val actionResultSha256: ByteArray get() = hex("actionResultSha256Hex")
        val actionResultAckEncoded: ByteArray get() = hex("actionResultAckEncodedHex")
        val notificationPayloadId: String get() = string("notificationPayloadId")
        val notificationUpsertRevision: Long get() = string("notificationUpsertRevision").toLong()
        val notificationRemovedRevision: Long get() = string("notificationRemovedRevision").toLong()
        val notificationSourceApplicationId: String get() = string("notificationSourceApplicationId")
        val notificationSourceApplicationName: String get() = string("notificationSourceApplicationName")
        val notificationTitle: String get() = string("notificationTitle")
        val notificationBody: String get() = string("notificationBody").replace("\\n", "\n")
        val notificationContainsContentImage: Boolean
            get() = Regex("\\\"notificationContainsContentImage\\\"\\s*:\\s*(true|false)")
                .find(json)?.groupValues?.get(1)?.toBooleanStrict()
                ?: error("Missing notificationContainsContentImage")
        val notificationActions: List<ActionVector>
            get() {
                val body = Regex(
                    "\\\"notificationActions\\\"\\s*:\\s*\\[([^]]*)]",
                    RegexOption.DOT_MATCHES_ALL,
                ).find(json)?.groupValues?.get(1) ?: error("Missing notificationActions")
                return Regex("\\{([^}]*)}", RegexOption.DOT_MATCHES_ALL).findAll(body).map { match ->
                    val action = match.groupValues[1]
                    fun value(field: String): String =
                        Regex("\\\"$field\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"")
                            .find(action)?.groupValues?.get(1)
                            ?: error("Missing notificationActions.$field")
                    fun flag(field: String): Boolean =
                        Regex("\\\"$field\\\"\\s*:\\s*(true|false)")
                            .find(action)?.groupValues?.get(1)?.toBooleanStrict()
                            ?: error("Missing notificationActions.$field")
                    ActionVector(
                        actionId = value("actionIdHex").hexToBytes(),
                        title = value("title"),
                        requiresTextInput = flag("requiresTextInput"),
                        allowsFreeFormInput = flag("allowsFreeFormInput"),
                    )
                }.toList()
            }
        val notificationAppIcon: MediaVector get() = media("notificationAppIcon")
        val notificationAvatar: MediaVector get() = media("notificationAvatar")
        val notificationUpsertEncoded: ByteArray get() = hex("notificationUpsertEncodedHex")
        val notificationRemovedEncoded: ByteArray get() = hex("notificationRemovedEncodedHex")
        val notificationSnapshotHighWaterRevision: Long
            get() = string("notificationSnapshotHighWaterRevision").toLong()
        val notificationSnapshotManifestEncoded: ByteArray
            get() = hex("notificationSnapshotManifestEncodedHex")

        private fun string(name: String): String =
            Regex("\\\"$name\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"")
                .find(json)?.groupValues?.get(1)
                ?: error("Missing $name")

        private fun hex(name: String): ByteArray {
            val value = Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
                .find(json)?.groupValues?.get(1)
                ?: error("Missing $name")
            return value.hexToBytes()
        }

        private fun media(name: String): MediaVector {
            val body = Regex("\\\"$name\\\"\\s*:\\s*\\{([^}]*)}", RegexOption.DOT_MATCHES_ALL)
                .find(json)?.groupValues?.get(1)
                ?: error("Missing $name")
            fun value(field: String): String =
                Regex("\\\"$field\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"")
                    .find(body)?.groupValues?.get(1)
                    ?: error("Missing $name.$field")
            fun number(field: String): Int =
                Regex("\\\"$field\\\"\\s*:\\s*(\\d+)")
                    .find(body)?.groupValues?.get(1)?.toInt()
                    ?: error("Missing $name.$field")
            return MediaVector(
                contentSha256 = value("contentSha256Hex").hexToBytes(),
                width = number("width"),
                height = number("height"),
                encoded = value("encodedHex").hexToBytes(),
            )
        }

        private fun String.hexToBytes(): ByteArray =
            chunked(2).map { it.toInt(16).toByte() }.toByteArray()

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

    private data class ActionVector(
        val actionId: ByteArray,
        val title: String,
        val requiresTextInput: Boolean,
        val allowsFreeFormInput: Boolean,
    ) {
        fun toProto(): NotificationActionDescriptor = NotificationActionDescriptor.newBuilder()
            .setActionId(ByteString.copyFrom(actionId))
            .setTitle(title)
            .setRequiresTextInput(requiresTextInput)
            .setAllowsFreeFormInput(allowsFreeFormInput)
            .build()
    }

    private data class MediaVector(
        val contentSha256: ByteArray,
        val width: Int,
        val height: Int,
        val encoded: ByteArray,
    ) {
        fun toProto(): NotificationMedia = NotificationMedia.newBuilder()
            .setContentSha256(ByteString.copyFrom(contentSha256))
            .setMimeType(NotificationMediaMimeType.NOTIFICATION_MEDIA_MIME_TYPE_PNG)
            .setWidth(width)
            .setHeight(height)
            .setEncodedBytes(ByteString.copyFrom(encoded))
            .build()
    }
}
