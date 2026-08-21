package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.NotificationRemoved
import dev.notificationmirroring.protocol.generated.v1.NotificationSnapshotEntry
import dev.notificationmirroring.protocol.generated.v1.NotificationSnapshotManifest
import dev.notificationmirroring.protocol.generated.v1.NotificationUpsert
import java.security.SecureRandom

/** Online-only sender for the P0 app-owned synthetic text notification slice. */
class NotificationEnvelopeSender(
    workspaceId: ByteArray,
    senderDeviceId: ByteArray,
    senderIdentity: AuthenticatedHpke.KeyPair,
    private val recipients: WorkspaceNotificationRecipientDirectory,
    private val allocateSequence: (ByteArray) -> Long,
    private val random: SecureRandom = SecureRandom(),
) {
    private val workspaceId = workspaceId.copyOf()
    private val senderDeviceId = senderDeviceId.copyOf()
    private val senderIdentity = AuthenticatedHpke.KeyPair(
        senderIdentity.publicKey.copyOf(),
        senderIdentity.privateKey.copyOf(),
    )

    fun createUpsert(
        notificationId: String,
        revision: Long,
        title: String?,
        body: String?,
        nowUnixMs: Long,
    ): List<ByteArray>? {
        val notification = NotificationUpsert.newBuilder()
            .setNotificationId(notificationId)
            .setNotificationRevision(revision)
            .also { builder -> title?.let(builder::setTitle) }
            .also { builder -> body?.let(builder::setBody) }
            .build()
        return create(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
                .setNotificationUpsert(notification)
                .build(),
            nowUnixMs,
        )
    }

    fun createRemoved(
        notificationId: String,
        revision: Long,
        nowUnixMs: Long,
    ): List<ByteArray>? = create(
        EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
            .setNotificationRemoved(
                NotificationRemoved.newBuilder()
                    .setNotificationId(notificationId)
                    .setNotificationRevision(revision),
            )
            .build(),
        nowUnixMs,
    )

    fun createSnapshotManifest(
        highWaterRevision: Long,
        activeNotifications: Map<String, Long>,
        nowUnixMs: Long,
    ): List<ByteArray>? {
        val orderedIds = canonicalNotificationIds(activeNotifications.keys)
        val manifest = NotificationSnapshotManifest.newBuilder()
            .setHighWaterRevision(highWaterRevision)
        orderedIds.forEach { notificationId ->
            manifest.addActiveNotifications(
                NotificationSnapshotEntry.newBuilder()
                    .setNotificationId(notificationId)
                    .setNotificationRevision(requireNotNull(activeNotifications[notificationId])),
            )
        }
        return create(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.NOTIFICATION_SCHEMA_VERSION)
                .setNotificationSnapshotManifest(manifest)
                .build(),
            nowUnixMs,
        )
    }

    fun clearIdentity() {
        senderIdentity.privateKey.fill(0)
    }

    private fun create(payload: EncryptedPayload, nowUnixMs: Long): List<ByteArray>? {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val targets = recipients.listNotificationRecipients(workspaceId, senderDeviceId, nowUnixMs)
        if (targets.isEmpty()) return null
        val canonicalPayload = EncryptedPayloadCodecV1.encode(payload)
        val frames = ArrayList<ByteArray>(targets.size)
        try {
            for (target in targets) {
                try {
                    frames += AuthenticatedPayloadEnvelopeSender.create(
                        AuthenticatedPayloadEnvelopeContext(
                            workspaceId = workspaceId,
                            senderDeviceId = senderDeviceId,
                            recipientDeviceId = target.deviceId,
                            senderIdentity = senderIdentity,
                            recipientPublicKey = target.identityPublicKey,
                            messageId = nextMessageId(),
                            sequence = allocateSequence(target.identityKeyId),
                            createdAtUnixMs = nowUnixMs,
                            expiresAtUnixMs = Math.addExact(nowUnixMs, ENVELOPE_TTL_MS),
                        ),
                        canonicalPayload,
                    )
                } finally {
                    target.identityPublicKey.fill(0)
                }
            }
            return frames
        } catch (error: Throwable) {
            frames.forEach { it.fill(0) }
            throw error
        } finally {
            canonicalPayload.fill(0)
        }
    }

    companion object {
        fun canonicalNotificationIds(notificationIds: Collection<String>): List<String> =
            notificationIds.sortedWith { left, right ->
                compareUnsigned(left.toByteArray(), right.toByteArray())
            }

        private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
            val commonLength = minOf(left.size, right.size)
            for (index in 0 until commonLength) {
                val difference = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
                if (difference != 0) return difference
            }
            return left.size - right.size
        }

        private const val ENVELOPE_TTL_MS = 5 * 60 * 1000L
    }

    private fun nextMessageId(): ByteArray = ByteArray(16).also { value ->
        do {
            random.nextBytes(value)
        } while (value.all { it.toInt() == 0 })
    }
}
