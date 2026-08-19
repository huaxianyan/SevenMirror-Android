package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.NotificationRemoved
import dev.notificationmirroring.protocol.generated.v1.NotificationUpsert
import java.security.SecureRandom

/** Online-only sender for the P0 app-owned synthetic text notification slice. */
class NotificationEnvelopeSender(
    workspaceId: ByteArray,
    senderDeviceId: ByteArray,
    senderIdentity: AuthenticatedHpke.KeyPair,
    private val trustedPeers: AndroidTrustedPeerStore,
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
    ): ByteArray? {
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
    ): ByteArray? = create(
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

    fun clearIdentity() {
        senderIdentity.privateKey.fill(0)
    }

    private fun create(payload: EncryptedPayload, nowUnixMs: Long): ByteArray? {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val peers = trustedPeers.listApproved(workspaceId)
        if (peers.size != 1) return null
        val peer = peers.single()
        val recipientPublicKey = trustedPeers.findApproved(
            workspaceId,
            peer.deviceId,
            peer.keyId,
        ) ?: return null
        val canonicalPayload = EncryptedPayloadCodecV1.encode(payload)
        return try {
            AuthenticatedPayloadEnvelopeSender.create(
                AuthenticatedPayloadEnvelopeContext(
                    workspaceId = workspaceId,
                    senderDeviceId = senderDeviceId,
                    recipientDeviceId = peer.deviceId,
                    senderIdentity = senderIdentity,
                    recipientPublicKey = recipientPublicKey,
                    messageId = nextMessageId(),
                    sequence = allocateSequence(peer.keyId),
                    createdAtUnixMs = nowUnixMs,
                    expiresAtUnixMs = Math.addExact(nowUnixMs, ENVELOPE_TTL_MS),
                ),
                canonicalPayload,
            )
        } finally {
            canonicalPayload.fill(0)
            recipientPublicKey.fill(0)
        }
    }

    private fun nextMessageId(): ByteArray = ByteArray(16).also { value ->
        do {
            random.nextBytes(value)
        } while (value.all { it.toInt() == 0 })
    }

    private companion object {
        const val ENVELOPE_TTL_MS = 5 * 60 * 1000L
    }
}
