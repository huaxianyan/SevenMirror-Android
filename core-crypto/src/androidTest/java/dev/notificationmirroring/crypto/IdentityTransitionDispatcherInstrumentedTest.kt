package dev.notificationmirroring.crypto

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedEnvelopePartsV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import dev.notificationmirroring.protocol.generated.v1.ActionResult
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransition
import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IdentityTransitionDispatcherInstrumentedTest {
    @Test
    fun routesOldKeyTransitionAndFallsBackOnlyForAuthenticatedBusinessPayload() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val suffix = UUID.randomUUID().toString()
        val peers = AndroidTrustedPeerStore(context, "dispatch-peers-$suffix")
        val local = AndroidLocalIdentityTransitionStore(context, "dispatch-local-$suffix")
        val replay = AndroidReplayLedger(context, "dispatch-replay-$suffix")
        val current = AuthenticatedHpke.generateKeyPair()
        val sender = AuthenticatedHpke.generateKeyPair()
        val successor = AuthenticatedHpke.generateKeyPair()
        val workspaceId = ByteArray(16) { 1 }
        val senderDeviceId = ByteArray(16) { 2 }
        val recipientDeviceId = ByteArray(16) { 3 }
        val senderKeyId = sha256(sender.publicKey)
        var businessFrames = 0
        try {
            peers.pinApproved(workspaceId, senderDeviceId, sender.publicKey)
            val transition = EncryptedPayloadCodecV1.encode(
                EncryptedPayload.newBuilder()
                    .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                    .setIdentityKeyTransition(
                        IdentityKeyTransition.newBuilder()
                            .setTransitionId(ByteString.copyFrom(ByteArray(16) { 4 }))
                            .setPreviousKeyId(ByteString.copyFrom(senderKeyId))
                            .setNewPublicKey(ByteString.copyFrom(successor.publicKey))
                            .setNewKeyId(ByteString.copyFrom(sha256(successor.publicKey))),
                    )
                    .build(),
            )
            val dispatcher = IdentityTransitionDispatcher(
                workspaceId,
                recipientDeviceId,
                current,
                null,
                peers,
                local,
                replay,
            ) { _, _ -> businessFrames += 1 }

            assertEquals(
                IdentityTransitionDispatchResult.PEER_TRANSITION,
                dispatcher.receive(
                    frame(
                        workspaceId,
                        senderDeviceId,
                        recipientDeviceId,
                        sender,
                        current.publicKey,
                        transition,
                        ByteArray(16) { 6 },
                    ),
                    NOW,
                ),
            )
            assertEquals(0, businessFrames)
            assertNotNull(peers.loadIdentityTransition(workspaceId, senderDeviceId, NOW))

            val business = EncryptedPayloadCodecV1.encode(
                EncryptedPayload.newBuilder()
                    .setSchemaVersion(EncryptedPayloadCodecV1.SCHEMA_VERSION)
                    .setActionResult(
                        ActionResult.newBuilder()
                            .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { 7 }))
                            .setStatus(ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED),
                    )
                    .build(),
            )
            assertEquals(
                IdentityTransitionDispatchResult.BUSINESS_FALLBACK,
                dispatcher.receive(
                    frame(
                        workspaceId,
                        senderDeviceId,
                        recipientDeviceId,
                        sender,
                        current.publicKey,
                        business,
                        ByteArray(16) { 8 },
                    ),
                    NOW,
                ),
            )
            assertEquals(1, businessFrames)
            dispatcher.clear()
        } finally {
            current.privateKey.fill(0)
            sender.privateKey.fill(0)
            successor.privateKey.fill(0)
            replay.clear()
            local.clear()
            peers.clear()
        }
    }

    private fun frame(
        workspaceId: ByteArray,
        senderDeviceId: ByteArray,
        recipientDeviceId: ByteArray,
        sender: AuthenticatedHpke.KeyPair,
        recipientPublicKey: ByteArray,
        plaintext: ByteArray,
        messageId: ByteArray,
    ): ByteArray {
        val header = RoutingHeaderCodecV1.encode(
            RoutingHeaderV1(
                workspaceId = workspaceId,
                senderDeviceId = senderDeviceId,
                recipientDeviceId = recipientDeviceId,
                senderKeyId = sha256(sender.publicKey),
                recipientKeyId = sha256(recipientPublicKey),
                messageId = messageId,
                sequence = messageId[0].toLong(),
                createdAtUnixMs = NOW,
                expiresAtUnixMs = NOW + 60_000,
            ),
        )
        val encrypted = AuthenticatedHpke.seal(recipientPublicKey, sender, plaintext, header)
        return EncryptedEnvelopeCodecV1.encode(
            EncryptedEnvelopePartsV1(header, encrypted.encapsulatedKey, encrypted.ciphertext),
        )
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private companion object {
        const val NOW = 1_800_000_000_000L
    }
}
