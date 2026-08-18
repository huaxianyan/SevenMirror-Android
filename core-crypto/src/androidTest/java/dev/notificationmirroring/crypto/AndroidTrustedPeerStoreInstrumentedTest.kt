package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransition
import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidTrustedPeerStoreInstrumentedTest {
    @Test
    fun approvedPinIsImmutableUntilExplicitRemoval() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val store = AndroidTrustedPeerStore(context, "test-${UUID.randomUUID()}")
        val workspaceId = ByteArray(16) { 1 }
        val deviceId = ByteArray(16) { 2 }
        val first = AuthenticatedHpke.generateKeyPair().publicKey
        val replacement = AuthenticatedHpke.generateKeyPair().publicKey
        try {
            assertEquals(
                AndroidTrustedPeerStore.PinResult.PINNED,
                store.pinApproved(workspaceId, deviceId, first),
            )
            assertEquals(
                AndroidTrustedPeerStore.PinResult.ALREADY_PINNED,
                store.pinApproved(workspaceId, deviceId, first),
            )
            assertThrows(IllegalStateException::class.java) {
                store.pinApproved(workspaceId, deviceId, replacement)
            }
            assertArrayEquals(
                first,
                store.findApproved(workspaceId, deviceId, sha256(first)),
            )
            assertNull(store.findApproved(workspaceId, deviceId, sha256(replacement)))

            store.remove(workspaceId, deviceId)
            assertNull(store.findApproved(workspaceId, deviceId, sha256(first)))
            assertEquals(
                AndroidTrustedPeerStore.PinResult.PINNED,
                store.pinApproved(workspaceId, deviceId, replacement),
            )
        } finally {
            store.clear()
        }
    }

    @Test
    fun exactIdentitySuccessorAndAcknowledgementSurviveStoreReconstruction() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val storeName = "test-${UUID.randomUUID()}"
        val store = AndroidTrustedPeerStore(context, storeName)
        val workspaceId = ByteArray(16) { 1 }
        val deviceId = ByteArray(16) { 2 }
        val previousPublicKey = AuthenticatedHpke.generateKeyPair().publicKey
        val newPublicKey = AuthenticatedHpke.generateKeyPair().publicKey
        val previousKeyId = sha256(previousPublicKey)
        val newKeyId = sha256(newPublicKey)
        val canonicalTransition = transitionPayload(
            ByteArray(16) { 3 },
            previousKeyId,
            newPublicKey,
            newKeyId,
        )
        val now = 1_800_000_000_000L
        var reconstructed: AndroidTrustedPeerStore? = null
        try {
            store.pinApproved(workspaceId, deviceId, previousPublicKey)
            val accepted = store.acceptIdentityTransition(
                workspaceId,
                deviceId,
                canonicalTransition,
                now,
            )
            assertEquals(AndroidTrustedPeerStore.TransitionResult.ACCEPTED, accepted.result)
            assertArrayEquals(canonicalTransition, accepted.state.canonicalTransition)
            val ack = EncryptedPayloadCodecV1.decode(accepted.state.canonicalAck)
            assertEquals(EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_ACK, ack.bodyCase)
            assertArrayEquals(
                sha256(canonicalTransition),
                ack.identityKeyTransitionAck.transitionSha256.toByteArray(),
            )

            store.close()
            val recoveredStore = AndroidTrustedPeerStore(context, storeName)
            reconstructed = recoveredStore
            val duplicate = recoveredStore.acceptIdentityTransition(
                workspaceId,
                deviceId,
                canonicalTransition,
                now + 1,
            )
            assertEquals(
                AndroidTrustedPeerStore.TransitionResult.ALREADY_ACCEPTED,
                duplicate.result,
            )
            assertArrayEquals(accepted.state.canonicalAck, duplicate.state.canonicalAck)
            assertArrayEquals(
                accepted.state.canonicalAck,
                recoveredStore.loadIdentityTransition(workspaceId, deviceId, now + 2)!!.canonicalAck,
            )

            val otherPublicKey = AuthenticatedHpke.generateKeyPair().publicKey
            assertThrows(IllegalStateException::class.java) {
                recoveredStore.acceptIdentityTransition(
                    workspaceId,
                    deviceId,
                    transitionPayload(
                        ByteArray(16) { 4 },
                        previousKeyId,
                        otherPublicKey,
                        sha256(otherPublicKey),
                    ),
                    now + 3,
                )
            }
        } finally {
            reconstructed?.close()
            store.clear()
        }
    }

    @Test
    fun expiredIdentitySuccessorBlocksWithoutChangingApprovedPin() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val store = AndroidTrustedPeerStore(context, "test-${UUID.randomUUID()}")
        val workspaceId = ByteArray(16) { 1 }
        val deviceId = ByteArray(16) { 2 }
        val previousPublicKey = AuthenticatedHpke.generateKeyPair().publicKey
        val newPublicKey = AuthenticatedHpke.generateKeyPair().publicKey
        val previousKeyId = sha256(previousPublicKey)
        val newKeyId = sha256(newPublicKey)
        val canonicalTransition = transitionPayload(
            ByteArray(16) { 5 },
            previousKeyId,
            newPublicKey,
            newKeyId,
        )
        val now = 1_800_000_000_000L
        try {
            store.pinApproved(workspaceId, deviceId, previousPublicKey)
            val accepted = store.acceptIdentityTransition(
                workspaceId,
                deviceId,
                canonicalTransition,
                now,
            )
            val blocked = store.loadIdentityTransition(
                workspaceId,
                deviceId,
                accepted.state.expiresAtUnixMs,
            )!!
            assertEquals(AndroidTrustedPeerStore.TransitionPhase.BLOCKED, blocked.phase)
            assertArrayEquals(
                previousPublicKey,
                store.findApproved(workspaceId, deviceId, previousKeyId),
            )
            assertNull(store.findApproved(workspaceId, deviceId, newKeyId))
            assertThrows(IllegalStateException::class.java) {
                store.acceptIdentityTransition(
                    workspaceId,
                    deviceId,
                    canonicalTransition,
                    accepted.state.expiresAtUnixMs,
                )
            }

            store.remove(workspaceId, deviceId)
            assertNull(
                store.loadIdentityTransition(
                    workspaceId,
                    deviceId,
                    accepted.state.expiresAtUnixMs + 1,
                ),
            )
        } finally {
            store.clear()
        }
    }

    @Test
    fun legacyApprovedPinMigratesBeforeAcceptingSuccessor() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val storeName = "test-${UUID.randomUUID()}"
        val databaseName = "syncnotifications-trusted-peers-$storeName.db"
        val databasePath = context.getDatabasePath(databaseName)
        databasePath.parentFile!!.mkdirs()
        val workspaceId = ByteArray(16) { 1 }
        val deviceId = ByteArray(16) { 2 }
        val previousPublicKey = AuthenticatedHpke.generateKeyPair().publicKey
        val previousKeyId = sha256(previousPublicKey)
        SQLiteDatabase.openOrCreateDatabase(databasePath, null).use { database ->
            database.execSQL(
                "CREATE TABLE approved_peer (" +
                    "workspace_id TEXT NOT NULL, " +
                    "device_id TEXT NOT NULL, " +
                    "key_id BLOB NOT NULL, " +
                    "public_key BLOB NOT NULL, " +
                    "PRIMARY KEY (workspace_id, device_id))",
            )
            database.insertOrThrow(
                "approved_peer",
                null,
                ContentValues(4).apply {
                    put("workspace_id", workspaceId.toHex())
                    put("device_id", deviceId.toHex())
                    put("key_id", previousKeyId)
                    put("public_key", previousPublicKey)
                },
            )
            database.version = 1
        }
        val store = AndroidTrustedPeerStore(context, storeName)
        try {
            assertArrayEquals(
                previousPublicKey,
                store.findApproved(workspaceId, deviceId, previousKeyId),
            )
            val newPublicKey = AuthenticatedHpke.generateKeyPair().publicKey
            assertEquals(
                AndroidTrustedPeerStore.TransitionResult.ACCEPTED,
                store.acceptIdentityTransition(
                    workspaceId,
                    deviceId,
                    transitionPayload(
                        ByteArray(16) { 6 },
                        previousKeyId,
                        newPublicKey,
                        sha256(newPublicKey),
                    ),
                    1_800_000_000_000L,
                ).result,
            )
        } finally {
            store.clear()
        }
    }

    @Test
    fun malformedPointIsRejectedBeforePersistence() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val store = AndroidTrustedPeerStore(context, "test-${UUID.randomUUID()}")
        val malformed = ByteArray(65).apply { this[0] = 4 }
        try {
            assertThrows(RuntimeException::class.java) {
                store.pinApproved(ByteArray(16) { 1 }, ByteArray(16) { 2 }, malformed)
            }
        } finally {
            store.clear()
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun transitionPayload(
        transitionId: ByteArray,
        previousKeyId: ByteArray,
        newPublicKey: ByteArray,
        newKeyId: ByteArray,
    ): ByteArray = EncryptedPayloadCodecV1.encode(
        EncryptedPayload.newBuilder()
            .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
            .setIdentityKeyTransition(
                IdentityKeyTransition.newBuilder()
                    .setTransitionId(ByteString.copyFrom(transitionId))
                    .setPreviousKeyId(ByteString.copyFrom(previousKeyId))
                    .setNewPublicKey(ByteString.copyFrom(newPublicKey))
                    .setNewKeyId(ByteString.copyFrom(newKeyId)),
            )
            .build(),
    )

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}
