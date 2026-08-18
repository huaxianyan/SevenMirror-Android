package dev.notificationmirroring.storage

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.crypto.AndroidHpkeIdentityStore
import dev.notificationmirroring.crypto.AndroidLocalIdentityTransitionStore
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransition
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionAck
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import dev.notificationmirroring.transport.StoredTransportCredential
import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidIdentityPromotionCoordinatorInstrumentedTest {
    @Test
    fun promotesExactIdentityAndTransportBindings() {
        val fixture = fixture()
        try {
            assertEquals(
                IdentityPromotionResult.PROMOTED,
                fixture.coordinator().promoteReady(),
            )
            fixture.assertPromoted()
            assertNull(fixture.journal.load())
            assertEquals(
                AndroidLocalIdentityTransitionStore.SessionPhase.PROMOTION_COMPLETED,
                fixture.transitions.dueCommits(fixture.workspaceId, fixture.now + 3)
                    .single().first.phase,
            )
        } finally {
            fixture.clear()
        }
    }

    @Test
    fun recoversAfterTransportRebindCommitsBeforeJournalPhaseUpdate() {
        val fixture = fixture()
        try {
            val record = fixture.preparedRecord()
            fixture.journal.create(record)
            fixture.transport.rebindIdentityKey(fixture.previousKeyId, fixture.newKeyId)
                .authToken.fill(0)

            assertEquals(
                IdentityPromotionResult.RECOVERED,
                fixture.reconstructedCoordinator().promoteReady(),
            )
            fixture.assertPromoted()
            assertNull(fixture.journal.load())
        } finally {
            fixture.clear()
        }
    }

    @Test
    fun defersRacedTransportRotationUntilItsPendingCredentialFinishes() {
        val fixture = fixture()
        try {
            fixture.journal.create(fixture.preparedRecord())
            val pendingToken = ByteArray(32) { 7 }
            fixture.transport.prepareRotation(pendingToken).also {
                it.current.authToken.fill(0)
                it.pendingAuthToken.fill(0)
            }
            assertEquals(
                IdentityPromotionResult.DEFERRED_TRANSPORT_ROTATION,
                fixture.coordinator().promoteReady(),
            )
            fixture.transport.markRotationAttempted(pendingToken)
            fixture.transport.promotePending().authToken.fill(0)

            assertEquals(
                IdentityPromotionResult.RECOVERED,
                fixture.reconstructedCoordinator().promoteReady(),
            )
            fixture.assertPromoted()
        } finally {
            fixture.clear()
        }
    }

    @Test
    fun recoversAfterBothExternalStoresCommitBeforeJournalPhaseUpdates() {
        val fixture = fixture()
        try {
            val record = fixture.preparedRecord()
            fixture.journal.create(record)
            fixture.transport.rebindIdentityKey(fixture.previousKeyId, fixture.newKeyId)
                .authToken.fill(0)
            fixture.identities.promotePending(fixture.previousKeyId, fixture.newKeyId)
                .privateKey.fill(0)

            assertEquals(
                IdentityPromotionResult.RECOVERED,
                fixture.reconstructedCoordinator().promoteReady(),
            )
            fixture.assertPromoted()
            assertNull(fixture.journal.load())
        } finally {
            fixture.clear()
        }
    }

    private fun fixture(): Fixture {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val suffix = UUID.randomUUID().toString()
        val identityName = "promotion-identity-$suffix"
        val transportName = "promotion-transport-$suffix"
        val transitionName = "promotion-transition-$suffix"
        val journalName = "promotion-journal-$suffix"
        val identities = AndroidHpkeIdentityStore(context, identityName)
        val transport = AndroidTransportCredentialStore(context, transportName)
        val transitions = AndroidLocalIdentityTransitionStore(context, transitionName)
        val journal = AndroidIdentityPromotionJournal(context, journalName)
        val current = identities.loadOrCreate()
        val rotation = identities.prepareRotation()
        val previousKeyId = sha256(current.publicKey)
        val pendingPublicKey = rotation.pending.publicKey.copyOf()
        val newKeyId = sha256(pendingPublicKey)
        current.privateKey.fill(0)
        rotation.current.privateKey.fill(0)
        rotation.pending.privateKey.fill(0)
        val workspaceId = ByteArray(16) { 1 }
        val deviceId = ByteArray(16) { 2 }
        val peerDeviceId = ByteArray(16) { 3 }
        val peerKeyId = ByteArray(32) { 4 }
        val transitionId = ByteArray(16) { 5 }
        val canonicalTransition = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                .setIdentityKeyTransition(
                    IdentityKeyTransition.newBuilder()
                        .setTransitionId(ByteString.copyFrom(transitionId))
                        .setPreviousKeyId(ByteString.copyFrom(previousKeyId))
                        .setNewPublicKey(ByteString.copyFrom(pendingPublicKey))
                        .setNewKeyId(ByteString.copyFrom(newKeyId)),
                )
                .build(),
        )
        val canonicalAck = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                .setIdentityKeyTransitionAck(
                    IdentityKeyTransitionAck.newBuilder()
                        .setTransitionId(ByteString.copyFrom(transitionId))
                        .setPreviousKeyId(ByteString.copyFrom(previousKeyId))
                        .setNewKeyId(ByteString.copyFrom(newKeyId))
                        .setTransitionSha256(ByteString.copyFrom(sha256(canonicalTransition))),
                )
                .build(),
        )
        val now = 1_800_000_000_000L
        transitions.create(
            workspaceId,
            deviceId,
            canonicalTransition,
            listOf(AndroidLocalIdentityTransitionStore.PeerSnapshot(peerDeviceId, peerKeyId)),
            now,
        )
        transitions.acceptAck(peerDeviceId, peerKeyId, canonicalAck, now + 1)
        transport.saveNew(
            StoredTransportCredential(
                serverOrigin = "https://relay.example",
                workspaceId = workspaceId,
                deviceId = deviceId,
                authToken = ByteArray(32) { 9 },
                identityKeyId = previousKeyId,
            ),
        )
        return Fixture(
            context,
            identityName,
            transportName,
            transitionName,
            journalName,
            identities,
            transport,
            transitions,
            journal,
            now,
            workspaceId,
            deviceId,
            transitionId,
            previousKeyId,
            newKeyId,
        )
    }

    private data class Fixture(
        val context: android.content.Context,
        val identityName: String,
        val transportName: String,
        val transitionName: String,
        val journalName: String,
        val identities: AndroidHpkeIdentityStore,
        val transport: AndroidTransportCredentialStore,
        val transitions: AndroidLocalIdentityTransitionStore,
        val journal: AndroidIdentityPromotionJournal,
        val now: Long,
        val workspaceId: ByteArray,
        val deviceId: ByteArray,
        val transitionId: ByteArray,
        val previousKeyId: ByteArray,
        val newKeyId: ByteArray,
    ) {
        fun coordinator() = AndroidIdentityPromotionCoordinator(
            identities,
            transport,
            transitions,
            journal,
        ) { now + 2 }

        fun reconstructedCoordinator() = AndroidIdentityPromotionCoordinator(
            AndroidHpkeIdentityStore(context, identityName),
            AndroidTransportCredentialStore(context, transportName),
            AndroidLocalIdentityTransitionStore(context, transitionName),
            AndroidIdentityPromotionJournal(context, journalName),
        ) { now + 3 }

        fun preparedRecord() = IdentityPromotionJournalRecord(
            workspaceId,
            deviceId,
            transitionId,
            previousKeyId,
            newKeyId,
            IdentityPromotionPhase.PREPARED,
        )

        fun assertPromoted() {
            assertNull(identities.loadRotation())
            val current = identities.loadExisting()!!
            try {
                assertArrayEquals(newKeyId, sha256(current.publicKey))
            } finally {
                current.privateKey.fill(0)
            }
            val credential = transport.load()!!
            try {
                assertArrayEquals(newKeyId, credential.identityKeyId)
            } finally {
                credential.authToken.fill(0)
            }
        }

        fun clear() {
            journal.clear()
            transitions.clear()
            transport.clear()
            identities.clear()
        }
    }

    private companion object {
        fun sha256(value: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(value)
    }
}
