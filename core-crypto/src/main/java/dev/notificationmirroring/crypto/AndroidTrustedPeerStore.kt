package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionAck
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionCommit
import java.security.MessageDigest

/** Immutable local E2EE pins; untrusted server directory entries must never call [pinApproved]. */
class AndroidTrustedPeerStore(
    context: Context,
    storeName: String = "default",
) : AutoCloseable {
    enum class PinResult { PINNED, ALREADY_PINNED }
    enum class TransitionResult { ACCEPTED, ALREADY_ACCEPTED }
    enum class CommitResult { COMMITTED, ALREADY_COMMITTED }
    enum class TransitionPhase { PENDING_COMMIT, BLOCKED }

    data class PeerIdentityTransitionState(
        val workspaceId: ByteArray,
        val peerDeviceId: ByteArray,
        val transitionId: ByteArray,
        val previousKeyId: ByteArray,
        val newKeyId: ByteArray,
        val newPublicKey: ByteArray,
        val canonicalTransition: ByteArray,
        val transitionSha256: ByteArray,
        val canonicalAck: ByteArray,
        val ackSha256: ByteArray,
        val acceptedAtUnixMs: Long,
        val expiresAtUnixMs: Long,
        val nextAckAttemptAtUnixMs: Long,
        val ackAttemptCount: Int,
        val phase: TransitionPhase,
    )

    data class ApprovedPeer(
        val deviceId: ByteArray,
        val keyId: ByteArray,
    )

    data class AcceptedPeerIdentityTransition(
        val result: TransitionResult,
        val state: PeerIdentityTransitionState,
    )

    data class IdentityCommitSenderBinding(
        val senderPublicKey: ByteArray,
        val transitionId: ByteArray,
        val previousKeyId: ByteArray,
        val newKeyId: ByteArray,
        val transitionSha256: ByteArray,
        val ackSha256: ByteArray,
        val alreadyCommitted: Boolean,
    )

    data class CommittedPeerIdentityTransition(
        val result: CommitResult,
        val newKeyId: ByteArray,
    )

    private data class TransitionTombstone(
        val workspaceId: ByteArray,
        val peerDeviceId: ByteArray,
        val transitionId: ByteArray,
        val previousKeyId: ByteArray,
        val newKeyId: ByteArray,
        val transitionSha256: ByteArray,
        val ackSha256: ByteArray,
        val canonicalCommit: ByteArray,
        val commitSha256: ByteArray,
        val committedAtUnixMs: Long,
        val expiresAtUnixMs: Long,
    )

    private val appContext = context.applicationContext
    private val safeName = storeName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "storeName must be 1-64 URL-safe characters"
        }
    }
    private val databaseName = "syncnotifications-trusted-peers-$safeName.db"
    private val helper = DatabaseHelper(appContext, databaseName)

    /** The caller must have authenticated this exact key through a separate approval workflow. */
    fun pinApproved(
        workspaceId: ByteArray,
        deviceId: ByteArray,
        publicKey: ByteArray,
    ): PinResult {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(deviceId, "deviceId")
        AuthenticatedHpke.requireValidPublicKey(publicKey)
        val keyId = sha256(publicKey)
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val existing = find(database, workspaceId, deviceId)
            val result = if (existing == null) {
                val rowId = database.insertOrThrow(
                    TABLE,
                    null,
                    ContentValues(4).apply {
                        put(WORKSPACE_ID, workspaceId.toHex())
                        put(DEVICE_ID, deviceId.toHex())
                        put(KEY_ID, keyId)
                        put(PUBLIC_KEY, publicKey.copyOf())
                    },
                )
                check(rowId != -1L) { "Unable to persist approved peer" }
                PinResult.PINNED
            } else {
                check(
                    MessageDigest.isEqual(existing.keyId, keyId) &&
                        MessageDigest.isEqual(existing.publicKey, publicKey),
                ) { "Approved peer key replacement requires explicit removal and approval" }
                PinResult.ALREADY_PINNED
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    fun findApproved(
        workspaceId: ByteArray,
        deviceId: ByteArray,
        keyId: ByteArray,
    ): ByteArray? {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(deviceId, "deviceId")
        validateKeyId(keyId)
        val record = find(helper.readableDatabase, workspaceId, deviceId) ?: return null
        check(MessageDigest.isEqual(record.keyId, sha256(record.publicKey))) {
            "Approved peer record key binding is corrupt"
        }
        if (!MessageDigest.isEqual(record.keyId, keyId)) return null
        AuthenticatedHpke.requireValidPublicKey(record.publicKey)
        return record.publicKey.copyOf()
    }

    fun listApproved(workspaceId: ByteArray): List<ApprovedPeer> {
        validateIdentifier(workspaceId, "workspaceId")
        return helper.readableDatabase.query(
            TABLE,
            arrayOf(DEVICE_ID, KEY_ID, PUBLIC_KEY),
            "$WORKSPACE_ID = ?",
            arrayOf(workspaceId.toHex()),
            null,
            null,
            "$DEVICE_ID ASC",
        ).use { cursor ->
            buildList {
                while (cursor.moveToNext()) {
                    val deviceId = cursor.getString(0).hexToBytes()
                    val keyId = cursor.getBlob(1).copyOf()
                    val publicKey = cursor.getBlob(2).copyOf()
                    try {
                        validateIdentifier(deviceId, "deviceId")
                        validateKeyId(keyId)
                        AuthenticatedHpke.requireValidPublicKey(publicKey)
                        check(MessageDigest.isEqual(keyId, sha256(publicKey))) {
                            "Approved peer record key binding is corrupt"
                        }
                        add(ApprovedPeer(deviceId, keyId))
                    } finally {
                        publicKey.fill(0)
                    }
                }
            }
        }
    }

    /** Atomically binds one exact successor and its deterministic ACK intent to the active pin. */
    @Synchronized
    fun acceptIdentityTransition(
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
        canonicalTransition: ByteArray,
        nowUnixMs: Long,
    ): AcceptedPeerIdentityTransition {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(peerDeviceId, "peerDeviceId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val payload = EncryptedPayloadCodecV1.decode(canonicalTransition)
        require(payload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION) {
            "Expected canonical identity key transition payload"
        }
        val transition = payload.identityKeyTransition
        val transitionId = transition.transitionId.toByteArray()
        val previousKeyId = transition.previousKeyId.toByteArray()
        val newKeyId = transition.newKeyId.toByteArray()
        val newPublicKey = transition.newPublicKey.toByteArray()
        val transitionSha256 = sha256(canonicalTransition)
        val canonicalAck = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                .setIdentityKeyTransitionAck(
                    IdentityKeyTransitionAck.newBuilder()
                        .setTransitionId(ByteString.copyFrom(transitionId))
                        .setPreviousKeyId(ByteString.copyFrom(previousKeyId))
                        .setNewKeyId(ByteString.copyFrom(newKeyId))
                        .setTransitionSha256(ByteString.copyFrom(transitionSha256)),
                )
                .build(),
        )
        val proposed = PeerIdentityTransitionState(
            workspaceId = workspaceId.copyOf(),
            peerDeviceId = peerDeviceId.copyOf(),
            transitionId = transitionId,
            previousKeyId = previousKeyId,
            newKeyId = newKeyId,
            newPublicKey = newPublicKey,
            canonicalTransition = canonicalTransition.copyOf(),
            transitionSha256 = transitionSha256,
            canonicalAck = canonicalAck,
            ackSha256 = sha256(canonicalAck),
            acceptedAtUnixMs = nowUnixMs,
            expiresAtUnixMs = Math.addExact(nowUnixMs, IDENTITY_TRANSITION_RETENTION_MS),
            nextAckAttemptAtUnixMs = nowUnixMs,
            ackAttemptCount = 0,
            phase = TransitionPhase.PENDING_COMMIT,
        )
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val committed = findTombstone(database, workspaceId, peerDeviceId)
            if (committed != null) {
                validateTombstone(committed)
                check(nowUnixMs >= committed.expiresAtUnixMs) {
                    "A committed identity transition tombstone is still active for this peer"
                }
                deleteTombstone(database, workspaceId, peerDeviceId)
            }
            val approved = find(database, workspaceId, peerDeviceId)
                ?: error("Identity transition sender is not an approved peer")
            check(
                MessageDigest.isEqual(approved.keyId, previousKeyId) &&
                    MessageDigest.isEqual(sha256(approved.publicKey), previousKeyId),
            ) { "Identity transition is not authenticated by the active approved peer key" }
            val existing = findTransition(database, workspaceId, peerDeviceId)
            val result = if (existing == null) {
                insertTransition(database, proposed)
                AcceptedPeerIdentityTransition(TransitionResult.ACCEPTED, proposed.copyState())
            } else {
                validateTransitionState(existing)
                if (existing.phase == TransitionPhase.BLOCKED || nowUnixMs >= existing.expiresAtUnixMs) {
                    if (existing.phase != TransitionPhase.BLOCKED) {
                        updateTransitionPhase(database, workspaceId, peerDeviceId, TransitionPhase.BLOCKED)
                    }
                    database.setTransactionSuccessful()
                    error("Identity transition is blocked after expiry")
                }
                check(sameAcceptedTransition(existing, proposed)) {
                    "A different identity successor is already pending for this peer"
                }
                val reactivated = if (
                    existing.ackAttemptCount != 0 || existing.nextAckAttemptAtUnixMs > nowUnixMs
                ) {
                    existing.copy(nextAckAttemptAtUnixMs = nowUnixMs, ackAttemptCount = 0).also {
                        updateAckSchedule(database, it)
                    }
                } else {
                    existing
                }
                AcceptedPeerIdentityTransition(
                    TransitionResult.ALREADY_ACCEPTED,
                    reactivated.copyState(),
                )
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun loadIdentityTransition(
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
        nowUnixMs: Long,
    ): PeerIdentityTransitionState? {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(peerDeviceId, "peerDeviceId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            var state = findTransition(database, workspaceId, peerDeviceId)
            if (state != null) {
                validateTransitionState(state)
                if (state.phase == TransitionPhase.PENDING_COMMIT && nowUnixMs >= state.expiresAtUnixMs) {
                    updateTransitionPhase(database, workspaceId, peerDeviceId, TransitionPhase.BLOCKED)
                    state = state.copy(phase = TransitionPhase.BLOCKED)
                }
                validateTransitionCryptography(state)
            }
            database.setTransactionSuccessful()
            state?.copyState()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun dueIdentityTransitionAcks(
        workspaceId: ByteArray,
        nowUnixMs: Long,
        limit: Int = 16,
    ): List<PeerIdentityTransitionState> {
        validateIdentifier(workspaceId, "workspaceId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        require(limit in 1..128) { "limit must be 1..128" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            blockExpiredTransitions(database, nowUnixMs)
            val values = database.query(
                TRANSITION_TABLE,
                TRANSITION_COLUMNS,
                "$WORKSPACE_ID = ? AND $PHASE = ? AND $NEXT_ACK_ATTEMPT_AT <= ?",
                arrayOf(
                    workspaceId.toHex(),
                    TransitionPhase.PENDING_COMMIT.name,
                    nowUnixMs.toString(),
                ),
                null,
                null,
                "$NEXT_ACK_ATTEMPT_AT ASC, $DEVICE_ID ASC",
                limit.toString(),
            ).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) {
                        val state = transitionFromCursor(cursor)
                        validateTransitionState(state)
                        validateTransitionCryptography(state)
                        add(state.copyState())
                    }
                }
            }
            database.setTransactionSuccessful()
            values
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun recordIdentityTransitionAckSendAttempt(
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
        transitionId: ByteArray,
        ackSha256: ByteArray,
        nextAttemptAtUnixMs: Long,
        maximumAttempts: Int = 5,
    ) {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(peerDeviceId, "peerDeviceId")
        validateIdentifier(transitionId, "transitionId")
        validateKeyId(ackSha256)
        require(nextAttemptAtUnixMs >= 0) { "nextAttemptAtUnixMs must be non-negative" }
        require(maximumAttempts > 0) { "maximumAttempts must be positive" }
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            val state = findTransition(database, workspaceId, peerDeviceId)
            if (state != null) {
                validateTransitionState(state)
                check(
                    MessageDigest.isEqual(state.transitionId, transitionId) &&
                        MessageDigest.isEqual(state.ackSha256, ackSha256),
                ) { "Identity transition ACK attempt binding changed" }
                if (state.phase == TransitionPhase.PENDING_COMMIT) {
                    val attemptCount = state.ackAttemptCount + 1
                    updateAckSchedule(
                        database,
                        state.copy(
                            nextAckAttemptAtUnixMs = if (attemptCount >= maximumAttempts) {
                                state.expiresAtUnixMs
                            } else {
                                minOf(nextAttemptAtUnixMs, state.expiresAtUnixMs)
                            },
                            ackAttemptCount = attemptCount,
                        ),
                    )
                }
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun allocateIdentityTransitionSequence(recipientKeyId: ByteArray): Long {
        validateKeyId(recipientKeyId)
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val key = recipientKeyId.toHex()
            val current = database.query(
                TRANSITION_SEQUENCE_TABLE,
                arrayOf(NEXT_SEQUENCE),
                "$NEW_KEY_ID = ?",
                arrayOf(key),
                null,
                null,
                null,
                "1",
            ).use { cursor -> if (cursor.moveToFirst()) cursor.getLong(0) else 1L }
            check(current in 1 until Long.MAX_VALUE) { "Identity transition sequence exhausted" }
            database.insertWithOnConflict(
                TRANSITION_SEQUENCE_TABLE,
                null,
                ContentValues(2).apply {
                    put(NEW_KEY_ID, key)
                    put(NEXT_SEQUENCE, current + 1)
                },
                SQLiteDatabase.CONFLICT_REPLACE,
            ).also { check(it != -1L) { "Unable to persist identity transition sequence" } }
            database.setTransactionSuccessful()
            current
        } finally {
            database.endTransaction()
        }
    }

    /** Resolves only a pending successor or exact committed successor for commit authentication. */
    @Synchronized
    fun resolveIdentityCommitSender(
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
        senderKeyId: ByteArray,
        nowUnixMs: Long,
    ): IdentityCommitSenderBinding? {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(peerDeviceId, "peerDeviceId")
        validateKeyId(senderKeyId)
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val approved = find(database, workspaceId, peerDeviceId)
            var transition = findTransition(database, workspaceId, peerDeviceId)
            var result: IdentityCommitSenderBinding? = null
            if (transition != null) {
                validateTransitionState(transition)
                if (transition.phase == TransitionPhase.PENDING_COMMIT &&
                    nowUnixMs >= transition.expiresAtUnixMs
                ) {
                    updateTransitionPhase(
                        database,
                        workspaceId,
                        peerDeviceId,
                        TransitionPhase.BLOCKED,
                    )
                    transition = transition.copy(phase = TransitionPhase.BLOCKED)
                }
                validateTransitionCryptography(transition)
                if (transition.phase == TransitionPhase.PENDING_COMMIT &&
                    approved != null &&
                    MessageDigest.isEqual(approved.keyId, transition.previousKeyId) &&
                    MessageDigest.isEqual(senderKeyId, transition.newKeyId)
                ) {
                    result = IdentityCommitSenderBinding(
                        senderPublicKey = transition.newPublicKey.copyOf(),
                        transitionId = transition.transitionId.copyOf(),
                        previousKeyId = transition.previousKeyId.copyOf(),
                        newKeyId = transition.newKeyId.copyOf(),
                        transitionSha256 = transition.transitionSha256.copyOf(),
                        ackSha256 = transition.ackSha256.copyOf(),
                        alreadyCommitted = false,
                    )
                }
            }
            if (result == null) {
                val tombstone = findTombstone(database, workspaceId, peerDeviceId)
                if (tombstone != null) {
                    validateTombstone(tombstone)
                    if (nowUnixMs >= tombstone.expiresAtUnixMs) {
                        deleteTombstone(database, workspaceId, peerDeviceId)
                    } else if (approved != null &&
                        MessageDigest.isEqual(approved.keyId, tombstone.newKeyId) &&
                        MessageDigest.isEqual(senderKeyId, tombstone.newKeyId)
                    ) {
                        result = IdentityCommitSenderBinding(
                            senderPublicKey = approved.publicKey.copyOf(),
                            transitionId = tombstone.transitionId.copyOf(),
                            previousKeyId = tombstone.previousKeyId.copyOf(),
                            newKeyId = tombstone.newKeyId.copyOf(),
                            transitionSha256 = tombstone.transitionSha256.copyOf(),
                            ackSha256 = tombstone.ackSha256.copyOf(),
                            alreadyCommitted = true,
                        )
                    }
                }
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    /** Atomically promotes the successor pin and retains an exact bounded duplicate record. */
    @Synchronized
    fun commitIdentityTransition(
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
        senderKeyId: ByteArray,
        canonicalCommit: ByteArray,
        nowUnixMs: Long,
    ): CommittedPeerIdentityTransition {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(peerDeviceId, "peerDeviceId")
        validateKeyId(senderKeyId)
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val payload = EncryptedPayloadCodecV1.decode(canonicalCommit)
        require(payload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_COMMIT) {
            "Expected canonical identity key transition commit"
        }
        val commit = payload.identityKeyTransitionCommit
        val commitSha256 = sha256(canonicalCommit)
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val approved = find(database, workspaceId, peerDeviceId)
            val transition = findTransition(database, workspaceId, peerDeviceId)
            val tombstone = findTombstone(database, workspaceId, peerDeviceId)
            val result = if (transition != null) {
                validateTransitionState(transition)
                if (transition.phase == TransitionPhase.BLOCKED ||
                    nowUnixMs >= transition.expiresAtUnixMs
                ) {
                    if (transition.phase != TransitionPhase.BLOCKED) {
                        updateTransitionPhase(
                            database,
                            workspaceId,
                            peerDeviceId,
                            TransitionPhase.BLOCKED,
                        )
                    }
                    database.setTransactionSuccessful()
                    error("Identity transition is blocked after expiry")
                }
                check(
                    approved != null &&
                        MessageDigest.isEqual(approved.keyId, transition.previousKeyId) &&
                        MessageDigest.isEqual(senderKeyId, transition.newKeyId) &&
                        commitMatchesTransition(commit, transition),
                ) { "Identity transition commit binding does not match" }
                check(tombstone == null) { "Identity transition has conflicting committed state" }
                val promoted = ContentValues(2).apply {
                    put(KEY_ID, transition.newKeyId.copyOf())
                    put(PUBLIC_KEY, transition.newPublicKey.copyOf())
                }
                check(database.update(
                    TABLE,
                    promoted,
                    "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
                    arrayOf(workspaceId.toHex(), peerDeviceId.toHex()),
                ) == 1) { "Approved peer disappeared before identity promotion" }
                val committed = TransitionTombstone(
                    workspaceId = workspaceId.copyOf(),
                    peerDeviceId = peerDeviceId.copyOf(),
                    transitionId = transition.transitionId.copyOf(),
                    previousKeyId = transition.previousKeyId.copyOf(),
                    newKeyId = transition.newKeyId.copyOf(),
                    transitionSha256 = transition.transitionSha256.copyOf(),
                    ackSha256 = transition.ackSha256.copyOf(),
                    canonicalCommit = canonicalCommit.copyOf(),
                    commitSha256 = commitSha256,
                    committedAtUnixMs = nowUnixMs,
                    expiresAtUnixMs = Math.addExact(nowUnixMs, IDENTITY_TRANSITION_RETENTION_MS),
                )
                insertTombstone(database, committed)
                deleteTransition(database, workspaceId, peerDeviceId)
                CommittedPeerIdentityTransition(
                    CommitResult.COMMITTED,
                    transition.newKeyId.copyOf(),
                )
            } else {
                check(tombstone != null && approved != null) {
                    "Identity transition commit has no durable successor state"
                }
                validateTombstone(tombstone)
                check(
                    nowUnixMs < tombstone.expiresAtUnixMs &&
                        MessageDigest.isEqual(approved.keyId, tombstone.newKeyId) &&
                        MessageDigest.isEqual(senderKeyId, tombstone.newKeyId) &&
                        MessageDigest.isEqual(tombstone.canonicalCommit, canonicalCommit) &&
                        MessageDigest.isEqual(tombstone.commitSha256, commitSha256) &&
                        commitMatchesTombstone(commit, tombstone),
                ) { "Identity transition duplicate commit binding does not match" }
                CommittedPeerIdentityTransition(
                    CommitResult.ALREADY_COMMITTED,
                    tombstone.newKeyId.copyOf(),
                )
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    fun remove(workspaceId: ByteArray, deviceId: ByteArray) {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(deviceId, "deviceId")
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            val arguments = arrayOf(workspaceId.toHex(), deviceId.toHex())
            database.delete(
                TOMBSTONE_TABLE,
                "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
                arguments,
            )
            database.delete(
                TRANSITION_TABLE,
                "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
                arguments,
            )
            database.delete(
                TABLE,
                "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
                arguments,
            )
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    override fun close() = helper.close()

    fun clear() {
        close()
        check(appContext.deleteDatabase(databaseName) || !appContext.getDatabasePath(databaseName).exists()) {
            "Unable to delete trusted peer store"
        }
    }

    private fun find(
        database: SQLiteDatabase,
        workspaceId: ByteArray,
        deviceId: ByteArray,
    ): PeerRecord? = database.query(
        TABLE,
        arrayOf(KEY_ID, PUBLIC_KEY),
        "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
        arrayOf(workspaceId.toHex(), deviceId.toHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else PeerRecord(
            keyId = cursor.getBlob(0).copyOf(),
            publicKey = cursor.getBlob(1).copyOf(),
        )
    }

    private fun findTransition(
        database: SQLiteDatabase,
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
    ): PeerIdentityTransitionState? = database.query(
        TRANSITION_TABLE,
        TRANSITION_COLUMNS,
        "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
        arrayOf(workspaceId.toHex(), peerDeviceId.toHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else transitionFromCursor(cursor)
    }

    private fun findTombstone(
        database: SQLiteDatabase,
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
    ): TransitionTombstone? = database.query(
        TOMBSTONE_TABLE,
        TOMBSTONE_COLUMNS,
        "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
        arrayOf(workspaceId.toHex(), peerDeviceId.toHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else TransitionTombstone(
            workspaceId = cursor.getString(0).hexToBytes(),
            peerDeviceId = cursor.getString(1).hexToBytes(),
            transitionId = cursor.getBlob(2).copyOf(),
            previousKeyId = cursor.getBlob(3).copyOf(),
            newKeyId = cursor.getBlob(4).copyOf(),
            transitionSha256 = cursor.getBlob(5).copyOf(),
            ackSha256 = cursor.getBlob(6).copyOf(),
            canonicalCommit = cursor.getBlob(7).copyOf(),
            commitSha256 = cursor.getBlob(8).copyOf(),
            committedAtUnixMs = cursor.getLong(9),
            expiresAtUnixMs = cursor.getLong(10),
        )
    }

    private fun insertTombstone(database: SQLiteDatabase, value: TransitionTombstone) {
        database.insertOrThrow(
            TOMBSTONE_TABLE,
            null,
            ContentValues(11).apply {
                put(WORKSPACE_ID, value.workspaceId.toHex())
                put(DEVICE_ID, value.peerDeviceId.toHex())
                put(TRANSITION_ID, value.transitionId)
                put(PREVIOUS_KEY_ID, value.previousKeyId)
                put(NEW_KEY_ID, value.newKeyId)
                put(TRANSITION_SHA256, value.transitionSha256)
                put(ACK_SHA256, value.ackSha256)
                put(CANONICAL_COMMIT, value.canonicalCommit)
                put(COMMIT_SHA256, value.commitSha256)
                put(COMMITTED_AT, value.committedAtUnixMs)
                put(EXPIRES_AT, value.expiresAtUnixMs)
            },
        )
    }

    private fun deleteTombstone(
        database: SQLiteDatabase,
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
    ) {
        database.delete(
            TOMBSTONE_TABLE,
            "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
            arrayOf(workspaceId.toHex(), peerDeviceId.toHex()),
        )
    }

    private fun deleteTransition(
        database: SQLiteDatabase,
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
    ) {
        check(database.delete(
            TRANSITION_TABLE,
            "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
            arrayOf(workspaceId.toHex(), peerDeviceId.toHex()),
        ) == 1) { "Identity transition disappeared before promotion" }
    }

    private fun transitionFromCursor(cursor: android.database.Cursor): PeerIdentityTransitionState =
        PeerIdentityTransitionState(
            workspaceId = cursor.getString(0).hexToBytes(),
            peerDeviceId = cursor.getString(1).hexToBytes(),
            transitionId = cursor.getBlob(2).copyOf(),
            previousKeyId = cursor.getBlob(3).copyOf(),
            newKeyId = cursor.getBlob(4).copyOf(),
            newPublicKey = cursor.getBlob(5).copyOf(),
            canonicalTransition = cursor.getBlob(6).copyOf(),
            transitionSha256 = cursor.getBlob(7).copyOf(),
            canonicalAck = cursor.getBlob(8).copyOf(),
            ackSha256 = cursor.getBlob(9).copyOf(),
            acceptedAtUnixMs = cursor.getLong(10),
            expiresAtUnixMs = cursor.getLong(11),
            nextAckAttemptAtUnixMs = cursor.getLong(12),
            ackAttemptCount = cursor.getInt(13),
            phase = try {
                TransitionPhase.valueOf(cursor.getString(14))
            } catch (error: IllegalArgumentException) {
                throw IllegalStateException("Stored identity transition phase is invalid", error)
            },
        )

    private fun insertTransition(
        database: SQLiteDatabase,
        state: PeerIdentityTransitionState,
    ) {
        database.insertOrThrow(
            TRANSITION_TABLE,
            null,
            ContentValues(15).apply {
                put(WORKSPACE_ID, state.workspaceId.toHex())
                put(DEVICE_ID, state.peerDeviceId.toHex())
                put(TRANSITION_ID, state.transitionId.copyOf())
                put(PREVIOUS_KEY_ID, state.previousKeyId.copyOf())
                put(NEW_KEY_ID, state.newKeyId.copyOf())
                put(NEW_PUBLIC_KEY, state.newPublicKey.copyOf())
                put(CANONICAL_TRANSITION, state.canonicalTransition.copyOf())
                put(TRANSITION_SHA256, state.transitionSha256.copyOf())
                put(CANONICAL_ACK, state.canonicalAck.copyOf())
                put(ACK_SHA256, state.ackSha256.copyOf())
                put(ACCEPTED_AT, state.acceptedAtUnixMs)
                put(EXPIRES_AT, state.expiresAtUnixMs)
                put(NEXT_ACK_ATTEMPT_AT, state.nextAckAttemptAtUnixMs)
                put(ACK_ATTEMPT_COUNT, state.ackAttemptCount)
                put(PHASE, state.phase.name)
            },
        )
    }

    private fun updateAckSchedule(
        database: SQLiteDatabase,
        state: PeerIdentityTransitionState,
    ) {
        check(
            database.update(
                TRANSITION_TABLE,
                ContentValues(2).apply {
                    put(NEXT_ACK_ATTEMPT_AT, state.nextAckAttemptAtUnixMs)
                    put(ACK_ATTEMPT_COUNT, state.ackAttemptCount)
                },
                "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
                arrayOf(state.workspaceId.toHex(), state.peerDeviceId.toHex()),
            ) == 1,
        ) { "Identity transition disappeared before ACK schedule update" }
    }

    private fun blockExpiredTransitions(database: SQLiteDatabase, nowUnixMs: Long) {
        database.update(
            TRANSITION_TABLE,
            ContentValues(1).apply { put(PHASE, TransitionPhase.BLOCKED.name) },
            "$PHASE = ? AND $EXPIRES_AT <= ?",
            arrayOf(TransitionPhase.PENDING_COMMIT.name, nowUnixMs.toString()),
        )
    }

    private fun updateTransitionPhase(
        database: SQLiteDatabase,
        workspaceId: ByteArray,
        peerDeviceId: ByteArray,
        phase: TransitionPhase,
    ) {
        check(
            database.update(
                TRANSITION_TABLE,
                ContentValues(1).apply { put(PHASE, phase.name) },
                "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
                arrayOf(workspaceId.toHex(), peerDeviceId.toHex()),
            ) == 1,
        ) { "Identity transition disappeared before phase update" }
    }

    private fun validateTransitionState(state: PeerIdentityTransitionState) {
        validateIdentifier(state.workspaceId, "workspaceId")
        validateIdentifier(state.peerDeviceId, "peerDeviceId")
        validateIdentifier(state.transitionId, "transitionId")
        validateKeyId(state.previousKeyId)
        validateKeyId(state.newKeyId)
        validateKeyId(state.transitionSha256)
        validateKeyId(state.ackSha256)
        AuthenticatedHpke.requireValidPublicKey(state.newPublicKey)
        check(state.acceptedAtUnixMs >= 0) { "Stored identity transition acceptance is invalid" }
        check(state.nextAckAttemptAtUnixMs >= 0) {
            "Stored identity transition ACK attempt time is invalid"
        }
        check(state.ackAttemptCount >= 0) {
            "Stored identity transition ACK attempt count is invalid"
        }
        check(
            state.expiresAtUnixMs == Math.addExact(
                state.acceptedAtUnixMs,
                IDENTITY_TRANSITION_RETENTION_MS,
            ),
        ) { "Stored identity transition expiry is invalid" }
    }

    private fun validateTransitionCryptography(state: PeerIdentityTransitionState) {
        val transitionPayload = EncryptedPayloadCodecV1.decode(state.canonicalTransition)
        check(transitionPayload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION) {
            "Stored identity transition payload has wrong body"
        }
        val transition = transitionPayload.identityKeyTransition
        check(
            MessageDigest.isEqual(transition.transitionId.toByteArray(), state.transitionId) &&
                MessageDigest.isEqual(transition.previousKeyId.toByteArray(), state.previousKeyId) &&
                MessageDigest.isEqual(transition.newKeyId.toByteArray(), state.newKeyId) &&
                MessageDigest.isEqual(transition.newPublicKey.toByteArray(), state.newPublicKey) &&
                MessageDigest.isEqual(sha256(state.canonicalTransition), state.transitionSha256),
        ) { "Stored identity transition binding is corrupt" }
        val ackPayload = EncryptedPayloadCodecV1.decode(state.canonicalAck)
        check(ackPayload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_ACK) {
            "Stored identity transition acknowledgement has wrong body"
        }
        val ack = ackPayload.identityKeyTransitionAck
        check(
            MessageDigest.isEqual(ack.transitionId.toByteArray(), state.transitionId) &&
                MessageDigest.isEqual(ack.previousKeyId.toByteArray(), state.previousKeyId) &&
                MessageDigest.isEqual(ack.newKeyId.toByteArray(), state.newKeyId) &&
                MessageDigest.isEqual(ack.transitionSha256.toByteArray(), state.transitionSha256) &&
                MessageDigest.isEqual(sha256(state.canonicalAck), state.ackSha256),
        ) { "Stored identity transition acknowledgement binding is corrupt" }
    }

    private fun validateTombstone(value: TransitionTombstone) {
        validateIdentifier(value.workspaceId, "workspaceId")
        validateIdentifier(value.peerDeviceId, "peerDeviceId")
        validateIdentifier(value.transitionId, "transitionId")
        validateKeyId(value.previousKeyId)
        validateKeyId(value.newKeyId)
        validateKeyId(value.transitionSha256)
        validateKeyId(value.ackSha256)
        validateKeyId(value.commitSha256)
        check(value.committedAtUnixMs >= 0 &&
            value.expiresAtUnixMs == Math.addExact(
                value.committedAtUnixMs,
                IDENTITY_TRANSITION_RETENTION_MS,
            )) { "Stored identity transition tombstone expiry is invalid" }
        val payload = EncryptedPayloadCodecV1.decode(value.canonicalCommit)
        check(payload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_COMMIT &&
            MessageDigest.isEqual(sha256(value.canonicalCommit), value.commitSha256) &&
            commitMatchesTombstone(payload.identityKeyTransitionCommit, value)) {
            "Stored identity transition tombstone binding is corrupt"
        }
    }

    private fun commitMatchesTransition(
        commit: IdentityKeyTransitionCommit,
        transition: PeerIdentityTransitionState,
    ): Boolean = MessageDigest.isEqual(commit.transitionId.toByteArray(), transition.transitionId) &&
        MessageDigest.isEqual(commit.previousKeyId.toByteArray(), transition.previousKeyId) &&
        MessageDigest.isEqual(commit.newKeyId.toByteArray(), transition.newKeyId) &&
        MessageDigest.isEqual(commit.transitionSha256.toByteArray(), transition.transitionSha256) &&
        MessageDigest.isEqual(commit.ackSha256.toByteArray(), transition.ackSha256)

    private fun commitMatchesTombstone(
        commit: IdentityKeyTransitionCommit,
        tombstone: TransitionTombstone,
    ): Boolean = MessageDigest.isEqual(commit.transitionId.toByteArray(), tombstone.transitionId) &&
        MessageDigest.isEqual(commit.previousKeyId.toByteArray(), tombstone.previousKeyId) &&
        MessageDigest.isEqual(commit.newKeyId.toByteArray(), tombstone.newKeyId) &&
        MessageDigest.isEqual(commit.transitionSha256.toByteArray(), tombstone.transitionSha256) &&
        MessageDigest.isEqual(commit.ackSha256.toByteArray(), tombstone.ackSha256)

    private fun sameAcceptedTransition(
        left: PeerIdentityTransitionState,
        right: PeerIdentityTransitionState,
    ): Boolean = MessageDigest.isEqual(left.transitionId, right.transitionId) &&
        MessageDigest.isEqual(left.previousKeyId, right.previousKeyId) &&
        MessageDigest.isEqual(left.newKeyId, right.newKeyId) &&
        MessageDigest.isEqual(left.newPublicKey, right.newPublicKey) &&
        MessageDigest.isEqual(left.canonicalTransition, right.canonicalTransition) &&
        MessageDigest.isEqual(left.transitionSha256, right.transitionSha256) &&
        MessageDigest.isEqual(left.canonicalAck, right.canonicalAck) &&
        MessageDigest.isEqual(left.ackSha256, right.ackSha256)

    private fun PeerIdentityTransitionState.copyState(): PeerIdentityTransitionState = copy(
        workspaceId = workspaceId.copyOf(),
        peerDeviceId = peerDeviceId.copyOf(),
        transitionId = transitionId.copyOf(),
        previousKeyId = previousKeyId.copyOf(),
        newKeyId = newKeyId.copyOf(),
        newPublicKey = newPublicKey.copyOf(),
        canonicalTransition = canonicalTransition.copyOf(),
        transitionSha256 = transitionSha256.copyOf(),
        canonicalAck = canonicalAck.copyOf(),
        ackSha256 = ackSha256.copyOf(),
    )

    private fun validateIdentifier(value: ByteArray, name: String) {
        require(value.size == IDENTIFIER_BYTES && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero $IDENTIFIER_BYTES-byte value"
        }
    }

    private fun validateKeyId(value: ByteArray) {
        require(value.size == KEY_ID_BYTES && value.any { it.toInt() != 0 }) {
            "keyId must be a non-zero $KEY_ID_BYTES-byte value"
        }
    }

    private data class PeerRecord(val keyId: ByteArray, val publicKey: ByteArray)

    private class DatabaseHelper(context: Context, name: String) :
        SQLiteOpenHelper(context, name, null, DATABASE_VERSION) {
        override fun onCreate(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TABLE (" +
                    "$WORKSPACE_ID TEXT NOT NULL, " +
                    "$DEVICE_ID TEXT NOT NULL, " +
                    "$KEY_ID BLOB NOT NULL, " +
                    "$PUBLIC_KEY BLOB NOT NULL, " +
                    "PRIMARY KEY ($WORKSPACE_ID, $DEVICE_ID))",
            )
            createTransitionTable(database)
            createTransitionSequenceTable(database)
            createTombstoneTable(database)
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            var version = oldVersion
            if (version == 1) {
                createTransitionTableV2(database)
                version = 2
            }
            if (version == 2) {
                database.execSQL("ALTER TABLE $TRANSITION_TABLE ADD COLUMN $NEXT_ACK_ATTEMPT_AT INTEGER")
                database.execSQL(
                    "ALTER TABLE $TRANSITION_TABLE ADD COLUMN $ACK_ATTEMPT_COUNT INTEGER NOT NULL DEFAULT 0",
                )
                database.execSQL(
                    "UPDATE $TRANSITION_TABLE SET $NEXT_ACK_ATTEMPT_AT = $ACCEPTED_AT " +
                        "WHERE $NEXT_ACK_ATTEMPT_AT IS NULL",
                )
                createTransitionSequenceTable(database)
                version = 3
            }
            if (version == 3) {
                createTombstoneTable(database)
                version = 4
            }
            if (version != newVersion) {
                throw IllegalStateException("Trusted peer migration missing: $oldVersion -> $newVersion")
            }
        }

        private fun createTransitionTableV2(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TRANSITION_TABLE (" +
                    "$WORKSPACE_ID TEXT NOT NULL, " +
                    "$DEVICE_ID TEXT NOT NULL, " +
                    "$TRANSITION_ID BLOB NOT NULL, " +
                    "$PREVIOUS_KEY_ID BLOB NOT NULL, " +
                    "$NEW_KEY_ID BLOB NOT NULL, " +
                    "$NEW_PUBLIC_KEY BLOB NOT NULL, " +
                    "$CANONICAL_TRANSITION BLOB NOT NULL, " +
                    "$TRANSITION_SHA256 BLOB NOT NULL, " +
                    "$CANONICAL_ACK BLOB NOT NULL, " +
                    "$ACK_SHA256 BLOB NOT NULL, " +
                    "$ACCEPTED_AT INTEGER NOT NULL, " +
                    "$EXPIRES_AT INTEGER NOT NULL, " +
                    "$PHASE TEXT NOT NULL, " +
                    "PRIMARY KEY ($WORKSPACE_ID, $DEVICE_ID))",
            )
        }

        private fun createTransitionSequenceTable(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TRANSITION_SEQUENCE_TABLE (" +
                    "$NEW_KEY_ID TEXT PRIMARY KEY, " +
                    "$NEXT_SEQUENCE INTEGER NOT NULL)",
            )
        }

        private fun createTombstoneTable(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TOMBSTONE_TABLE (" +
                    "$WORKSPACE_ID TEXT NOT NULL, $DEVICE_ID TEXT NOT NULL, " +
                    "$TRANSITION_ID BLOB NOT NULL, $PREVIOUS_KEY_ID BLOB NOT NULL, " +
                    "$NEW_KEY_ID BLOB NOT NULL, $TRANSITION_SHA256 BLOB NOT NULL, " +
                    "$ACK_SHA256 BLOB NOT NULL, $CANONICAL_COMMIT BLOB NOT NULL, " +
                    "$COMMIT_SHA256 BLOB NOT NULL, $COMMITTED_AT INTEGER NOT NULL, " +
                    "$EXPIRES_AT INTEGER NOT NULL, " +
                    "PRIMARY KEY ($WORKSPACE_ID, $DEVICE_ID))",
            )
        }

        private fun createTransitionTable(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TRANSITION_TABLE (" +
                    "$WORKSPACE_ID TEXT NOT NULL, " +
                    "$DEVICE_ID TEXT NOT NULL, " +
                    "$TRANSITION_ID BLOB NOT NULL, " +
                    "$PREVIOUS_KEY_ID BLOB NOT NULL, " +
                    "$NEW_KEY_ID BLOB NOT NULL, " +
                    "$NEW_PUBLIC_KEY BLOB NOT NULL, " +
                    "$CANONICAL_TRANSITION BLOB NOT NULL, " +
                    "$TRANSITION_SHA256 BLOB NOT NULL, " +
                    "$CANONICAL_ACK BLOB NOT NULL, " +
                    "$ACK_SHA256 BLOB NOT NULL, " +
                    "$ACCEPTED_AT INTEGER NOT NULL, " +
                    "$EXPIRES_AT INTEGER NOT NULL, " +
                    "$NEXT_ACK_ATTEMPT_AT INTEGER NOT NULL, " +
                    "$ACK_ATTEMPT_COUNT INTEGER NOT NULL, " +
                    "$PHASE TEXT NOT NULL, " +
                    "PRIMARY KEY ($WORKSPACE_ID, $DEVICE_ID))",
            )
        }
    }

    private companion object {
        const val DATABASE_VERSION = 4
        const val IDENTIFIER_BYTES = 16
        const val KEY_ID_BYTES = 32
        const val TABLE = "approved_peer"
        const val TRANSITION_TABLE = "peer_identity_transition"
        const val TRANSITION_SEQUENCE_TABLE = "identity_transition_sequence"
        const val TOMBSTONE_TABLE = "peer_identity_transition_tombstone"
        const val WORKSPACE_ID = "workspace_id"
        const val DEVICE_ID = "device_id"
        const val KEY_ID = "key_id"
        const val PUBLIC_KEY = "public_key"
        const val TRANSITION_ID = "transition_id"
        const val PREVIOUS_KEY_ID = "previous_key_id"
        const val NEW_KEY_ID = "new_key_id"
        const val NEW_PUBLIC_KEY = "new_public_key"
        const val CANONICAL_TRANSITION = "canonical_transition"
        const val TRANSITION_SHA256 = "transition_sha256"
        const val CANONICAL_ACK = "canonical_ack"
        const val ACK_SHA256 = "ack_sha256"
        const val ACCEPTED_AT = "accepted_at_unix_ms"
        const val EXPIRES_AT = "expires_at_unix_ms"
        const val NEXT_ACK_ATTEMPT_AT = "next_ack_attempt_at_unix_ms"
        const val ACK_ATTEMPT_COUNT = "ack_attempt_count"
        const val PHASE = "phase"
        const val NEXT_SEQUENCE = "next_sequence"
        const val CANONICAL_COMMIT = "canonical_commit"
        const val COMMIT_SHA256 = "commit_sha256"
        const val COMMITTED_AT = "committed_at_unix_ms"
        const val IDENTITY_TRANSITION_RETENTION_MS = 7L * 24 * 60 * 60 * 1_000
        val TOMBSTONE_COLUMNS = arrayOf(
            WORKSPACE_ID,
            DEVICE_ID,
            TRANSITION_ID,
            PREVIOUS_KEY_ID,
            NEW_KEY_ID,
            TRANSITION_SHA256,
            ACK_SHA256,
            CANONICAL_COMMIT,
            COMMIT_SHA256,
            COMMITTED_AT,
            EXPIRES_AT,
        )
        val TRANSITION_COLUMNS = arrayOf(
            WORKSPACE_ID,
            DEVICE_ID,
            TRANSITION_ID,
            PREVIOUS_KEY_ID,
            NEW_KEY_ID,
            NEW_PUBLIC_KEY,
            CANONICAL_TRANSITION,
            TRANSITION_SHA256,
            CANONICAL_ACK,
            ACK_SHA256,
            ACCEPTED_AT,
            EXPIRES_AT,
            NEXT_ACK_ATTEMPT_AT,
            ACK_ATTEMPT_COUNT,
            PHASE,
        )

        fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

        fun String.hexToBytes(): ByteArray {
            check(length % 2 == 0) { "Stored hex value has invalid length" }
            return ByteArray(length / 2) { index ->
                substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
