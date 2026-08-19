package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionCommit
import java.security.MessageDigest

class AndroidLocalIdentityTransitionStore(
    context: Context,
    storeName: String = "default",
) : AutoCloseable {
    enum class SessionPhase { AWAITING_ACKS, RECOVERY_AUTHORIZED, PROMOTION_COMPLETED, BLOCKED }
    enum class PeerPhase { AWAITING_ACK, COMMIT_QUEUED }
    enum class AcceptResult { ACCEPTED, ALREADY_ACCEPTED }

    data class PeerSnapshot(val deviceId: ByteArray, val keyId: ByteArray)

    data class Session(
        val workspaceId: ByteArray,
        val localDeviceId: ByteArray,
        val transitionId: ByteArray,
        val previousKeyId: ByteArray,
        val newKeyId: ByteArray,
        val newPublicKey: ByteArray,
        val canonicalTransition: ByteArray,
        val transitionSha256: ByteArray,
        val createdAtUnixMs: Long,
        val expiresAtUnixMs: Long,
        val phase: SessionPhase,
    )

    data class PeerState(
        val transitionId: ByteArray,
        val deviceId: ByteArray,
        val keyId: ByteArray,
        val canonicalAck: ByteArray?,
        val ackSha256: ByteArray?,
        val canonicalCommit: ByteArray?,
        val nextCommitAttemptAtUnixMs: Long,
        val commitAttemptCount: Int,
        val phase: PeerPhase,
    )

    data class AckBinding(
        val workspaceId: ByteArray,
        val localDeviceId: ByteArray,
        val senderDeviceId: ByteArray,
        val senderKeyId: ByteArray,
        val transitionId: ByteArray,
        val previousKeyId: ByteArray,
        val newKeyId: ByteArray,
        val transitionSha256: ByteArray,
    )

    data class AcceptedAck(val result: AcceptResult, val peer: PeerState)

    private val appContext = context.applicationContext
    private val safeName = storeName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "storeName must be 1-64 URL-safe characters"
        }
    }
    private val databaseName = "syncnotifications-local-identity-transition-$safeName.db"
    private val helper = DatabaseHelper(appContext, databaseName)

    @Synchronized
    fun create(
        workspaceId: ByteArray,
        localDeviceId: ByteArray,
        canonicalTransition: ByteArray,
        peers: List<PeerSnapshot>,
        nowUnixMs: Long,
    ): Session {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(localDeviceId, "localDeviceId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        require(peers.size in 1..128) { "Peer snapshot size is out of range" }
        val payload = EncryptedPayloadCodecV1.decode(canonicalTransition)
        require(payload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION) {
            "Expected canonical identity key transition payload"
        }
        val transition = payload.identityKeyTransition
        val session = Session(
            workspaceId = workspaceId.copyOf(),
            localDeviceId = localDeviceId.copyOf(),
            transitionId = transition.transitionId.toByteArray(),
            previousKeyId = transition.previousKeyId.toByteArray(),
            newKeyId = transition.newKeyId.toByteArray(),
            newPublicKey = transition.newPublicKey.toByteArray(),
            canonicalTransition = canonicalTransition.copyOf(),
            transitionSha256 = sha256(canonicalTransition),
            createdAtUnixMs = nowUnixMs,
            expiresAtUnixMs = Math.addExact(nowUnixMs, RETENTION_MS),
            phase = SessionPhase.AWAITING_ACKS,
        )
        val peerStates = peers.map { peer ->
            validateIdentifier(peer.deviceId, "peerDeviceId")
            validateDigest(peer.keyId, "peerKeyId")
            PeerState(
                transitionId = session.transitionId.copyOf(),
                deviceId = peer.deviceId.copyOf(),
                keyId = peer.keyId.copyOf(),
                canonicalAck = null,
                ackSha256 = null,
                canonicalCommit = null,
                nextCommitAttemptAtUnixMs = nowUnixMs,
                commitAttemptCount = 0,
                phase = PeerPhase.AWAITING_ACK,
            )
        }
        check(peerStates.map { it.deviceId.toHex() }.toSet().size == peerStates.size) {
            "Peer snapshot contains a duplicate device"
        }
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            check(findSession(database) == null) { "An active local identity transition already exists" }
            insertSession(database, session)
            peerStates.forEach { insertPeer(database, it) }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
        return session.copyState()
    }

    @Synchronized
    fun loadSession(nowUnixMs: Long): Session? {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val session = findSession(database)
            val current = session?.let {
                validateSession(it)
                blockIfExpired(database, it, nowUnixMs)
            }
            database.setTransactionSuccessful()
            current?.copyState()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun expectedAckBinding(senderDeviceId: ByteArray, nowUnixMs: Long): AckBinding? {
        validateIdentifier(senderDeviceId, "senderDeviceId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val session = findSession(database) ?: return null
            validateSession(session)
            val current = blockIfExpired(database, session, nowUnixMs)
            val peer = findPeer(database, current.transitionId, senderDeviceId) ?: return null
            validatePeer(peer)
            validatePeerCryptography(current, peer)
            database.setTransactionSuccessful()
            AckBinding(
                workspaceId = current.workspaceId.copyOf(),
                localDeviceId = current.localDeviceId.copyOf(),
                senderDeviceId = peer.deviceId.copyOf(),
                senderKeyId = peer.keyId.copyOf(),
                transitionId = current.transitionId.copyOf(),
                previousKeyId = current.previousKeyId.copyOf(),
                newKeyId = current.newKeyId.copyOf(),
                transitionSha256 = current.transitionSha256.copyOf(),
            )
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun acceptAck(
        senderDeviceId: ByteArray,
        senderKeyId: ByteArray,
        canonicalAck: ByteArray,
        nowUnixMs: Long,
    ): AcceptedAck {
        validateIdentifier(senderDeviceId, "senderDeviceId")
        validateDigest(senderKeyId, "senderKeyId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val preflight = expectedAckBinding(senderDeviceId, nowUnixMs)
            ?: error("Identity transition acknowledgement sender is not in the peer snapshot")
        check(MessageDigest.isEqual(preflight.senderKeyId, senderKeyId)) {
            "Identity transition acknowledgement sender is not in the peer snapshot"
        }
        val payload = EncryptedPayloadCodecV1.decode(canonicalAck)
        require(payload.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_ACK) {
            "Expected canonical identity key transition acknowledgement"
        }
        val ack = payload.identityKeyTransitionAck
        val ackSha256 = sha256(canonicalAck)
        val canonicalCommit = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(EncryptedPayloadCodecV1.IDENTITY_LIFECYCLE_SCHEMA_VERSION)
                .setIdentityKeyTransitionCommit(
                    IdentityKeyTransitionCommit.newBuilder()
                        .setTransitionId(ack.transitionId)
                        .setPreviousKeyId(ack.previousKeyId)
                        .setNewKeyId(ack.newKeyId)
                        .setTransitionSha256(ack.transitionSha256)
                        .setAckSha256(ByteString.copyFrom(ackSha256)),
                )
                .build(),
        )
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val session = findSession(database) ?: error("No active local identity transition exists")
            validateSession(session)
            val current = blockIfExpired(database, session, nowUnixMs)
            check(current.phase != SessionPhase.BLOCKED) {
                "Local identity transition is blocked after expiry"
            }
            check(
                MessageDigest.isEqual(ack.transitionId.toByteArray(), current.transitionId) &&
                    MessageDigest.isEqual(ack.previousKeyId.toByteArray(), current.previousKeyId) &&
                    MessageDigest.isEqual(ack.newKeyId.toByteArray(), current.newKeyId) &&
                    MessageDigest.isEqual(ack.transitionSha256.toByteArray(), current.transitionSha256),
            ) { "Identity transition acknowledgement binding does not match" }
            val peer = findPeer(database, current.transitionId, senderDeviceId)
                ?: error("Identity transition acknowledgement sender is not in the peer snapshot")
            validatePeer(peer)
            check(MessageDigest.isEqual(peer.keyId, senderKeyId)) {
                "Identity transition acknowledgement sender is not in the peer snapshot"
            }
            val result = if (peer.phase == PeerPhase.COMMIT_QUEUED) {
                check(
                    optionalEquals(peer.canonicalAck, canonicalAck) &&
                        optionalEquals(peer.ackSha256, ackSha256) &&
                        optionalEquals(peer.canonicalCommit, canonicalCommit),
                ) { "Peer acknowledgement is already bound to different bytes" }
                val reactivated = peer.copy(
                    nextCommitAttemptAtUnixMs = nowUnixMs,
                    commitAttemptCount = 0,
                )
                updatePeer(database, reactivated)
                AcceptedAck(AcceptResult.ALREADY_ACCEPTED, reactivated.copyState())
            } else {
                val committed = peer.copy(
                    canonicalAck = canonicalAck.copyOf(),
                    ackSha256 = ackSha256,
                    canonicalCommit = canonicalCommit,
                    nextCommitAttemptAtUnixMs = nowUnixMs,
                    commitAttemptCount = 0,
                    phase = PeerPhase.COMMIT_QUEUED,
                )
                updatePeer(database, committed)
                AcceptedAck(AcceptResult.ACCEPTED, committed.copyState())
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun dueTransitions(
        workspaceId: ByteArray,
        nowUnixMs: Long,
        limit: Int = 16,
    ): List<Pair<Session, PeerState>> {
        validateIdentifier(workspaceId, "workspaceId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        require(limit in 1..128) { "limit must be 1..128" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val session = findSession(database) ?: return emptyList()
            validateSession(session)
            val current = blockIfExpired(database, session, nowUnixMs)
            val values = if (
                current.phase == SessionPhase.AWAITING_ACKS &&
                MessageDigest.isEqual(current.workspaceId, workspaceId)
            ) {
                database.query(
                    PEER_TABLE,
                    PEER_COLUMNS,
                    "$TRANSITION_ID = ? AND $PHASE = ? AND $NEXT_COMMIT_ATTEMPT_AT <= ?",
                    arrayOf(
                        current.transitionId.toHex(),
                        PeerPhase.AWAITING_ACK.name,
                        nowUnixMs.toString(),
                    ),
                    null,
                    null,
                    "$NEXT_COMMIT_ATTEMPT_AT ASC, $PEER_DEVICE_ID ASC",
                    limit.toString(),
                ).use { cursor ->
                    buildList {
                        while (cursor.moveToNext()) {
                            val peer = peerFromCursor(cursor, current.transitionId)
                            validatePeer(peer)
                            add(current.copyState() to peer.copyState())
                        }
                    }
                }
            } else {
                emptyList()
            }
            database.setTransactionSuccessful()
            values
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun recordTransitionSendAttempt(
        peerDeviceId: ByteArray,
        transitionId: ByteArray,
        transitionSha256: ByteArray,
        nextAttemptAtUnixMs: Long,
        maximumAttempts: Int = 5,
    ) {
        validateIdentifier(peerDeviceId, "peerDeviceId")
        validateIdentifier(transitionId, "transitionId")
        validateDigest(transitionSha256, "transitionSha256")
        require(nextAttemptAtUnixMs >= 0) { "nextAttemptAtUnixMs must be non-negative" }
        require(maximumAttempts > 0) { "maximumAttempts must be positive" }
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            val session = findSession(database)
            if (session != null) {
                validateSession(session)
                check(MessageDigest.isEqual(session.transitionId, transitionId) &&
                    MessageDigest.isEqual(session.transitionSha256, transitionSha256)) {
                    "Identity transition delivery attempt binding changed"
                }
                val peer = findPeer(database, session.transitionId, peerDeviceId)
                if (peer != null && session.phase == SessionPhase.AWAITING_ACKS &&
                    peer.phase == PeerPhase.AWAITING_ACK
                ) {
                    val attemptCount = Math.addExact(peer.commitAttemptCount, 1)
                    updatePeer(database, peer.copy(
                        commitAttemptCount = attemptCount,
                        nextCommitAttemptAtUnixMs = if (attemptCount >= maximumAttempts) {
                            session.expiresAtUnixMs
                        } else {
                            minOf(nextAttemptAtUnixMs, session.expiresAtUnixMs)
                        },
                    ))
                }
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun dueCommits(
        workspaceId: ByteArray,
        nowUnixMs: Long,
        limit: Int = 16,
    ): List<Pair<Session, PeerState>> {
        validateIdentifier(workspaceId, "workspaceId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        require(limit in 1..128) { "limit must be 1..128" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val session = findSession(database) ?: return emptyList()
            validateSession(session)
            val current = blockIfExpired(database, session, nowUnixMs)
            val values = if (
                current.phase != SessionPhase.BLOCKED &&
                MessageDigest.isEqual(current.workspaceId, workspaceId)
            ) {
                database.query(
                    PEER_TABLE,
                    PEER_COLUMNS,
                    "$TRANSITION_ID = ? AND $PHASE = ? AND $NEXT_COMMIT_ATTEMPT_AT <= ?",
                    arrayOf(
                        current.transitionId.toHex(),
                        PeerPhase.COMMIT_QUEUED.name,
                        nowUnixMs.toString(),
                    ),
                    null,
                    null,
                    "$NEXT_COMMIT_ATTEMPT_AT ASC, $PEER_DEVICE_ID ASC",
                    limit.toString(),
                ).use { cursor ->
                    buildList {
                        while (cursor.moveToNext()) {
                            val peer = peerFromCursor(cursor, current.transitionId)
                            validatePeer(peer)
                            validatePeerCryptography(current, peer)
                            add(current.copyState() to peer.copyState())
                        }
                    }
                }
            } else {
                emptyList()
            }
            database.setTransactionSuccessful()
            values
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun recordCommitSendAttempt(
        peerDeviceId: ByteArray,
        transitionId: ByteArray,
        ackSha256: ByteArray,
        nextAttemptAtUnixMs: Long,
        maximumAttempts: Int = 5,
    ) {
        validateIdentifier(peerDeviceId, "peerDeviceId")
        validateIdentifier(transitionId, "transitionId")
        validateDigest(ackSha256, "ackSha256")
        require(nextAttemptAtUnixMs >= 0) { "nextAttemptAtUnixMs must be non-negative" }
        require(maximumAttempts > 0) { "maximumAttempts must be positive" }
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            val session = findSession(database)
            if (session != null) {
                validateSession(session)
                val peer = findPeer(database, session.transitionId, peerDeviceId)
                if (peer != null) {
                    validatePeer(peer)
                    check(
                        MessageDigest.isEqual(peer.transitionId, transitionId) &&
                            optionalEquals(peer.ackSha256, ackSha256),
                    ) { "Identity transition commit attempt binding changed" }
                    if (session.phase != SessionPhase.BLOCKED &&
                        peer.phase == PeerPhase.COMMIT_QUEUED
                    ) {
                        val attemptCount = peer.commitAttemptCount + 1
                        updatePeer(
                            database,
                            peer.copy(
                                nextCommitAttemptAtUnixMs = if (
                                    session.phase == SessionPhase.RECOVERY_AUTHORIZED
                                ) {
                                    if (attemptCount >= maximumAttempts) Long.MAX_VALUE
                                    else nextAttemptAtUnixMs
                                } else if (attemptCount >= maximumAttempts) {
                                    session.expiresAtUnixMs
                                } else {
                                    minOf(nextAttemptAtUnixMs, session.expiresAtUnixMs)
                                },
                                commitAttemptCount = attemptCount,
                            ),
                        )
                    }
                }
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun allocateCommitSequence(recipientKeyId: ByteArray): Long {
        validateDigest(recipientKeyId, "recipientKeyId")
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val key = recipientKeyId.toHex()
            val current = database.query(
                SEQUENCE_TABLE,
                arrayOf(NEXT_SEQUENCE),
                "$PEER_KEY_ID = ?",
                arrayOf(key),
                null,
                null,
                null,
                "1",
            ).use { cursor -> if (cursor.moveToFirst()) cursor.getLong(0) else 1L }
            check(current in 1 until Long.MAX_VALUE) { "Identity transition commit sequence exhausted" }
            check(database.insertWithOnConflict(
                SEQUENCE_TABLE,
                null,
                ContentValues(2).apply {
                    put(PEER_KEY_ID, key)
                    put(NEXT_SEQUENCE, current + 1)
                },
                SQLiteDatabase.CONFLICT_REPLACE,
            ) != -1L) { "Unable to persist identity transition commit sequence" }
            database.setTransactionSuccessful()
            current
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun promotionReadiness(nowUnixMs: Long): Session? {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val session = findSession(database) ?: return null
            validateSession(session)
            val current = blockIfExpired(database, session, nowUnixMs)
            val ready = if (
                current.phase == SessionPhase.AWAITING_ACKS ||
                current.phase == SessionPhase.RECOVERY_AUTHORIZED
            ) {
                database.rawQuery(
                    "SELECT COUNT(*), SUM(CASE WHEN $PHASE = ? THEN 1 ELSE 0 END) " +
                        "FROM $PEER_TABLE WHERE $TRANSITION_ID = ?",
                    arrayOf(PeerPhase.COMMIT_QUEUED.name, current.transitionId.toHex()),
                ).use { cursor ->
                    check(cursor.moveToFirst())
                    val total = cursor.getLong(0)
                    total > 0 && cursor.getLong(1) == total
                }
            } else {
                false
            }
            database.setTransactionSuccessful()
            if (ready) current.copyState() else null
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun markPromotionCompleted(
        transitionId: ByteArray,
        previousKeyId: ByteArray,
        newKeyId: ByteArray,
    ) {
        validateIdentifier(transitionId, "transitionId")
        validateDigest(previousKeyId, "previousKeyId")
        validateDigest(newKeyId, "newKeyId")
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            val session = findSession(database)
            check(session != null &&
                MessageDigest.isEqual(session.transitionId, transitionId) &&
                MessageDigest.isEqual(session.previousKeyId, previousKeyId) &&
                MessageDigest.isEqual(session.newKeyId, newKeyId) &&
                session.phase != SessionPhase.BLOCKED) {
                "Local identity promotion completion binding does not match"
            }
            if (session.phase != SessionPhase.PROMOTION_COMPLETED) {
                check(database.update(
                    SESSION_TABLE,
                    ContentValues(1).apply { put(PHASE, SessionPhase.PROMOTION_COMPLETED.name) },
                    "$ID = ?",
                    arrayOf(SESSION_ID.toString()),
                ) == 1) { "Local identity transition disappeared before promotion completion" }
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun loadPeer(senderDeviceId: ByteArray, nowUnixMs: Long): PeerState? {
        validateIdentifier(senderDeviceId, "senderDeviceId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val session = findSession(database) ?: return null
            val current = blockIfExpired(database, session, nowUnixMs)
            val peer = findPeer(database, current.transitionId, senderDeviceId)
            peer?.let {
                validatePeer(it)
                validatePeerCryptography(current, it)
            }
            database.setTransactionSuccessful()
            peer?.copyState()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun listPeers(nowUnixMs: Long): List<PeerState> {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val session = findSession(database) ?: return emptyList()
            val current = blockIfExpired(database, session, nowUnixMs)
            val peers = database.query(
                PEER_TABLE,
                PEER_COLUMNS,
                "$TRANSITION_ID = ?",
                arrayOf(current.transitionId.toHex()),
                null,
                null,
                "$PEER_DEVICE_ID ASC",
            ).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) {
                        val peer = peerFromCursor(cursor, current.transitionId)
                        validatePeer(peer)
                        validatePeerCryptography(current, peer)
                        add(peer.copyState())
                    }
                }
            }
            database.setTransactionSuccessful()
            peers
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun removePeerFromSnapshot(
        peerDeviceId: ByteArray,
        peerKeyId: ByteArray,
        transitionId: ByteArray,
    ): Boolean {
        validateIdentifier(peerDeviceId, "peerDeviceId")
        validateDigest(peerKeyId, "peerKeyId")
        validateIdentifier(transitionId, "transitionId")
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val session = findSession(database)
            check(session != null && MessageDigest.isEqual(session.transitionId, transitionId)) {
                "Identity transition peer removal binding does not match"
            }
            validateSession(session)
            check(session.phase != SessionPhase.PROMOTION_COMPLETED) {
                "Completed identity transition snapshot cannot be changed"
            }
            val peer = findPeer(database, transitionId, peerDeviceId)
            val removed = if (peer == null) {
                false
            } else {
                validatePeer(peer)
                check(MessageDigest.isEqual(peer.keyId, peerKeyId)) {
                    "Identity transition peer removal key binding does not match"
                }
                check(database.delete(
                    PEER_TABLE,
                    "$TRANSITION_ID = ? AND $PEER_DEVICE_ID = ?",
                    arrayOf(transitionId.toHex(), peerDeviceId.toHex()),
                ) == 1) { "Identity transition peer disappeared during removal" }
                true
            }
            val peerCounts = database.rawQuery(
                "SELECT COUNT(*), SUM(CASE WHEN $PHASE = ? THEN 1 ELSE 0 END) " +
                    "FROM $PEER_TABLE WHERE $TRANSITION_ID = ?",
                arrayOf(PeerPhase.COMMIT_QUEUED.name, transitionId.toHex()),
            ).use { cursor ->
                check(cursor.moveToFirst())
                cursor.getLong(0) to cursor.getLong(1)
            }
            val nextPhase = when {
                peerCounts.first == 0L -> SessionPhase.BLOCKED
                session.phase == SessionPhase.BLOCKED &&
                    peerCounts.second == peerCounts.first -> SessionPhase.RECOVERY_AUTHORIZED
                else -> null
            }
            if (nextPhase != null && nextPhase != session.phase) {
                check(database.update(
                    SESSION_TABLE,
                    ContentValues(1).apply { put(PHASE, nextPhase.name) },
                    "$ID = ?",
                    arrayOf(SESSION_ID.toString()),
                ) == 1) { "Local identity transition disappeared during recovery authorization" }
            }
            database.setTransactionSuccessful()
            removed
        } finally {
            database.endTransaction()
        }
    }

    override fun close() = helper.close()

    fun clear() {
        close()
        check(appContext.deleteDatabase(databaseName) || !appContext.getDatabasePath(databaseName).exists()) {
            "Unable to delete local identity transition store"
        }
    }

    private fun blockIfExpired(database: SQLiteDatabase, session: Session, nowUnixMs: Long): Session {
        if (session.phase == SessionPhase.AWAITING_ACKS && nowUnixMs >= session.expiresAtUnixMs) {
            check(
                database.update(
                    SESSION_TABLE,
                    ContentValues(1).apply { put(PHASE, SessionPhase.BLOCKED.name) },
                    "$ID = ?",
                    arrayOf(SESSION_ID.toString()),
                ) == 1,
            ) { "Local identity transition disappeared before blocking" }
            return session.copy(phase = SessionPhase.BLOCKED)
        }
        return session
    }

    private fun insertSession(database: SQLiteDatabase, value: Session) {
        database.insertOrThrow(
            SESSION_TABLE,
            null,
            ContentValues(12).apply {
                put(ID, SESSION_ID)
                put(WORKSPACE_ID, value.workspaceId.toHex())
                put(LOCAL_DEVICE_ID, value.localDeviceId.toHex())
                put(TRANSITION_ID, value.transitionId.toHex())
                put(PREVIOUS_KEY_ID, value.previousKeyId)
                put(NEW_KEY_ID, value.newKeyId)
                put(NEW_PUBLIC_KEY, value.newPublicKey)
                put(CANONICAL_TRANSITION, value.canonicalTransition)
                put(TRANSITION_SHA256, value.transitionSha256)
                put(CREATED_AT, value.createdAtUnixMs)
                put(EXPIRES_AT, value.expiresAtUnixMs)
                put(PHASE, value.phase.name)
            },
        )
    }

    private fun insertPeer(database: SQLiteDatabase, value: PeerState) {
        database.insertOrThrow(
            PEER_TABLE,
            null,
            ContentValues(6).apply {
                put(TRANSITION_ID, value.transitionId.toHex())
                put(PEER_DEVICE_ID, value.deviceId.toHex())
                put(PEER_KEY_ID, value.keyId)
                put(NEXT_COMMIT_ATTEMPT_AT, value.nextCommitAttemptAtUnixMs)
                put(COMMIT_ATTEMPT_COUNT, value.commitAttemptCount)
                put(PHASE, value.phase.name)
            },
        )
    }

    private fun updatePeer(database: SQLiteDatabase, value: PeerState) {
        check(
            database.update(
                PEER_TABLE,
                ContentValues(6).apply {
                    put(CANONICAL_ACK, value.canonicalAck)
                    put(ACK_SHA256, value.ackSha256)
                    put(CANONICAL_COMMIT, value.canonicalCommit)
                    put(NEXT_COMMIT_ATTEMPT_AT, value.nextCommitAttemptAtUnixMs)
                    put(COMMIT_ATTEMPT_COUNT, value.commitAttemptCount)
                    put(PHASE, value.phase.name)
                },
                "$TRANSITION_ID = ? AND $PEER_DEVICE_ID = ?",
                arrayOf(value.transitionId.toHex(), value.deviceId.toHex()),
            ) == 1,
        ) { "Local identity transition peer disappeared" }
    }

    private fun findSession(database: SQLiteDatabase): Session? = database.query(
        SESSION_TABLE,
        arrayOf(
            WORKSPACE_ID,
            LOCAL_DEVICE_ID,
            TRANSITION_ID,
            PREVIOUS_KEY_ID,
            NEW_KEY_ID,
            NEW_PUBLIC_KEY,
            CANONICAL_TRANSITION,
            TRANSITION_SHA256,
            CREATED_AT,
            EXPIRES_AT,
            PHASE,
        ),
        "$ID = ?",
        arrayOf(SESSION_ID.toString()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else Session(
            workspaceId = cursor.getString(0).hexToBytes(),
            localDeviceId = cursor.getString(1).hexToBytes(),
            transitionId = cursor.getString(2).hexToBytes(),
            previousKeyId = cursor.getBlob(3).copyOf(),
            newKeyId = cursor.getBlob(4).copyOf(),
            newPublicKey = cursor.getBlob(5).copyOf(),
            canonicalTransition = cursor.getBlob(6).copyOf(),
            transitionSha256 = cursor.getBlob(7).copyOf(),
            createdAtUnixMs = cursor.getLong(8),
            expiresAtUnixMs = cursor.getLong(9),
            phase = enumValue(cursor.getString(10), "session phase"),
        )
    }

    private fun findPeer(
        database: SQLiteDatabase,
        transitionId: ByteArray,
        deviceId: ByteArray,
    ): PeerState? = database.query(
        PEER_TABLE,
        PEER_COLUMNS,
        "$TRANSITION_ID = ? AND $PEER_DEVICE_ID = ?",
        arrayOf(transitionId.toHex(), deviceId.toHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else peerFromCursor(cursor, transitionId)
    }

    private fun peerFromCursor(cursor: android.database.Cursor, transitionId: ByteArray): PeerState =
        PeerState(
            transitionId = transitionId.copyOf(),
            deviceId = cursor.getString(0).hexToBytes(),
            keyId = cursor.getBlob(1).copyOf(),
            canonicalAck = if (cursor.isNull(2)) null else cursor.getBlob(2).copyOf(),
            ackSha256 = if (cursor.isNull(3)) null else cursor.getBlob(3).copyOf(),
            canonicalCommit = if (cursor.isNull(4)) null else cursor.getBlob(4).copyOf(),
            nextCommitAttemptAtUnixMs = cursor.getLong(5),
            commitAttemptCount = cursor.getInt(6),
            phase = enumValue(cursor.getString(7), "peer phase"),
        )

    private fun validateSession(value: Session) {
        validateIdentifier(value.workspaceId, "workspaceId")
        validateIdentifier(value.localDeviceId, "localDeviceId")
        validateIdentifier(value.transitionId, "transitionId")
        validateDigest(value.previousKeyId, "previousKeyId")
        validateDigest(value.newKeyId, "newKeyId")
        validateDigest(value.transitionSha256, "transitionSha256")
        AuthenticatedHpke.requireValidPublicKey(value.newPublicKey)
        check(value.createdAtUnixMs >= 0 &&
            value.expiresAtUnixMs == Math.addExact(value.createdAtUnixMs, RETENTION_MS)) {
            "Stored local identity transition expiry is invalid"
        }
        val transition = EncryptedPayloadCodecV1.decode(value.canonicalTransition)
        check(transition.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION &&
            MessageDigest.isEqual(sha256(value.canonicalTransition), value.transitionSha256) &&
            MessageDigest.isEqual(
                transition.identityKeyTransition.transitionId.toByteArray(),
                value.transitionId,
            ) &&
            MessageDigest.isEqual(
                transition.identityKeyTransition.previousKeyId.toByteArray(),
                value.previousKeyId,
            ) &&
            MessageDigest.isEqual(
                transition.identityKeyTransition.newKeyId.toByteArray(),
                value.newKeyId,
            ) &&
            MessageDigest.isEqual(
                transition.identityKeyTransition.newPublicKey.toByteArray(),
                value.newPublicKey,
            )) {
            "Stored local identity transition binding is corrupt"
        }
    }

    private fun validatePeer(value: PeerState) {
        validateIdentifier(value.transitionId, "transitionId")
        validateIdentifier(value.deviceId, "peerDeviceId")
        validateDigest(value.keyId, "peerKeyId")
        check(value.nextCommitAttemptAtUnixMs >= 0) {
            "Stored local identity transition commit attempt time is invalid"
        }
        check(value.commitAttemptCount >= 0) {
            "Stored local identity transition commit attempt count is invalid"
        }
        val complete = value.canonicalAck != null && value.ackSha256 != null && value.canonicalCommit != null
        check((value.canonicalAck == null) == (value.ackSha256 == null) &&
            (value.canonicalAck == null) == (value.canonicalCommit == null)) {
            "Stored local identity transition peer state is partial"
        }
        check((value.phase == PeerPhase.COMMIT_QUEUED) == complete) {
            "Stored local identity transition peer phase is inconsistent"
        }
    }

    private fun validatePeerCryptography(session: Session, peer: PeerState) {
        if (peer.phase != PeerPhase.COMMIT_QUEUED) return
        val ackBytes = checkNotNull(peer.canonicalAck)
        val ackDigest = checkNotNull(peer.ackSha256)
        val commitBytes = checkNotNull(peer.canonicalCommit)
        check(MessageDigest.isEqual(sha256(ackBytes), ackDigest)) {
            "Stored local identity transition acknowledgement digest is corrupt"
        }
        val commit = EncryptedPayloadCodecV1.decode(commitBytes)
        check(commit.bodyCase == EncryptedPayload.BodyCase.IDENTITY_KEY_TRANSITION_COMMIT &&
            MessageDigest.isEqual(commit.identityKeyTransitionCommit.transitionId.toByteArray(), session.transitionId) &&
            MessageDigest.isEqual(commit.identityKeyTransitionCommit.previousKeyId.toByteArray(), session.previousKeyId) &&
            MessageDigest.isEqual(commit.identityKeyTransitionCommit.newKeyId.toByteArray(), session.newKeyId) &&
            MessageDigest.isEqual(commit.identityKeyTransitionCommit.transitionSha256.toByteArray(), session.transitionSha256) &&
            MessageDigest.isEqual(commit.identityKeyTransitionCommit.ackSha256.toByteArray(), ackDigest)) {
            "Stored local identity transition commit binding is corrupt"
        }
    }

    private fun optionalEquals(left: ByteArray?, right: ByteArray): Boolean =
        left != null && MessageDigest.isEqual(left, right)

    private fun Session.copyState(): Session = copy(
        workspaceId = workspaceId.copyOf(),
        localDeviceId = localDeviceId.copyOf(),
        transitionId = transitionId.copyOf(),
        previousKeyId = previousKeyId.copyOf(),
        newKeyId = newKeyId.copyOf(),
        newPublicKey = newPublicKey.copyOf(),
        canonicalTransition = canonicalTransition.copyOf(),
        transitionSha256 = transitionSha256.copyOf(),
    )

    private fun PeerState.copyState(): PeerState = copy(
        transitionId = transitionId.copyOf(),
        deviceId = deviceId.copyOf(),
        keyId = keyId.copyOf(),
        canonicalAck = canonicalAck?.copyOf(),
        ackSha256 = ackSha256?.copyOf(),
        canonicalCommit = canonicalCommit?.copyOf(),
    )

    private fun validateIdentifier(value: ByteArray, name: String) {
        require(value.size == 16 && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero 16-byte value"
        }
    }

    private fun validateDigest(value: ByteArray, name: String) {
        require(value.size == 32 && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero 32-byte value"
        }
    }

    private inline fun <reified T : Enum<T>> enumValue(value: String, name: String): T = try {
        enumValueOf<T>(value)
    } catch (error: IllegalArgumentException) {
        throw IllegalStateException("Stored local identity transition $name is invalid", error)
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0) { "Stored hex value has invalid length" }
        return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private class DatabaseHelper(context: Context, name: String) :
        SQLiteOpenHelper(context, name, null, DATABASE_VERSION) {
        override fun onCreate(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $SESSION_TABLE (" +
                    "$ID INTEGER PRIMARY KEY CHECK ($ID = $SESSION_ID), " +
                    "$WORKSPACE_ID TEXT NOT NULL, $LOCAL_DEVICE_ID TEXT NOT NULL, " +
                    "$TRANSITION_ID TEXT NOT NULL, $PREVIOUS_KEY_ID BLOB NOT NULL, " +
                    "$NEW_KEY_ID BLOB NOT NULL, $NEW_PUBLIC_KEY BLOB NOT NULL, " +
                    "$CANONICAL_TRANSITION BLOB NOT NULL, $TRANSITION_SHA256 BLOB NOT NULL, " +
                    "$CREATED_AT INTEGER NOT NULL, $EXPIRES_AT INTEGER NOT NULL, $PHASE TEXT NOT NULL)",
            )
            database.execSQL(
                "CREATE TABLE $PEER_TABLE (" +
                    "$TRANSITION_ID TEXT NOT NULL, $PEER_DEVICE_ID TEXT NOT NULL, " +
                    "$PEER_KEY_ID BLOB NOT NULL, $CANONICAL_ACK BLOB, $ACK_SHA256 BLOB, " +
                    "$CANONICAL_COMMIT BLOB, $NEXT_COMMIT_ATTEMPT_AT INTEGER NOT NULL, " +
                    "$COMMIT_ATTEMPT_COUNT INTEGER NOT NULL, $PHASE TEXT NOT NULL, " +
                    "PRIMARY KEY ($TRANSITION_ID, $PEER_DEVICE_ID))",
            )
            createSequenceTable(database)
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            var version = oldVersion
            if (version == 1) {
                database.execSQL(
                    "ALTER TABLE $PEER_TABLE ADD COLUMN $NEXT_COMMIT_ATTEMPT_AT " +
                        "INTEGER NOT NULL DEFAULT 0",
                )
                database.execSQL(
                    "ALTER TABLE $PEER_TABLE ADD COLUMN $COMMIT_ATTEMPT_COUNT " +
                        "INTEGER NOT NULL DEFAULT 0",
                )
                createSequenceTable(database)
                version = 2
            }
            if (version != newVersion) {
                throw IllegalStateException(
                    "Local identity transition migration missing: $oldVersion -> $newVersion",
                )
            }
        }

        private fun createSequenceTable(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $SEQUENCE_TABLE (" +
                    "$PEER_KEY_ID TEXT PRIMARY KEY, $NEXT_SEQUENCE INTEGER NOT NULL)",
            )
        }
    }

    private companion object {
        const val DATABASE_VERSION = 2
        const val RETENTION_MS = 7L * 24 * 60 * 60 * 1_000
        const val SESSION_ID = 1
        const val SESSION_TABLE = "local_transition_session"
        const val PEER_TABLE = "local_transition_peer"
        const val SEQUENCE_TABLE = "local_transition_sequence"
        const val ID = "id"
        const val WORKSPACE_ID = "workspace_id"
        const val LOCAL_DEVICE_ID = "local_device_id"
        const val TRANSITION_ID = "transition_id"
        const val PREVIOUS_KEY_ID = "previous_key_id"
        const val NEW_KEY_ID = "new_key_id"
        const val NEW_PUBLIC_KEY = "new_public_key"
        const val CANONICAL_TRANSITION = "canonical_transition"
        const val TRANSITION_SHA256 = "transition_sha256"
        const val CREATED_AT = "created_at_unix_ms"
        const val EXPIRES_AT = "expires_at_unix_ms"
        const val PHASE = "phase"
        const val PEER_DEVICE_ID = "peer_device_id"
        const val PEER_KEY_ID = "peer_key_id"
        const val CANONICAL_ACK = "canonical_ack"
        const val ACK_SHA256 = "ack_sha256"
        const val CANONICAL_COMMIT = "canonical_commit"
        const val NEXT_COMMIT_ATTEMPT_AT = "next_commit_attempt_at_unix_ms"
        const val COMMIT_ATTEMPT_COUNT = "commit_attempt_count"
        const val NEXT_SEQUENCE = "next_sequence"
        val PEER_COLUMNS = arrayOf(
            PEER_DEVICE_ID,
            PEER_KEY_ID,
            CANONICAL_ACK,
            ACK_SHA256,
            CANONICAL_COMMIT,
            NEXT_COMMIT_ATTEMPT_AT,
            COMMIT_ATTEMPT_COUNT,
            PHASE,
        )
    }
}
