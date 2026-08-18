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
    enum class SessionPhase { AWAITING_ACKS, BLOCKED }
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
                AcceptedAck(AcceptResult.ALREADY_ACCEPTED, peer.copyState())
            } else {
                val committed = peer.copy(
                    canonicalAck = canonicalAck.copyOf(),
                    ackSha256 = ackSha256,
                    canonicalCommit = canonicalCommit,
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
            ContentValues(5).apply {
                put(TRANSITION_ID, value.transitionId.toHex())
                put(PEER_DEVICE_ID, value.deviceId.toHex())
                put(PEER_KEY_ID, value.keyId)
                put(PHASE, value.phase.name)
            },
        )
    }

    private fun updatePeer(database: SQLiteDatabase, value: PeerState) {
        check(
            database.update(
                PEER_TABLE,
                ContentValues(4).apply {
                    put(CANONICAL_ACK, value.canonicalAck)
                    put(ACK_SHA256, value.ackSha256)
                    put(CANONICAL_COMMIT, value.canonicalCommit)
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
        arrayOf(PEER_KEY_ID, CANONICAL_ACK, ACK_SHA256, CANONICAL_COMMIT, PHASE),
        "$TRANSITION_ID = ? AND $PEER_DEVICE_ID = ?",
        arrayOf(transitionId.toHex(), deviceId.toHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else PeerState(
            transitionId = transitionId.copyOf(),
            deviceId = deviceId.copyOf(),
            keyId = cursor.getBlob(0).copyOf(),
            canonicalAck = if (cursor.isNull(1)) null else cursor.getBlob(1).copyOf(),
            ackSha256 = if (cursor.isNull(2)) null else cursor.getBlob(2).copyOf(),
            canonicalCommit = if (cursor.isNull(3)) null else cursor.getBlob(3).copyOf(),
            phase = enumValue(cursor.getString(4), "peer phase"),
        )
    }

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
        SQLiteOpenHelper(context, name, null, 1) {
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
                    "$CANONICAL_COMMIT BLOB, $PHASE TEXT NOT NULL, " +
                    "PRIMARY KEY ($TRANSITION_ID, $PEER_DEVICE_ID))",
            )
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            throw IllegalStateException("Local identity transition migration missing: $oldVersion -> $newVersion")
        }
    }

    private companion object {
        const val RETENTION_MS = 7L * 24 * 60 * 60 * 1_000
        const val SESSION_ID = 1
        const val SESSION_TABLE = "local_transition_session"
        const val PEER_TABLE = "local_transition_peer"
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
    }
}
