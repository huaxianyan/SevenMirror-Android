package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import dev.notificationmirroring.protocol.generated.v1.IdentityKeyTransitionAck
import java.security.MessageDigest

/** Immutable local E2EE pins; untrusted server directory entries must never call [pinApproved]. */
class AndroidTrustedPeerStore(
    context: Context,
    storeName: String = "default",
) : AutoCloseable {
    enum class PinResult { PINNED, ALREADY_PINNED }
    enum class TransitionResult { ACCEPTED, ALREADY_ACCEPTED }
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
        val phase: TransitionPhase,
    )

    data class AcceptedPeerIdentityTransition(
        val result: TransitionResult,
        val state: PeerIdentityTransitionState,
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
            phase = TransitionPhase.PENDING_COMMIT,
        )
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
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
                AcceptedPeerIdentityTransition(
                    TransitionResult.ALREADY_ACCEPTED,
                    existing.copyState(),
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

    fun remove(workspaceId: ByteArray, deviceId: ByteArray) {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(deviceId, "deviceId")
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            val arguments = arrayOf(workspaceId.toHex(), deviceId.toHex())
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
        arrayOf(
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
            PHASE,
        ),
        "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
        arrayOf(workspaceId.toHex(), peerDeviceId.toHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else PeerIdentityTransitionState(
            workspaceId = workspaceId.copyOf(),
            peerDeviceId = peerDeviceId.copyOf(),
            transitionId = cursor.getBlob(0).copyOf(),
            previousKeyId = cursor.getBlob(1).copyOf(),
            newKeyId = cursor.getBlob(2).copyOf(),
            newPublicKey = cursor.getBlob(3).copyOf(),
            canonicalTransition = cursor.getBlob(4).copyOf(),
            transitionSha256 = cursor.getBlob(5).copyOf(),
            canonicalAck = cursor.getBlob(6).copyOf(),
            ackSha256 = cursor.getBlob(7).copyOf(),
            acceptedAtUnixMs = cursor.getLong(8),
            expiresAtUnixMs = cursor.getLong(9),
            phase = try {
                TransitionPhase.valueOf(cursor.getString(10))
            } catch (error: IllegalArgumentException) {
                throw IllegalStateException("Stored identity transition phase is invalid", error)
            },
        )
    }

    private fun insertTransition(
        database: SQLiteDatabase,
        state: PeerIdentityTransitionState,
    ) {
        database.insertOrThrow(
            TRANSITION_TABLE,
            null,
            ContentValues(13).apply {
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
                put(PHASE, state.phase.name)
            },
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
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            if (oldVersion == 1 && newVersion == 2) {
                createTransitionTable(database)
                return
            }
            throw IllegalStateException("Trusted peer migration missing: $oldVersion -> $newVersion")
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
                    "$PHASE TEXT NOT NULL, " +
                    "PRIMARY KEY ($WORKSPACE_ID, $DEVICE_ID))",
            )
        }
    }

    private companion object {
        const val DATABASE_VERSION = 2
        const val IDENTIFIER_BYTES = 16
        const val KEY_ID_BYTES = 32
        const val TABLE = "approved_peer"
        const val TRANSITION_TABLE = "peer_identity_transition"
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
        const val PHASE = "phase"
        const val IDENTITY_TRANSITION_RETENTION_MS = 7L * 24 * 60 * 60 * 1_000

        fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
