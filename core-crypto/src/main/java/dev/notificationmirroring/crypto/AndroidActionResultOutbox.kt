package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload

/** Durable canonical results waiting for bounded recipient-specific encryption/send attempts. */
class AndroidActionResultOutbox(
    context: Context,
    outboxName: String = "default",
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
) : AutoCloseable {
    enum class EnqueueResult { ENQUEUED, ALREADY_ENQUEUED, CAPACITY_EXCEEDED }

    data class Entry(
        val rowId: Long,
        val recipientDeviceId: ByteArray,
        val recipientKeyId: ByteArray,
        val idempotencyKey: ByteArray,
        val resultPayload: ByteArray,
        val createdAtUnixMs: Long,
        val expiresAtUnixMs: Long,
        val attemptCount: Int,
    )

    private val appContext = context.applicationContext
    private val safeName = outboxName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "outboxName must be 1-64 URL-safe characters"
        }
    }
    private val databaseName = "syncnotifications-action-result-outbox-$safeName.db"
    private val helper = DatabaseHelper(appContext, databaseName)

    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
    }

    fun enqueue(
        recipientDeviceId: ByteArray,
        recipientKeyId: ByteArray,
        canonicalResultPayload: ByteArray,
        nowUnixMs: Long,
    ): EnqueueResult {
        validateIdentifier(recipientDeviceId, 16, "recipientDeviceId")
        validateIdentifier(recipientKeyId, 32, "recipientKeyId")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val payload = EncryptedPayloadCodecV1.decode(canonicalResultPayload)
        require(payload.bodyCase == EncryptedPayload.BodyCase.ACTION_RESULT) {
            "Expected canonical action.result payload"
        }
        val idempotencyKey = payload.actionResult.idempotencyKey.toByteArray()
        validateIdentifier(idempotencyKey, 16, "idempotencyKey")
        val expiresAtUnixMs = Math.addExact(nowUnixMs, RETENTION_MS)
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            purgeExpired(database, nowUnixMs)
            val existing = find(database, recipientKeyId, idempotencyKey)
            val result = when {
                existing != null -> {
                    check(
                        existing.recipientDeviceId.contentEquals(recipientDeviceId) &&
                            existing.resultPayload.contentEquals(canonicalResultPayload),
                    ) { "Result outbox key is already bound to different bytes" }
                    val updated = database.update(
                        OUTBOX_TABLE,
                        ContentValues(2).apply {
                            put(NEXT_ATTEMPT_AT, nowUnixMs)
                            put(ATTEMPT_COUNT, 0)
                        },
                        "rowid = ?",
                        arrayOf(existing.rowId.toString()),
                    )
                    check(updated == 1) { "Action result outbox entry disappeared" }
                    EnqueueResult.ALREADY_ENQUEUED
                }
                count(database) >= maxEntries -> EnqueueResult.CAPACITY_EXCEEDED
                else -> {
                    val rowId = database.insertOrThrow(
                        OUTBOX_TABLE,
                        null,
                        ContentValues(8).apply {
                            put(RECIPIENT_DEVICE_ID, recipientDeviceId.copyOf())
                            put(RECIPIENT_KEY_ID, recipientKeyId.toHex())
                            put(IDEMPOTENCY_KEY, idempotencyKey.toHex())
                            put(RESULT_PAYLOAD, canonicalResultPayload.copyOf())
                            put(CREATED_AT, nowUnixMs)
                            put(EXPIRES_AT, expiresAtUnixMs)
                            put(NEXT_ATTEMPT_AT, nowUnixMs)
                            put(ATTEMPT_COUNT, 0)
                        },
                    )
                    check(rowId != -1L) { "Unable to persist action result outbox entry" }
                    EnqueueResult.ENQUEUED
                }
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    fun due(nowUnixMs: Long, limit: Int = 16): List<Entry> {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        require(limit in 1..128) { "limit must be 1..128" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            purgeExpired(database, nowUnixMs)
            val entries = database.query(
                OUTBOX_TABLE,
                arrayOf(
                    "rowid",
                    RECIPIENT_DEVICE_ID,
                    RECIPIENT_KEY_ID,
                    IDEMPOTENCY_KEY,
                    RESULT_PAYLOAD,
                    CREATED_AT,
                    EXPIRES_AT,
                    ATTEMPT_COUNT,
                ),
                "$NEXT_ATTEMPT_AT <= ?",
                arrayOf(nowUnixMs.toString()),
                null,
                null,
                "$NEXT_ATTEMPT_AT ASC, rowid ASC",
                limit.toString(),
            ).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) {
                        add(
                            Entry(
                                rowId = cursor.getLong(0),
                                recipientDeviceId = cursor.getBlob(1).copyOf(),
                                recipientKeyId = cursor.getString(2).hexToBytes(),
                                idempotencyKey = cursor.getString(3).hexToBytes(),
                                resultPayload = cursor.getBlob(4).copyOf(),
                                createdAtUnixMs = cursor.getLong(5),
                                expiresAtUnixMs = cursor.getLong(6),
                                attemptCount = cursor.getInt(7),
                            ),
                        )
                    }
                }
            }
            database.setTransactionSuccessful()
            entries
        } finally {
            database.endTransaction()
        }
    }

    /** Records only a frame accepted by WebSocket.send; false sends remain immediately due. */
    fun recordSendAttempt(rowId: Long, nextAttemptAtUnixMs: Long, maximumAttempts: Int = 5) {
        require(rowId > 0) { "rowId must be positive" }
        require(nextAttemptAtUnixMs >= 0) { "nextAttemptAtUnixMs must be non-negative" }
        require(maximumAttempts > 0) { "maximumAttempts must be positive" }
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            val current = database.query(
                OUTBOX_TABLE,
                arrayOf(ATTEMPT_COUNT),
                "rowid = ?",
                arrayOf(rowId.toString()),
                null,
                null,
                null,
                "1",
            ).use { cursor -> if (cursor.moveToFirst()) cursor.getInt(0) else null }
            if (current != null) {
                val dormantUntil = if (current + 1 >= maximumAttempts) {
                    database.query(
                        OUTBOX_TABLE,
                        arrayOf(EXPIRES_AT),
                        "rowid = ?",
                        arrayOf(rowId.toString()),
                        null,
                        null,
                        null,
                        "1",
                    ).use { cursor ->
                        check(cursor.moveToFirst()) { "Action result outbox entry disappeared" }
                        cursor.getLong(0)
                    }
                } else {
                    nextAttemptAtUnixMs
                }
                val updated = database.update(
                    OUTBOX_TABLE,
                    ContentValues(2).apply {
                        put(ATTEMPT_COUNT, current + 1)
                        put(NEXT_ATTEMPT_AT, dormantUntil)
                    },
                    "rowid = ?",
                    arrayOf(rowId.toString()),
                )
                check(updated == 1) { "Action result outbox entry disappeared" }
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    /** Allocates a persistent positive sequence for one recipient key. */
    fun allocateSequence(recipientKeyId: ByteArray): Long {
        validateIdentifier(recipientKeyId, 32, "recipientKeyId")
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val current = database.query(
                SEQUENCE_TABLE,
                arrayOf(NEXT_SEQUENCE),
                "$RECIPIENT_KEY_ID = ?",
                arrayOf(recipientKeyId.toHex()),
                null,
                null,
                null,
                "1",
            ).use { cursor -> if (cursor.moveToFirst()) cursor.getLong(0) else 1L }
            check(current in 1 until Long.MAX_VALUE) { "Outbound sequence exhausted" }
            database.insertWithOnConflict(
                SEQUENCE_TABLE,
                null,
                ContentValues(2).apply {
                    put(RECIPIENT_KEY_ID, recipientKeyId.toHex())
                    put(NEXT_SEQUENCE, current + 1)
                },
                SQLiteDatabase.CONFLICT_REPLACE,
            ).also { check(it != -1L) { "Unable to persist outbound sequence" } }
            database.setTransactionSuccessful()
            current
        } finally {
            database.endTransaction()
        }
    }

    override fun close() = helper.close()

    fun clear() {
        close()
        check(appContext.deleteDatabase(databaseName) || !appContext.getDatabasePath(databaseName).exists()) {
            "Unable to delete action result outbox"
        }
    }

    private fun find(
        database: SQLiteDatabase,
        recipientKeyId: ByteArray,
        idempotencyKey: ByteArray,
    ): Entry? = database.query(
        OUTBOX_TABLE,
        arrayOf(
            "rowid",
            RECIPIENT_DEVICE_ID,
            RECIPIENT_KEY_ID,
            IDEMPOTENCY_KEY,
            RESULT_PAYLOAD,
            CREATED_AT,
            EXPIRES_AT,
            ATTEMPT_COUNT,
        ),
        "$RECIPIENT_KEY_ID = ? AND $IDEMPOTENCY_KEY = ?",
        arrayOf(recipientKeyId.toHex(), idempotencyKey.toHex()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else Entry(
            rowId = cursor.getLong(0),
            recipientDeviceId = cursor.getBlob(1).copyOf(),
            recipientKeyId = cursor.getString(2).hexToBytes(),
            idempotencyKey = cursor.getString(3).hexToBytes(),
            resultPayload = cursor.getBlob(4).copyOf(),
            createdAtUnixMs = cursor.getLong(5),
            expiresAtUnixMs = cursor.getLong(6),
            attemptCount = cursor.getInt(7),
        )
    }

    private fun purgeExpired(database: SQLiteDatabase, nowUnixMs: Long) {
        database.delete(OUTBOX_TABLE, "$EXPIRES_AT <= ?", arrayOf(nowUnixMs.toString()))
    }

    private fun count(database: SQLiteDatabase): Long =
        database.compileStatement("SELECT COUNT(*) FROM $OUTBOX_TABLE").use { it.simpleQueryForLong() }

    private fun validateIdentifier(value: ByteArray, size: Int, name: String) {
        require(value.size == size && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero $size-byte value"
        }
    }

    private class DatabaseHelper(context: Context, name: String) :
        SQLiteOpenHelper(context, name, null, DATABASE_VERSION) {
        override fun onCreate(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $OUTBOX_TABLE (" +
                    "$RECIPIENT_DEVICE_ID BLOB NOT NULL, " +
                    "$RECIPIENT_KEY_ID TEXT NOT NULL, " +
                    "$IDEMPOTENCY_KEY TEXT NOT NULL, " +
                    "$RESULT_PAYLOAD BLOB NOT NULL, " +
                    "$CREATED_AT INTEGER NOT NULL, " +
                    "$EXPIRES_AT INTEGER NOT NULL, " +
                    "$NEXT_ATTEMPT_AT INTEGER NOT NULL, " +
                    "$ATTEMPT_COUNT INTEGER NOT NULL, " +
                    "UNIQUE ($RECIPIENT_KEY_ID, $IDEMPOTENCY_KEY))",
            )
            database.execSQL(
                "CREATE INDEX action_result_due_idx ON $OUTBOX_TABLE ($NEXT_ATTEMPT_AT)",
            )
            database.execSQL(
                "CREATE TABLE $SEQUENCE_TABLE (" +
                    "$RECIPIENT_KEY_ID TEXT PRIMARY KEY, " +
                    "$NEXT_SEQUENCE INTEGER NOT NULL)",
            )
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            throw IllegalStateException("Action result outbox migration missing: $oldVersion -> $newVersion")
        }
    }

    private companion object {
        const val DATABASE_VERSION = 1
        const val DEFAULT_MAX_ENTRIES = 16_384
        const val RETENTION_MS = 30L * 24 * 60 * 60 * 1000
        const val OUTBOX_TABLE = "action_result_outbox"
        const val SEQUENCE_TABLE = "outbound_sequence"
        const val RECIPIENT_DEVICE_ID = "recipient_device_id"
        const val RECIPIENT_KEY_ID = "recipient_key_id"
        const val IDEMPOTENCY_KEY = "idempotency_key"
        const val RESULT_PAYLOAD = "result_payload"
        const val CREATED_AT = "created_at_unix_ms"
        const val EXPIRES_AT = "expires_at_unix_ms"
        const val NEXT_ATTEMPT_AT = "next_attempt_at_unix_ms"
        const val ATTEMPT_COUNT = "attempt_count"
        const val NEXT_SEQUENCE = "next_sequence"

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

        fun String.hexToBytes(): ByteArray {
            require(length % 2 == 0) { "hex length must be even" }
            return ByteArray(length / 2) { index ->
                substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
