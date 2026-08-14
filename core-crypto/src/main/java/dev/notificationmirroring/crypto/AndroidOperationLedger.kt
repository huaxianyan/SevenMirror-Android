package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/** Persistent, atomic guard and result cache for notification side effects. */
class AndroidOperationLedger(
    context: Context,
    ledgerName: String = "default",
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
) : AutoCloseable {
    sealed interface BeginResult {
        data object Accepted : BeginResult
        data object DuplicatePending : BeginResult
        data class DuplicateCompleted(val resultPayload: ByteArray) : BeginResult
        data object CapacityExceeded : BeginResult
    }

    sealed interface LookupResult {
        data object Unknown : LookupResult
        data object Pending : LookupResult
        data class Completed(val resultPayload: ByteArray) : LookupResult
    }

    private val appContext = context.applicationContext
    private val safeName = ledgerName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "ledgerName must be 1-64 URL-safe characters"
        }
    }
    private val databaseName = "syncnotifications-operation-$safeName.db"
    private val helper = DatabaseHelper(appContext, databaseName)

    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
    }

    /** Atomically reserves an operation before PendingIntent invocation. */
    fun beginOrRecover(
        senderKeyId: ByteArray,
        idempotencyKey: ByteArray,
        nowUnixMs: Long,
    ): BeginResult {
        validateKey(senderKeyId, 32, "senderKeyId")
        validateKey(idempotencyKey, 16, "idempotencyKey")
        val expiresAt = Math.addExact(nowUnixMs, RETENTION_MS)
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            database.delete(TABLE, "$EXPIRES_AT <= ?", arrayOf(nowUnixMs.toString()))
            val existing = find(database, senderKeyId, idempotencyKey)
            val result = when {
                existing != null -> existing
                count(database) >= maxEntries -> BeginResult.CapacityExceeded
                else -> {
                    val values = ContentValues(4).apply {
                        put(SENDER_KEY_ID, senderKeyId.copyOf())
                        put(IDEMPOTENCY_KEY, idempotencyKey.copyOf())
                        put(EXPIRES_AT, expiresAt)
                        putNull(RESULT_PAYLOAD)
                    }
                    val rowId = database.insertWithOnConflict(
                        TABLE,
                        null,
                        values,
                        SQLiteDatabase.CONFLICT_IGNORE,
                    )
                    if (rowId == -1L) {
                        requireNotNull(find(database, senderKeyId, idempotencyKey))
                    } else {
                        BeginResult.Accepted
                    }
                }
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    /** Looks up the exact durable result without creating or changing an operation. */
    fun lookup(
        senderKeyId: ByteArray,
        idempotencyKey: ByteArray,
        nowUnixMs: Long,
    ): LookupResult {
        validateKey(senderKeyId, 32, "senderKeyId")
        validateKey(idempotencyKey, 16, "idempotencyKey")
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            database.delete(TABLE, "$EXPIRES_AT <= ?", arrayOf(nowUnixMs.toString()))
            val result = when (val existing = find(database, senderKeyId, idempotencyKey)) {
                null -> LookupResult.Unknown
                BeginResult.DuplicatePending -> LookupResult.Pending
                is BeginResult.DuplicateCompleted ->
                    LookupResult.Completed(existing.resultPayload.copyOf())
                else -> error("Stored operation lookup returned an impossible state")
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    /** Stores canonical ActionResult bytes after local execution returns. */
    fun complete(
        senderKeyId: ByteArray,
        idempotencyKey: ByteArray,
        resultPayload: ByteArray,
    ) {
        validateKey(senderKeyId, 32, "senderKeyId")
        validateKey(idempotencyKey, 16, "idempotencyKey")
        require(resultPayload.size in 1..MAX_RESULT_PAYLOAD_BYTES) {
            "resultPayload is out of range"
        }
        val database = helper.writableDatabase
        val rowId = findRowId(database, senderKeyId, idempotencyKey)
        check(rowId != 0L) { "Operation was not reserved" }
        val values = ContentValues(1).apply { put(RESULT_PAYLOAD, resultPayload.copyOf()) }
        val updated = database.update(
            TABLE,
            values,
            "rowid = ? AND $RESULT_PAYLOAD IS NULL",
            arrayOf(rowId.toString()),
        )
        check(updated == 1) { "Operation was already completed" }
    }

    override fun close() = helper.close()

    fun clear() {
        close()
        check(appContext.deleteDatabase(databaseName) || !appContext.getDatabasePath(databaseName).exists()) {
            "Unable to delete operation ledger"
        }
    }

    private fun find(
        database: SQLiteDatabase,
        sender: ByteArray,
        key: ByteArray,
    ): BeginResult? {
        val rowId = findRowId(database, sender, key)
        if (rowId == 0L) return null
        return database.query(
            TABLE,
            arrayOf(RESULT_PAYLOAD),
            "rowid = ?",
            arrayOf(rowId.toString()),
            null,
            null,
            null,
            "1",
        ).use { cursor ->
            check(cursor.moveToFirst()) { "Operation row disappeared during transaction" }
            if (cursor.isNull(0)) {
                BeginResult.DuplicatePending
            } else {
                BeginResult.DuplicateCompleted(cursor.getBlob(0).copyOf())
            }
        }
    }

    private fun findRowId(database: SQLiteDatabase, sender: ByteArray, key: ByteArray): Long =
        database.compileStatement(
            "SELECT IFNULL((SELECT rowid FROM $TABLE " +
                "WHERE $SENDER_KEY_ID = ? AND $IDEMPOTENCY_KEY = ?), 0)",
        ).use {
            it.bindBlob(1, sender)
            it.bindBlob(2, key)
            it.simpleQueryForLong()
        }

    private fun count(database: SQLiteDatabase): Long =
        database.compileStatement("SELECT COUNT(*) FROM $TABLE").use { it.simpleQueryForLong() }

    private fun validateKey(value: ByteArray, size: Int, name: String) {
        require(value.size == size && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero $size-byte value"
        }
    }

    private class DatabaseHelper(context: Context, name: String) :
        SQLiteOpenHelper(context, name, null, DATABASE_VERSION) {
        override fun onCreate(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TABLE (" +
                    "$SENDER_KEY_ID BLOB NOT NULL, " +
                    "$IDEMPOTENCY_KEY BLOB NOT NULL, " +
                    "$EXPIRES_AT INTEGER NOT NULL, " +
                    "$RESULT_PAYLOAD BLOB NULL, " +
                    "PRIMARY KEY ($SENDER_KEY_ID, $IDEMPOTENCY_KEY))",
            )
            database.execSQL("CREATE INDEX operation_expiry_idx ON $TABLE ($EXPIRES_AT)")
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            if (oldVersion == 1 && newVersion == 2) {
                database.execSQL("ALTER TABLE $TABLE ADD COLUMN $RESULT_PAYLOAD BLOB NULL")
                return
            }
            throw IllegalStateException("Operation ledger migration missing: $oldVersion -> $newVersion")
        }
    }

    private companion object {
        const val DEFAULT_MAX_ENTRIES = 16_384
        const val RETENTION_MS = 30L * 24 * 60 * 60 * 1000
        const val MAX_RESULT_PAYLOAD_BYTES = 8_192
        const val DATABASE_VERSION = 2
        const val TABLE = "operation_entry"
        const val SENDER_KEY_ID = "sender_key_id"
        const val IDEMPOTENCY_KEY = "idempotency_key"
        const val EXPIRES_AT = "expires_at_unix_ms"
        const val RESULT_PAYLOAD = "result_payload"
    }
}
