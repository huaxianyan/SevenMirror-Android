package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/** Persistent, atomic guard against logically duplicated side-effect requests. */
class AndroidOperationLedger(
    context: Context,
    ledgerName: String = "default",
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
) : AutoCloseable {
    enum class Decision { ACCEPTED, DUPLICATE, CAPACITY_EXCEEDED }

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

    /** Must commit before the caller invokes a PendingIntent or another side effect. */
    fun checkAndRecord(
        senderKeyId: ByteArray,
        idempotencyKey: ByteArray,
        nowUnixMs: Long,
    ): Decision {
        require(senderKeyId.size == 32 && senderKeyId.any { it.toInt() != 0 }) {
            "senderKeyId must be a non-zero 32-byte value"
        }
        require(idempotencyKey.size == 16 && idempotencyKey.any { it.toInt() != 0 }) {
            "idempotencyKey must be a non-zero 16-byte value"
        }
        val expiresAt = Math.addExact(nowUnixMs, RETENTION_MS)
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            database.delete(TABLE, "$EXPIRES_AT <= ?", arrayOf(nowUnixMs.toString()))
            if (contains(database, senderKeyId, idempotencyKey)) {
                database.setTransactionSuccessful()
                Decision.DUPLICATE
            } else if (count(database) >= maxEntries) {
                database.setTransactionSuccessful()
                Decision.CAPACITY_EXCEEDED
            } else {
                val values = ContentValues(3).apply {
                    put(SENDER_KEY_ID, senderKeyId.copyOf())
                    put(IDEMPOTENCY_KEY, idempotencyKey.copyOf())
                    put(EXPIRES_AT, expiresAt)
                }
                val rowId = database.insertWithOnConflict(
                    TABLE,
                    null,
                    values,
                    SQLiteDatabase.CONFLICT_IGNORE,
                )
                val decision = if (rowId == -1L) Decision.DUPLICATE else Decision.ACCEPTED
                database.setTransactionSuccessful()
                decision
            }
        } finally {
            database.endTransaction()
        }
    }

    override fun close() = helper.close()

    fun clear() {
        close()
        check(appContext.deleteDatabase(databaseName) || !appContext.getDatabasePath(databaseName).exists()) {
            "Unable to delete operation ledger"
        }
    }

    private fun contains(database: SQLiteDatabase, sender: ByteArray, key: ByteArray): Boolean =
        database.compileStatement(
            "SELECT EXISTS(SELECT 1 FROM $TABLE WHERE $SENDER_KEY_ID = ? AND $IDEMPOTENCY_KEY = ?)",
        ).use {
            it.bindBlob(1, sender)
            it.bindBlob(2, key)
            it.simpleQueryForLong() == 1L
        }

    private fun count(database: SQLiteDatabase): Long =
        database.compileStatement("SELECT COUNT(*) FROM $TABLE").use { it.simpleQueryForLong() }

    private class DatabaseHelper(context: Context, name: String) :
        SQLiteOpenHelper(context, name, null, 1) {
        override fun onCreate(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TABLE (" +
                    "$SENDER_KEY_ID BLOB NOT NULL, " +
                    "$IDEMPOTENCY_KEY BLOB NOT NULL, " +
                    "$EXPIRES_AT INTEGER NOT NULL, " +
                    "PRIMARY KEY ($SENDER_KEY_ID, $IDEMPOTENCY_KEY))",
            )
            database.execSQL("CREATE INDEX operation_expiry_idx ON $TABLE ($EXPIRES_AT)")
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            throw IllegalStateException("Operation ledger migration missing: $oldVersion -> $newVersion")
        }
    }

    private companion object {
        const val DEFAULT_MAX_ENTRIES = 16_384
        const val RETENTION_MS = 30L * 24 * 60 * 60 * 1000
        const val TABLE = "operation_entry"
        const val SENDER_KEY_ID = "sender_key_id"
        const val IDEMPOTENCY_KEY = "idempotency_key"
        const val EXPIRES_AT = "expires_at_unix_ms"
    }
}
