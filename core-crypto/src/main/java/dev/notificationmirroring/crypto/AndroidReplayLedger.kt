package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Persistent replay ledger for authenticated envelopes.
 *
 * Callers must invoke [checkAndRecord] after HPKE authentication succeeds and
 * before applying any externally visible side effect. Database failures are
 * deliberately propagated so callers fail closed rather than reopening the
 * replay window.
 */
class AndroidReplayLedger(
    context: Context,
    ledgerName: String = "default",
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
) : AutoCloseable {
    enum class Decision {
        ACCEPTED,
        DUPLICATE,
        EXPIRED,
        CAPACITY_EXCEEDED,
    }

    private val appContext = context.applicationContext
    private val safeName = ledgerName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "ledgerName must be 1-64 URL-safe characters"
        }
    }
    private val databaseName = "syncnotifications-replay-$safeName.db"
    private val helper = ReplayDatabaseHelper(appContext, databaseName)

    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
    }

    /**
     * Atomically removes expired records and records a new authenticated tuple.
     * An accepted tuple is consumed even if the subsequent side effect fails;
     * operation-result recovery must not execute the same side effect twice.
     */
    fun checkAndRecord(
        senderKeyId: ByteArray,
        messageId: ByteArray,
        expiresAtUnixMs: Long,
        nowUnixMs: Long,
    ): Decision {
        require(senderKeyId.size == SENDER_KEY_ID_BYTES) {
            "senderKeyId must be $SENDER_KEY_ID_BYTES bytes"
        }
        require(messageId.size == MESSAGE_ID_BYTES) {
            "messageId must be $MESSAGE_ID_BYTES bytes"
        }
        if (expiresAtUnixMs <= nowUnixMs) return Decision.EXPIRED

        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            database.delete(
                TABLE_REPLAY,
                "$COLUMN_EXPIRES_AT <= ?",
                arrayOf(nowUnixMs.toString()),
            )

            if (contains(database, senderKeyId, messageId)) {
                database.setTransactionSuccessful()
                Decision.DUPLICATE
            } else if (count(database) >= maxEntries) {
                database.setTransactionSuccessful()
                Decision.CAPACITY_EXCEEDED
            } else {
                val values = ContentValues(3).apply {
                    put(COLUMN_SENDER_KEY_ID, senderKeyId.copyOf())
                    put(COLUMN_MESSAGE_ID, messageId.copyOf())
                    put(COLUMN_EXPIRES_AT, expiresAtUnixMs)
                }
                val rowId = database.insertWithOnConflict(
                    TABLE_REPLAY,
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

    override fun close() {
        helper.close()
    }

    /** Deletes the complete ledger. Intended for explicit identity reset/tests. */
    fun clear() {
        close()
        check(appContext.deleteDatabase(databaseName) || !appContext.getDatabasePath(databaseName).exists()) {
            "Unable to delete replay ledger"
        }
    }

    private fun contains(
        database: SQLiteDatabase,
        senderKeyId: ByteArray,
        messageId: ByteArray,
    ): Boolean {
        val statement = database.compileStatement(
            "SELECT EXISTS(SELECT 1 FROM $TABLE_REPLAY " +
                "WHERE $COLUMN_SENDER_KEY_ID = ? AND $COLUMN_MESSAGE_ID = ?)",
        )
        return statement.use {
            it.bindBlob(1, senderKeyId)
            it.bindBlob(2, messageId)
            it.simpleQueryForLong() == 1L
        }
    }

    private fun count(database: SQLiteDatabase): Long =
        database.compileStatement("SELECT COUNT(*) FROM $TABLE_REPLAY").use {
            it.simpleQueryForLong()
        }

    private class ReplayDatabaseHelper(context: Context, databaseName: String) :
        SQLiteOpenHelper(context, databaseName, null, DATABASE_VERSION) {
        override fun onConfigure(database: SQLiteDatabase) {
            super.onConfigure(database)
            database.setForeignKeyConstraintsEnabled(true)
        }

        override fun onCreate(database: SQLiteDatabase) {
            database.execSQL(
                """
                CREATE TABLE $TABLE_REPLAY (
                    $COLUMN_SENDER_KEY_ID BLOB NOT NULL,
                    $COLUMN_MESSAGE_ID BLOB NOT NULL,
                    $COLUMN_EXPIRES_AT INTEGER NOT NULL,
                    PRIMARY KEY ($COLUMN_SENDER_KEY_ID, $COLUMN_MESSAGE_ID)
                )
                """.trimIndent(),
            )
            database.execSQL(
                "CREATE INDEX replay_expiry_idx ON $TABLE_REPLAY ($COLUMN_EXPIRES_AT)",
            )
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            throw IllegalStateException(
                "Replay ledger migration missing: $oldVersion -> $newVersion",
            )
        }
    }

    private companion object {
        const val DEFAULT_MAX_ENTRIES = 4096
        const val SENDER_KEY_ID_BYTES = 32
        const val MESSAGE_ID_BYTES = 16
        const val DATABASE_VERSION = 1
        const val TABLE_REPLAY = "replay_entry"
        const val COLUMN_SENDER_KEY_ID = "sender_key_id"
        const val COLUMN_MESSAGE_ID = "message_id"
        const val COLUMN_EXPIRES_AT = "expires_at_unix_ms"
    }
}
