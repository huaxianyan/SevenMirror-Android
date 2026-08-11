package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

enum class TrustPairingRole { OFFERER, APPROVER }

data class TrustPairingSession(
    val role: TrustPairingRole,
    val offerBytes: ByteArray,
    val approvalBytes: ByteArray?,
    val expiresAtUnixMs: Long,
)

/** One durable active transcript. It can only be replaced after explicit [cancel]. */
class AndroidTrustPairingSessionStore(
    context: Context,
    storeName: String = "default",
) : AutoCloseable {
    private val appContext = context.applicationContext
    private val safeName = storeName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "storeName must be 1-64 URL-safe characters"
        }
    }
    private val databaseName = "syncnotifications-trust-pairing-$safeName.db"
    private val helper = DatabaseHelper(appContext, databaseName)

    @Synchronized
    fun load(): TrustPairingSession? = find(helper.readableDatabase)?.also(::validateSession)

    @Synchronized
    fun create(session: TrustPairingSession) {
        validateSession(session)
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            check(find(database) == null) {
                "An active trust pairing session already exists; cancel it explicitly"
            }
            database.insertOrThrow(
                TABLE,
                null,
                ContentValues(5).apply {
                    put(ID, RECORD_ID)
                    put(ROLE, session.role.name)
                    put(OFFER, session.offerBytes.copyOf())
                    session.approvalBytes?.let { put(APPROVAL, it.copyOf()) } ?: putNull(APPROVAL)
                    put(EXPIRES_AT, session.expiresAtUnixMs)
                },
            )
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun attachApproval(expectedOffer: ByteArray, approvalBytes: ByteArray) {
        require(approvalBytes.size == APPROVAL_SIZE) { "Trust approval has invalid length" }
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            val session = find(database) ?: error("No active trust pairing offer exists")
            validateSession(session)
            check(session.role == TrustPairingRole.OFFERER && session.approvalBytes == null &&
                session.offerBytes.contentEquals(expectedOffer)) {
                "Active trust pairing session does not match this approval"
            }
            val updated = database.update(
                TABLE,
                ContentValues(1).apply { put(APPROVAL, approvalBytes.copyOf()) },
                "$ID = ?",
                arrayOf(RECORD_ID.toString()),
            )
            check(updated == 1) { "Unable to attach trust approval" }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun removeExact(offerBytes: ByteArray, approvalBytes: ByteArray?) {
        val database = helper.writableDatabase
        database.beginTransaction()
        try {
            val session = find(database) ?: error("Trust pairing session disappeared")
            validateSession(session)
            check(session.offerBytes.contentEquals(offerBytes) &&
                optionalEquals(session.approvalBytes, approvalBytes)) {
                "Trust pairing session changed before completion"
            }
            check(database.delete(TABLE, "$ID = ?", arrayOf(RECORD_ID.toString())) == 1) {
                "Unable to remove completed trust pairing session"
            }
            database.setTransactionSuccessful()
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    fun cancel() {
        helper.writableDatabase.delete(TABLE, "$ID = ?", arrayOf(RECORD_ID.toString()))
    }

    override fun close() = helper.close()

    fun clear() {
        close()
        check(appContext.deleteDatabase(databaseName) || !appContext.getDatabasePath(databaseName).exists()) {
            "Unable to delete trust pairing store"
        }
    }

    private fun find(database: SQLiteDatabase): TrustPairingSession? = database.query(
        TABLE,
        arrayOf(ROLE, OFFER, APPROVAL, EXPIRES_AT),
        "$ID = ?",
        arrayOf(RECORD_ID.toString()),
        null,
        null,
        null,
        "1",
    ).use { cursor ->
        if (!cursor.moveToFirst()) null else TrustPairingSession(
            role = try {
                TrustPairingRole.valueOf(cursor.getString(0))
            } catch (error: IllegalArgumentException) {
                throw IllegalStateException("Stored trust pairing role is invalid", error)
            },
            offerBytes = cursor.getBlob(1).copyOf(),
            approvalBytes = if (cursor.isNull(2)) null else cursor.getBlob(2).copyOf(),
            expiresAtUnixMs = cursor.getLong(3),
        )
    }

    private fun validateSession(value: TrustPairingSession) {
        check(value.offerBytes.size == OFFER_SIZE) { "Stored trust offer has invalid length" }
        check(value.approvalBytes == null || value.approvalBytes.size == APPROVAL_SIZE) {
            "Stored trust approval has invalid length"
        }
        check(value.role != TrustPairingRole.APPROVER || value.approvalBytes != null) {
            "Approver session must contain an approval"
        }
        check(value.expiresAtUnixMs >= 0) { "Stored trust pairing expiry is invalid" }
    }

    private fun optionalEquals(left: ByteArray?, right: ByteArray?): Boolean =
        if (left == null) right == null else right != null && left.contentEquals(right)

    private class DatabaseHelper(context: Context, name: String) :
        SQLiteOpenHelper(context, name, null, DATABASE_VERSION) {
        override fun onCreate(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TABLE (" +
                    "$ID INTEGER PRIMARY KEY CHECK ($ID = $RECORD_ID), " +
                    "$ROLE TEXT NOT NULL, " +
                    "$OFFER BLOB NOT NULL, " +
                    "$APPROVAL BLOB, " +
                    "$EXPIRES_AT INTEGER NOT NULL)",
            )
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            throw IllegalStateException("Trust pairing migration missing: $oldVersion -> $newVersion")
        }
    }

    private companion object {
        const val DATABASE_VERSION = 1
        const val RECORD_ID = 1
        const val OFFER_SIZE = 133
        const val APPROVAL_SIZE = 149
        const val TABLE = "active_pairing"
        const val ID = "id"
        const val ROLE = "role"
        const val OFFER = "offer_bytes"
        const val APPROVAL = "approval_bytes"
        const val EXPIRES_AT = "expires_at_unix_ms"
    }
}
