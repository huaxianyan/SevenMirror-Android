package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.security.MessageDigest

/** Immutable local E2EE pins; untrusted server directory entries must never call [pinApproved]. */
class AndroidTrustedPeerStore(
    context: Context,
    storeName: String = "default",
) : AutoCloseable {
    enum class PinResult { PINNED, ALREADY_PINNED }

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

    fun remove(workspaceId: ByteArray, deviceId: ByteArray) {
        validateIdentifier(workspaceId, "workspaceId")
        validateIdentifier(deviceId, "deviceId")
        helper.writableDatabase.delete(
            TABLE,
            "$WORKSPACE_ID = ? AND $DEVICE_ID = ?",
            arrayOf(workspaceId.toHex(), deviceId.toHex()),
        )
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
        }

        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            throw IllegalStateException("Trusted peer migration missing: $oldVersion -> $newVersion")
        }
    }

    private companion object {
        const val DATABASE_VERSION = 1
        const val IDENTIFIER_BYTES = 16
        const val KEY_ID_BYTES = 32
        const val TABLE = "approved_peer"
        const val WORKSPACE_ID = "workspace_id"
        const val DEVICE_ID = "device_id"
        const val KEY_ID = "key_id"
        const val PUBLIC_KEY = "public_key"

        fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
