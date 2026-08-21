package dev.notificationmirroring.crypto

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceCertificate
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceRole
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceType
import java.security.MessageDigest

data class WorkspaceNotificationRecipient(
    val deviceId: ByteArray,
    val identityKeyId: ByteArray,
    val identityPublicKey: ByteArray,
)

fun interface WorkspaceNotificationRecipientDirectory {
    fun listNotificationRecipients(
        workspaceId: ByteArray,
        localDeviceId: ByteArray,
        nowUnixMs: Long,
    ): List<WorkspaceNotificationRecipient>
}

interface WorkspaceMembershipTrustStore {
    fun pinAuthority(workspaceId: ByteArray, deviceId: ByteArray, authorityPublicKey: ByteArray): AndroidWorkspaceMembershipStore.PinResult
    fun reconcileApproved(workspaceId: ByteArray, deviceId: ByteArray, signedCertificate: ByteArray, signedRoster: ByteArray): AndroidWorkspaceMembershipStore.ReconcileResult
    fun load(workspaceId: ByteArray, deviceId: ByteArray): AndroidWorkspaceMembershipStore.State?
}

class AndroidWorkspaceMembershipStore(
    context: Context,
    storeName: String = "default",
) : WorkspaceMembershipTrustStore, WorkspaceNotificationRecipientDirectory, AutoCloseable {
    enum class PinResult { PINNED, ALREADY_PINNED }
    enum class ReconcileResult { APPLIED, ALREADY_APPLIED }

    data class State(
        val workspaceId: ByteArray,
        val deviceId: ByteArray,
        val authorityPublicKey: ByteArray,
        val signedCertificate: ByteArray?,
        val rosterEpoch: Long,
        val rosterDigest: ByteArray?,
        val signedRoster: ByteArray?,
        val localDeviceActive: Boolean,
    )

    private val safeName = storeName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) { "Invalid membership store name" }
    }
    private val helper = Helper(context.applicationContext, "syncnotifications-membership-$safeName.db")

    @Synchronized
    override fun pinAuthority(workspaceId: ByteArray, deviceId: ByteArray, authorityPublicKey: ByteArray): PinResult {
        requireId(workspaceId, "workspaceId")
        requireId(deviceId, "deviceId")
        require(authorityPublicKey.size == 32) { "Authority public key must be 32 bytes" }
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val existing = read(database, workspaceId, deviceId)
            val result = if (existing == null) {
                database.insertOrThrow(TABLE, null, ContentValues().apply {
                    put(WORKSPACE, workspaceId.toHex())
                    put(DEVICE, deviceId.toHex())
                    put(AUTHORITY, authorityPublicKey.copyOf())
                    put(EPOCH, 0L)
                    put(ACTIVE, 0)
                })
                PinResult.PINNED
            } else {
                check(MessageDigest.isEqual(existing.authorityPublicKey, authorityPublicKey)) {
                    "Workspace authority replacement requires an authenticated transition"
                }
                PinResult.ALREADY_PINNED
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    @Synchronized
    override fun reconcileApproved(
        workspaceId: ByteArray,
        deviceId: ByteArray,
        signedCertificate: ByteArray,
        signedRoster: ByteArray,
    ): ReconcileResult {
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val existing = read(database, workspaceId, deviceId)
                ?: error("Workspace authority must be pinned before membership reconciliation")
            val certificate = WorkspaceMembershipV1.decodeCertificate(
                signedCertificate,
                existing.authorityPublicKey,
            )
            check(
                certificate.certificate.workspaceId.toByteArray().contentEquals(workspaceId) &&
                    certificate.certificate.deviceId.toByteArray().contentEquals(deviceId),
            ) { "Device certificate is not bound to this local device" }
            if (existing.signedCertificate != null) {
                check(MessageDigest.isEqual(existing.signedCertificate, signedCertificate)) {
                    "Device certificate replacement requires a higher-level membership transition"
                }
            }
            val roster = WorkspaceMembershipV1.decodeRoster(signedRoster, existing.authorityPublicKey)
            check(roster.roster.workspaceId.toByteArray().contentEquals(workspaceId)) {
                "Workspace roster is not bound to the pinned workspace"
            }
            val epoch = roster.roster.rosterEpoch
            val digest = roster.rosterDigest.toByteArray()
            val localActive = roster.roster.activeCertificatesList.any {
                MessageDigest.isEqual(it.certificateId.toByteArray(), certificate.certificateId.toByteArray()) &&
                    MessageDigest.isEqual(it.toByteArray(), signedCertificate)
            }
            val result = when {
                existing.rosterEpoch == 0L -> {
                    check(epoch >= certificate.certificate.membershipEpoch && localActive) {
                        "Bootstrap roster must contain the exact local device certificate"
                    }
                    ReconcileResult.APPLIED
                }
                epoch == existing.rosterEpoch -> {
                    check(
                        MessageDigest.isEqual(existing.rosterDigest, digest) &&
                            MessageDigest.isEqual(existing.signedRoster, signedRoster),
                    ) { "Roster epoch is bound to different canonical bytes" }
                    ReconcileResult.ALREADY_APPLIED
                }
                epoch == Math.addExact(existing.rosterEpoch, 1L) -> {
                    check(MessageDigest.isEqual(existing.rosterDigest, roster.roster.previousRosterDigest.toByteArray())) {
                        "Roster previous digest does not match the durable rollback floor"
                    }
                    ReconcileResult.APPLIED
                }
                else -> error("Roster epoch is stale or non-contiguous")
            }
            if (result == ReconcileResult.APPLIED) {
                database.update(
                    TABLE,
                    ContentValues().apply {
                        put(CERTIFICATE, signedCertificate.copyOf())
                        put(EPOCH, epoch)
                        put(DIGEST, digest)
                        put(ROSTER, signedRoster.copyOf())
                        put(ACTIVE, if (localActive) 1 else 0)
                    },
                    "$WORKSPACE = ? AND $DEVICE = ?",
                    arrayOf(workspaceId.toHex(), deviceId.toHex()),
                ).also { check(it == 1) { "Membership state changed during reconciliation" } }
            }
            database.setTransactionSuccessful()
            result
        } finally {
            database.endTransaction()
        }
    }

    override fun load(workspaceId: ByteArray, deviceId: ByteArray): State? =
        read(helper.readableDatabase, workspaceId, deviceId)?.copyState()

    override fun listNotificationRecipients(
        workspaceId: ByteArray,
        localDeviceId: ByteArray,
        nowUnixMs: Long,
    ): List<WorkspaceNotificationRecipient> {
        require(nowUnixMs > 0) { "Current time is invalid" }
        val state = load(workspaceId, localDeviceId) ?: return emptyList()
        if (!state.localDeviceActive) return emptyList()
        val signedRoster = checkNotNull(state.signedRoster)
        val roster = WorkspaceMembershipV1.decodeRoster(signedRoster, state.authorityPublicKey).roster
        val local = roster.activeCertificatesList.singleOrNull {
            MessageDigest.isEqual(it.certificate.deviceId.toByteArray(), localDeviceId) &&
                MessageDigest.isEqual(it.toByteArray(), state.signedCertificate)
        }?.certificate ?: return emptyList()
        if (DeviceRole.DEVICE_ROLE_SEND_NOTIFICATIONS !in local.rolesList ||
            !certificateIsCurrent(local, nowUnixMs)
        ) return emptyList()
        return roster.activeCertificatesList.mapNotNull { signed ->
            val certificate = signed.certificate
            if (certificate.deviceType != DeviceType.DEVICE_TYPE_CHROME ||
                DeviceRole.DEVICE_ROLE_RECEIVE_NOTIFICATIONS !in certificate.rolesList ||
                !certificateIsCurrent(certificate, nowUnixMs)
            ) return@mapNotNull null
            WorkspaceNotificationRecipient(
                certificate.deviceId.toByteArray(),
                certificate.identityKeyId.toByteArray(),
                certificate.identityPublicKey.toByteArray(),
            )
        }
    }

    fun clear() {
        helper.writableDatabase.delete(TABLE, null, null)
    }

    override fun close() = helper.close()

    private fun read(database: SQLiteDatabase, workspaceId: ByteArray, deviceId: ByteArray): State? {
        requireId(workspaceId, "workspaceId")
        requireId(deviceId, "deviceId")
        return database.query(
            TABLE,
            arrayOf(AUTHORITY, CERTIFICATE, EPOCH, DIGEST, ROSTER, ACTIVE),
            "$WORKSPACE = ? AND $DEVICE = ?",
            arrayOf(workspaceId.toHex(), deviceId.toHex()),
            null,
            null,
            null,
        ).use { cursor ->
            if (!cursor.moveToFirst()) return null
            State(
                workspaceId.copyOf(),
                deviceId.copyOf(),
                cursor.getBlob(0).copyOf(),
                if (cursor.isNull(1)) null else cursor.getBlob(1).copyOf(),
                cursor.getLong(2),
                if (cursor.isNull(3)) null else cursor.getBlob(3).copyOf(),
                if (cursor.isNull(4)) null else cursor.getBlob(4).copyOf(),
                cursor.getInt(5) == 1,
            ).also { validateStored(it) }
        }
    }

    private fun validateStored(state: State) {
        check(state.authorityPublicKey.size == 32)
        if (state.rosterEpoch == 0L) {
            check(
                state.signedCertificate == null && state.rosterDigest == null &&
                    state.signedRoster == null && !state.localDeviceActive,
            ) { "Persisted initial membership state is corrupt" }
        } else {
            check(state.signedCertificate != null && state.rosterDigest?.size == 32 && state.signedRoster != null)
            val certificate = WorkspaceMembershipV1.decodeCertificate(
                state.signedCertificate,
                state.authorityPublicKey,
            )
            val roster = WorkspaceMembershipV1.decodeRoster(state.signedRoster, state.authorityPublicKey)
            check(
                certificate.certificate.workspaceId.toByteArray().contentEquals(state.workspaceId) &&
                    certificate.certificate.deviceId.toByteArray().contentEquals(state.deviceId) &&
                    roster.roster.workspaceId.toByteArray().contentEquals(state.workspaceId) &&
                    roster.roster.rosterEpoch == state.rosterEpoch &&
                    MessageDigest.isEqual(roster.rosterDigest.toByteArray(), state.rosterDigest),
            ) { "Persisted membership cryptographic binding is corrupt" }
            val active = roster.roster.activeCertificatesList.any {
                MessageDigest.isEqual(it.certificateId.toByteArray(), certificate.certificateId.toByteArray()) &&
                    MessageDigest.isEqual(it.toByteArray(), state.signedCertificate)
            }
            check(active == state.localDeviceActive) {
                "Persisted local membership status is corrupt"
            }
        }
    }

    private fun certificateIsCurrent(
        certificate: DeviceCertificate,
        nowUnixMs: Long,
    ): Boolean = certificate.issuedAtUnixMs <= nowUnixMs &&
        (certificate.expiresAtUnixMs == 0L || certificate.expiresAtUnixMs > nowUnixMs)

    private fun State.copyState() = copy(
        workspaceId = workspaceId.copyOf(), deviceId = deviceId.copyOf(),
        authorityPublicKey = authorityPublicKey.copyOf(),
        signedCertificate = signedCertificate?.copyOf(), rosterDigest = rosterDigest?.copyOf(),
        signedRoster = signedRoster?.copyOf(),
    )

    private class Helper(context: Context, name: String) : SQLiteOpenHelper(context, name, null, 1) {
        override fun onCreate(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TABLE (" +
                    "$WORKSPACE TEXT NOT NULL, $DEVICE TEXT NOT NULL, $AUTHORITY BLOB NOT NULL, " +
                    "$CERTIFICATE BLOB, $EPOCH INTEGER NOT NULL, $DIGEST BLOB, $ROSTER BLOB, " +
                    "$ACTIVE INTEGER NOT NULL, PRIMARY KEY ($WORKSPACE, $DEVICE))",
            )
        }
        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
    }

    companion object {
        private const val TABLE = "workspace_membership"
        private const val WORKSPACE = "workspace_id"
        private const val DEVICE = "device_id"
        private const val AUTHORITY = "authority_public_key"
        private const val CERTIFICATE = "signed_certificate"
        private const val EPOCH = "roster_epoch"
        private const val DIGEST = "roster_digest"
        private const val ROSTER = "signed_roster"
        private const val ACTIVE = "local_device_active"
        private fun requireId(value: ByteArray, name: String) { require(value.size == 16 && value.any { it != 0.toByte() }) { "$name must be a non-zero 16-byte value" } }
        private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
    }
}
