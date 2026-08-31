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

data class WorkspaceActionPeer(
    val deviceId: ByteArray,
    val identityKeyId: ByteArray,
    val identityPublicKey: ByteArray,
)

enum class WorkspaceDeviceType { ANDROID, CHROME }

data class WorkspaceDeviceSummary(
    val displayName: String,
    val deviceType: WorkspaceDeviceType,
    val isCurrentDevice: Boolean,
    val accessCurrent: Boolean,
)

fun interface WorkspaceDeviceDirectory {
    fun listAuthorizedDevices(
        workspaceId: ByteArray,
        localDeviceId: ByteArray,
        nowUnixMs: Long,
    ): List<WorkspaceDeviceSummary>
}

fun interface WorkspaceActionPeerResolver {
    fun resolveActionPeer(
        workspaceId: ByteArray,
        localDeviceId: ByteArray,
        peerDeviceId: ByteArray,
        peerKeyId: ByteArray,
        nowUnixMs: Long,
    ): WorkspaceActionPeer?
}

interface WorkspaceMembershipTrustStore {
    fun pinAuthority(workspaceId: ByteArray, deviceId: ByteArray, authorityPublicKey: ByteArray): AndroidWorkspaceMembershipStore.PinResult
    fun reconcileApproved(workspaceId: ByteArray, deviceId: ByteArray, signedCertificate: ByteArray, signedRoster: ByteArray): AndroidWorkspaceMembershipStore.ReconcileResult
    fun reconcileAuthorityTransition(workspaceId: ByteArray, deviceId: ByteArray, signedTransition: ByteArray, signedActivationRoster: ByteArray): AndroidWorkspaceMembershipStore.ReconcileResult
    fun load(workspaceId: ByteArray, deviceId: ByteArray): AndroidWorkspaceMembershipStore.State?
}

class AndroidWorkspaceMembershipStore(
    context: Context,
    storeName: String = "default",
) : WorkspaceMembershipTrustStore, WorkspaceNotificationRecipientDirectory, WorkspaceDeviceDirectory, WorkspaceActionPeerResolver, AutoCloseable {
    enum class PinResult { PINNED, ALREADY_PINNED }
    enum class ReconcileResult { APPLIED, ALREADY_APPLIED }

    data class State(
        val workspaceId: ByteArray,
        val deviceId: ByteArray,
        val authorityPublicKey: ByteArray,
        val authorityEpoch: Long,
        val authorityTransitionDigest: ByteArray,
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
                    put(AUTHORITY_EPOCH, 1L)
                    put(AUTHORITY_DIGEST, ByteArray(32))
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
                        put(AUTHORITY_EPOCH, existing.authorityEpoch)
                        put(AUTHORITY_DIGEST, existing.authorityTransitionDigest.copyOf())
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

    @Synchronized
    override fun reconcileAuthorityTransition(
        workspaceId: ByteArray,
        deviceId: ByteArray,
        signedTransition: ByteArray,
        signedActivationRoster: ByteArray,
    ): ReconcileResult {
        val database = helper.writableDatabase
        database.beginTransaction()
        return try {
            val existing = read(database, workspaceId, deviceId)
                ?: error("Workspace authority must be pinned before authority transition")
            check(existing.rosterEpoch > 0 && existing.rosterDigest != null) {
                "Authority transition requires an accepted predecessor roster"
            }
            val signed = WorkspaceMembershipV1.decodeAuthorityTransition(signedTransition)
            val transition = signed.transition
            check(transition.workspaceId.toByteArray().contentEquals(workspaceId)) {
                "Authority transition is not bound to the workspace"
            }
            if (transition.transitionEpoch == existing.authorityEpoch) {
                check(
                    MessageDigest.isEqual(signed.transitionDigest.toByteArray(), existing.authorityTransitionDigest) &&
                        MessageDigest.isEqual(transition.newAuthorityPublicKey.toByteArray(), existing.authorityPublicKey) &&
                        existing.signedRoster != null && MessageDigest.isEqual(signedActivationRoster, existing.signedRoster),
                ) { "Authority transition epoch is bound to a different transition" }
                database.setTransactionSuccessful()
                return ReconcileResult.ALREADY_APPLIED
            }
            check(
                transition.transitionEpoch == Math.addExact(existing.authorityEpoch, 1L) &&
                    MessageDigest.isEqual(transition.previousTransitionDigest.toByteArray(), existing.authorityTransitionDigest) &&
                    MessageDigest.isEqual(transition.previousAuthorityPublicKey.toByteArray(), existing.authorityPublicKey),
            ) { "Authority transition is stale, forked, or non-contiguous" }
            check(
                transition.activationRosterEpoch == Math.addExact(existing.rosterEpoch, 1L) &&
                    MessageDigest.isEqual(transition.previousRosterDigest.toByteArray(), existing.rosterDigest),
            ) { "Authority transition does not extend the durable roster floor" }
            val newAuthority = transition.newAuthorityPublicKey.toByteArray()
            val roster = WorkspaceMembershipV1.decodeRoster(signedActivationRoster, newAuthority)
            check(
                roster.roster.workspaceId.toByteArray().contentEquals(workspaceId) &&
                    roster.roster.rosterEpoch == transition.activationRosterEpoch &&
                    MessageDigest.isEqual(roster.roster.previousRosterDigest.toByteArray(), transition.previousRosterDigest.toByteArray()),
            ) { "Authority activation roster does not match the transition" }
            val local = roster.roster.activeCertificatesList.singleOrNull {
                it.certificate.deviceId.toByteArray().contentEquals(deviceId)
            } ?: error("Authority activation roster does not contain the local device")
            database.update(
                TABLE,
                ContentValues().apply {
                    put(AUTHORITY, newAuthority)
                    put(AUTHORITY_EPOCH, transition.transitionEpoch)
                    put(AUTHORITY_DIGEST, signed.transitionDigest.toByteArray())
                    put(CERTIFICATE, local.toByteArray())
                    put(EPOCH, roster.roster.rosterEpoch)
                    put(DIGEST, roster.rosterDigest.toByteArray())
                    put(ROSTER, signedActivationRoster.copyOf())
                    put(ACTIVE, 1)
                },
                "$WORKSPACE = ? AND $DEVICE = ? AND $AUTHORITY_EPOCH = ? AND $EPOCH = ?",
                arrayOf(workspaceId.toHex(), deviceId.toHex(), existing.authorityEpoch.toString(), existing.rosterEpoch.toString()),
            ).also { check(it == 1) { "Membership state changed during authority transition" } }
            database.setTransactionSuccessful()
            ReconcileResult.APPLIED
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

    override fun listAuthorizedDevices(
        workspaceId: ByteArray,
        localDeviceId: ByteArray,
        nowUnixMs: Long,
    ): List<WorkspaceDeviceSummary> {
        require(nowUnixMs > 0) { "Current time is invalid" }
        val state = load(workspaceId, localDeviceId) ?: return emptyList()
        if (!state.localDeviceActive) return emptyList()
        val roster = WorkspaceMembershipV1.decodeRoster(
            checkNotNull(state.signedRoster),
            state.authorityPublicKey,
        ).roster
        return roster.activeCertificatesList.map { signed ->
            val certificate = signed.certificate
            WorkspaceDeviceSummary(
                displayName = certificate.displayName,
                deviceType = when (certificate.deviceType) {
                    DeviceType.DEVICE_TYPE_ANDROID -> WorkspaceDeviceType.ANDROID
                    DeviceType.DEVICE_TYPE_CHROME -> WorkspaceDeviceType.CHROME
                    else -> error("Authorized roster contains an unsupported device type")
                },
                isCurrentDevice = MessageDigest.isEqual(
                    certificate.deviceId.toByteArray(),
                    localDeviceId,
                ),
                accessCurrent = certificateIsCurrent(certificate, nowUnixMs),
            )
        }.sortedWith(
            compareByDescending<WorkspaceDeviceSummary> { it.isCurrentDevice }
                .thenBy(WorkspaceDeviceSummary::deviceType)
                .thenBy(String.CASE_INSENSITIVE_ORDER, WorkspaceDeviceSummary::displayName),
        )
    }

    override fun resolveActionPeer(
        workspaceId: ByteArray,
        localDeviceId: ByteArray,
        peerDeviceId: ByteArray,
        peerKeyId: ByteArray,
        nowUnixMs: Long,
    ): WorkspaceActionPeer? {
        require(nowUnixMs > 0) { "Current time is invalid" }
        val state = load(workspaceId, localDeviceId) ?: return null
        if (!state.localDeviceActive) return null
        val roster = WorkspaceMembershipV1.decodeRoster(
            checkNotNull(state.signedRoster),
            state.authorityPublicKey,
        ).roster
        val local = roster.activeCertificatesList.singleOrNull {
            MessageDigest.isEqual(it.certificate.deviceId.toByteArray(), localDeviceId) &&
                MessageDigest.isEqual(it.toByteArray(), state.signedCertificate)
        }?.certificate ?: return null
        val peer = roster.activeCertificatesList.singleOrNull {
            MessageDigest.isEqual(it.certificate.deviceId.toByteArray(), peerDeviceId) &&
                MessageDigest.isEqual(it.certificate.identityKeyId.toByteArray(), peerKeyId)
        }?.certificate ?: return null
        return authorizeWorkspaceActionPeer(local, peer, nowUnixMs)
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
            arrayOf(AUTHORITY, AUTHORITY_EPOCH, AUTHORITY_DIGEST, CERTIFICATE, EPOCH, DIGEST, ROSTER, ACTIVE),
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
                cursor.getLong(1),
                cursor.getBlob(2).copyOf(),
                if (cursor.isNull(3)) null else cursor.getBlob(3).copyOf(),
                cursor.getLong(4),
                if (cursor.isNull(5)) null else cursor.getBlob(5).copyOf(),
                if (cursor.isNull(6)) null else cursor.getBlob(6).copyOf(),
                cursor.getInt(7) == 1,
            ).also { validateStored(it) }
        }
    }

    private fun validateStored(state: State) {
        check(state.authorityPublicKey.size == 32 && state.authorityEpoch > 0 && state.authorityTransitionDigest.size == 32)
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
        authorityTransitionDigest = authorityTransitionDigest.copyOf(),
        signedCertificate = signedCertificate?.copyOf(), rosterDigest = rosterDigest?.copyOf(),
        signedRoster = signedRoster?.copyOf(),
    )

    private class Helper(context: Context, name: String) : SQLiteOpenHelper(context, name, null, 2) {
        override fun onCreate(database: SQLiteDatabase) {
            database.execSQL(
                "CREATE TABLE $TABLE (" +
                    "$WORKSPACE TEXT NOT NULL, $DEVICE TEXT NOT NULL, $AUTHORITY BLOB NOT NULL, " +
                    "$AUTHORITY_EPOCH INTEGER NOT NULL, $AUTHORITY_DIGEST BLOB NOT NULL, " +
                    "$CERTIFICATE BLOB, $EPOCH INTEGER NOT NULL, $DIGEST BLOB, $ROSTER BLOB, " +
                    "$ACTIVE INTEGER NOT NULL, PRIMARY KEY ($WORKSPACE, $DEVICE))",
            )
        }
        override fun onUpgrade(database: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            if (oldVersion < 2) {
                database.execSQL("ALTER TABLE $TABLE ADD COLUMN $AUTHORITY_EPOCH INTEGER NOT NULL DEFAULT 1")
                database.execSQL("ALTER TABLE $TABLE ADD COLUMN $AUTHORITY_DIGEST BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'")
            }
        }
    }

    companion object {
        private const val TABLE = "workspace_membership"
        private const val WORKSPACE = "workspace_id"
        private const val DEVICE = "device_id"
        private const val AUTHORITY = "authority_public_key"
        private const val AUTHORITY_EPOCH = "authority_epoch"
        private const val AUTHORITY_DIGEST = "authority_transition_digest"
        private const val CERTIFICATE = "signed_certificate"
        private const val EPOCH = "roster_epoch"
        private const val DIGEST = "roster_digest"
        private const val ROSTER = "signed_roster"
        private const val ACTIVE = "local_device_active"
        private fun requireId(value: ByteArray, name: String) { require(value.size == 16 && value.any { it != 0.toByte() }) { "$name must be a non-zero 16-byte value" } }
        private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
    }
}

internal fun authorizeWorkspaceActionPeer(
    local: DeviceCertificate,
    peer: DeviceCertificate,
    nowUnixMs: Long,
): WorkspaceActionPeer? {
    fun current(certificate: DeviceCertificate) =
        certificate.issuedAtUnixMs <= nowUnixMs &&
            (certificate.expiresAtUnixMs == 0L || certificate.expiresAtUnixMs > nowUnixMs)
    if (local.deviceType != DeviceType.DEVICE_TYPE_ANDROID ||
        DeviceRole.DEVICE_ROLE_SEND_NOTIFICATIONS !in local.rolesList ||
        peer.deviceType != DeviceType.DEVICE_TYPE_CHROME ||
        DeviceRole.DEVICE_ROLE_INVOKE_NOTIFICATION_ACTIONS !in peer.rolesList ||
        !current(local) || !current(peer)
    ) return null
    return WorkspaceActionPeer(
        peer.deviceId.toByteArray(),
        peer.identityKeyId.toByteArray(),
        peer.identityPublicKey.toByteArray(),
    )
}
