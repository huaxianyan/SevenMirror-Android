package dev.notificationmirroring.storage

import android.content.Context
import android.util.Base64
import dev.notificationmirroring.crypto.AndroidHpkeIdentityStore
import dev.notificationmirroring.crypto.AndroidLocalIdentityTransitionStore
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import java.security.MessageDigest

enum class IdentityPromotionPhase { PREPARED, TRANSPORT_REBOUND, IDENTITY_PROMOTED }
enum class IdentityPromotionResult {
    NOT_READY,
    DEFERRED_TRANSPORT_ROTATION,
    PROMOTED,
    RECOVERED,
}

data class IdentityPromotionJournalRecord(
    val workspaceId: ByteArray,
    val deviceId: ByteArray,
    val transitionId: ByteArray,
    val previousKeyId: ByteArray,
    val newKeyId: ByteArray,
    val phase: IdentityPromotionPhase,
)

/** Durable non-secret journal for cross-store E2EE identity promotion. */
class AndroidIdentityPromotionJournal(
    context: Context,
    journalName: String = "default",
) {
    private val safeName = journalName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "journalName must be 1-64 URL-safe characters"
        }
    }
    private val preferences = context.applicationContext.getSharedPreferences(
        "syncnotifications.identity-promotion.$safeName",
        Context.MODE_PRIVATE,
    )

    @Synchronized
    fun load(): IdentityPromotionJournalRecord? {
        val values = listOf(
            preferences.getString(WORKSPACE_ID, null),
            preferences.getString(DEVICE_ID, null),
            preferences.getString(TRANSITION_ID, null),
            preferences.getString(PREVIOUS_KEY_ID, null),
            preferences.getString(NEW_KEY_ID, null),
            preferences.getString(PHASE, null),
        )
        val present = values.count { it != null }
        if (present == 0) return null
        check(present == values.size) { "Partial identity promotion journal; refusing recovery" }
        val record = IdentityPromotionJournalRecord(
            workspaceId = values[0]!!.decodeBase64(),
            deviceId = values[1]!!.decodeBase64(),
            transitionId = values[2]!!.decodeBase64(),
            previousKeyId = values[3]!!.decodeBase64(),
            newKeyId = values[4]!!.decodeBase64(),
            phase = runCatching { IdentityPromotionPhase.valueOf(values[5]!!) }
                .getOrElse { error("Identity promotion journal phase is invalid") },
        )
        validate(record)
        return record.copyState()
    }

    @Synchronized
    fun create(record: IdentityPromotionJournalRecord) {
        validate(record)
        check(record.phase == IdentityPromotionPhase.PREPARED) {
            "New identity promotion journal must be prepared"
        }
        check(load() == null) { "An identity promotion journal already exists" }
        check(write(record)) { "Failed to persist identity promotion journal" }
    }

    @Synchronized
    fun update(record: IdentityPromotionJournalRecord) {
        validate(record)
        val existing = checkNotNull(load()) { "Identity promotion journal is missing" }
        check(existing.sameBinding(record) && record.phase.ordinal >= existing.phase.ordinal) {
            "Identity promotion journal update does not match"
        }
        check(write(record)) { "Failed to update identity promotion journal" }
    }

    @Synchronized
    fun remove(record: IdentityPromotionJournalRecord) {
        validate(record)
        val existing = load() ?: return
        check(existing.sameBinding(record) && existing.phase == IdentityPromotionPhase.IDENTITY_PROMOTED) {
            "Identity promotion journal cannot be removed before completion"
        }
        check(preferences.edit().clear().commit()) { "Failed to remove identity promotion journal" }
    }

    @Synchronized
    fun clear() {
        check(preferences.edit().clear().commit()) { "Failed to clear identity promotion journal" }
    }

    private fun write(record: IdentityPromotionJournalRecord): Boolean = preferences.edit()
        .putString(WORKSPACE_ID, record.workspaceId.encodeBase64())
        .putString(DEVICE_ID, record.deviceId.encodeBase64())
        .putString(TRANSITION_ID, record.transitionId.encodeBase64())
        .putString(PREVIOUS_KEY_ID, record.previousKeyId.encodeBase64())
        .putString(NEW_KEY_ID, record.newKeyId.encodeBase64())
        .putString(PHASE, record.phase.name)
        .commit()

    private fun validate(record: IdentityPromotionJournalRecord) {
        validateIdentifier(record.workspaceId, "workspaceId")
        validateIdentifier(record.deviceId, "deviceId")
        validateIdentifier(record.transitionId, "transitionId")
        validateKeyId(record.previousKeyId, "previousKeyId")
        validateKeyId(record.newKeyId, "newKeyId")
        check(!MessageDigest.isEqual(record.previousKeyId, record.newKeyId)) {
            "Identity promotion journal keys must differ"
        }
    }

    private fun IdentityPromotionJournalRecord.sameBinding(other: IdentityPromotionJournalRecord): Boolean =
        MessageDigest.isEqual(workspaceId, other.workspaceId) &&
            MessageDigest.isEqual(deviceId, other.deviceId) &&
            MessageDigest.isEqual(transitionId, other.transitionId) &&
            MessageDigest.isEqual(previousKeyId, other.previousKeyId) &&
            MessageDigest.isEqual(newKeyId, other.newKeyId)

    private fun IdentityPromotionJournalRecord.copyState(): IdentityPromotionJournalRecord = copy(
        workspaceId = workspaceId.copyOf(),
        deviceId = deviceId.copyOf(),
        transitionId = transitionId.copyOf(),
        previousKeyId = previousKeyId.copyOf(),
        newKeyId = newKeyId.copyOf(),
    )

    private fun ByteArray.encodeBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)
    private fun String.decodeBase64(): ByteArray = Base64.decode(this, Base64.NO_WRAP)

    private companion object {
        const val WORKSPACE_ID = "workspace_id"
        const val DEVICE_ID = "device_id"
        const val TRANSITION_ID = "transition_id"
        const val PREVIOUS_KEY_ID = "previous_key_id"
        const val NEW_KEY_ID = "new_key_id"
        const val PHASE = "phase"
    }
}

/** Replays journaled steps until identity and transport binding converge. */
class AndroidIdentityPromotionCoordinator(
    private val identities: AndroidHpkeIdentityStore,
    private val transport: AndroidTransportCredentialStore,
    private val localTransitions: AndroidLocalIdentityTransitionStore,
    private val journal: AndroidIdentityPromotionJournal,
    private val now: () -> Long = System::currentTimeMillis,
) {
    @Synchronized
    fun promoteReady(): IdentityPromotionResult {
        var record = journal.load()
        val recovering = record != null
        if (record == null) {
            val session = localTransitions.promotionReadiness(now())
                ?: return IdentityPromotionResult.NOT_READY
            record = IdentityPromotionJournalRecord(
                workspaceId = session.workspaceId,
                deviceId = session.localDeviceId,
                transitionId = session.transitionId,
                previousKeyId = session.previousKeyId,
                newKeyId = session.newKeyId,
                phase = IdentityPromotionPhase.PREPARED,
            )
            validatePreparedState(record)
            journal.create(record)
        }

        if (mustDeferForTransportRotation(record)) {
            return IdentityPromotionResult.DEFERRED_TRANSPORT_ROTATION
        }
        transport.rebindIdentityKey(record.previousKeyId, record.newKeyId).authToken.fill(0)
        if (record.phase == IdentityPromotionPhase.PREPARED) {
            record = record.copy(phase = IdentityPromotionPhase.TRANSPORT_REBOUND)
            journal.update(record)
        }

        identities.promotePending(record.previousKeyId, record.newKeyId).privateKey.fill(0)
        if (record.phase != IdentityPromotionPhase.IDENTITY_PROMOTED) {
            record = record.copy(phase = IdentityPromotionPhase.IDENTITY_PROMOTED)
            journal.update(record)
        }

        verifyPromotedState(record)
        localTransitions.markPromotionCompleted(
            record.transitionId,
            record.previousKeyId,
            record.newKeyId,
        )
        journal.remove(record)
        return if (recovering) IdentityPromotionResult.RECOVERED else IdentityPromotionResult.PROMOTED
    }

    private fun mustDeferForTransportRotation(record: IdentityPromotionJournalRecord): Boolean {
        val rotation = transport.loadRotation() ?: return false
        try {
            if (MessageDigest.isEqual(rotation.current.identityKeyId, record.newKeyId)) return false
            if (record.phase == IdentityPromotionPhase.PREPARED &&
                MessageDigest.isEqual(rotation.current.identityKeyId, record.previousKeyId)
            ) return true
            error("Transport credential rotation conflicts with identity promotion journal")
        } finally {
            rotation.current.authToken.fill(0)
            rotation.pendingAuthToken.fill(0)
        }
    }

    private fun validatePreparedState(record: IdentityPromotionJournalRecord) {
        transport.loadRotation()?.let { rotation ->
            rotation.current.authToken.fill(0)
            rotation.pendingAuthToken.fill(0)
            error("Transport credential rotation must finish before identity promotion")
        }
        val credential = checkNotNull(transport.load()) { "Transport credential is not configured" }
        try {
            check(
                MessageDigest.isEqual(credential.workspaceId, record.workspaceId) &&
                    MessageDigest.isEqual(credential.deviceId, record.deviceId) &&
                    MessageDigest.isEqual(credential.identityKeyId, record.previousKeyId),
            ) { "Transport credential does not match identity promotion journal" }
        } finally {
            credential.authToken.fill(0)
        }
        val rotation = checkNotNull(identities.loadRotation()) {
            "Identity slots do not match identity promotion journal"
        }
        try {
            check(
                MessageDigest.isEqual(sha256(rotation.current.publicKey), record.previousKeyId) &&
                    MessageDigest.isEqual(sha256(rotation.pending.publicKey), record.newKeyId),
            ) { "Identity slots do not match identity promotion journal" }
        } finally {
            rotation.current.privateKey.fill(0)
            rotation.pending.privateKey.fill(0)
        }
    }

    private fun verifyPromotedState(record: IdentityPromotionJournalRecord) {
        identities.loadRotation()?.let { rotation ->
            rotation.current.privateKey.fill(0)
            rotation.pending.privateKey.fill(0)
            error("Pending identity remains after promotion")
        }
        val identity = checkNotNull(identities.loadExisting()) { "Promoted identity is missing" }
        val credential = checkNotNull(transport.load()) { "Transport credential is missing" }
        try {
            check(
                MessageDigest.isEqual(sha256(identity.publicKey), record.newKeyId) &&
                    MessageDigest.isEqual(credential.identityKeyId, record.newKeyId) &&
                    MessageDigest.isEqual(credential.workspaceId, record.workspaceId) &&
                    MessageDigest.isEqual(credential.deviceId, record.deviceId),
            ) { "Promoted identity and transport binding do not converge" }
        } finally {
            identity.privateKey.fill(0)
            credential.authToken.fill(0)
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)
}

private fun validateIdentifier(value: ByteArray, name: String) {
    require(value.size == 16 && value.any { it.toInt() != 0 }) {
        "$name must be a non-zero 16-byte value"
    }
}

private fun validateKeyId(value: ByteArray, name: String) {
    require(value.size == 32 && value.any { it.toInt() != 0 }) {
        "$name must be a non-zero 32-byte value"
    }
}
