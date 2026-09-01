package dev.notificationmirroring.transport

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import dev.notificationmirroring.crypto.WorkspaceMembershipV1
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

enum class PendingMembershipPhase { REGISTERED, PROOF_ATTEMPTED, PENDING_APPROVAL }
data class StoredPendingAndroidMembership(
    val pending: PendingAndroidMembership,
    val authorityPublicKey: ByteArray,
    val challengeEnc: ByteArray,
    val challengeCiphertext: ByteArray,
    val canonicalProof: ByteArray?,
    val phase: PendingMembershipPhase,
)
interface PendingAndroidMembershipStore {
    fun prepareRegistration(value: PendingAndroidMembership, authorityPublicKey: ByteArray, challengeEnc: ByteArray, challengeCiphertext: ByteArray): StoredPendingAndroidMembership
    fun bindProof(value: PendingAndroidMembership, canonicalProof: ByteArray)
    fun markProofAttempted(value: PendingAndroidMembership, canonicalProof: ByteArray)
    fun markPendingApproval(value: PendingAndroidMembership)
    fun load(): StoredPendingAndroidMembership?
    fun clear()
}

/** Keystore-wrapped exact enrollment intent retained until later transport promotion. */
class AndroidPendingMembershipStore(context: Context, storeName: String = "default") : PendingAndroidMembershipStore {
    private val safeName = storeName.also { require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) { "Invalid pending membership store name" } }
    private val preferences = context.applicationContext.getSharedPreferences("syncnotifications.pending-membership.$safeName", Context.MODE_PRIVATE)
    private val keyAlias = "syncnotifications.pending-membership.wrap.$safeName"

    @Synchronized
    override fun prepareRegistration(value: PendingAndroidMembership, authorityPublicKey: ByteArray, challengeEnc: ByteArray, challengeCiphertext: ByteArray): StoredPendingAndroidMembership {
        validateRegistration(value, authorityPublicKey, challengeEnc, challengeCiphertext)
        load()?.let { existing ->
            try { check(sameRegistration(existing, value, authorityPublicKey, challengeEnc, challengeCiphertext)) { "A different membership enrollment is already pending" }; return existing.copyState() }
            finally { existing.clearSecrets() }
        }
        val plaintext = pack(value.authToken, null)
        val wrapped = try { wrap(plaintext, aad(value, authorityPublicKey, challengeEnc, challengeCiphertext)) } finally { plaintext.fill(0) }
        check(preferences.edit()
            .putString(KEY_ORIGIN, value.serverOrigin).putString(KEY_WORKSPACE, value.workspaceId.b64())
            .putString(KEY_DEVICE, value.deviceId.b64()).putString(KEY_IDENTITY, value.identityKeyId.b64())
            .putString(KEY_AUTHORITY, authorityPublicKey.b64()).putString(KEY_CHALLENGE_ENC, challengeEnc.b64())
            .putString(KEY_CHALLENGE_CIPHERTEXT, challengeCiphertext.b64())
            .putString(KEY_CIPHERTEXT, wrapped.ciphertext.b64()).putString(KEY_IV, wrapped.iv.b64())
            .putString(KEY_PHASE, PendingMembershipPhase.REGISTERED.name).commit()) { "Failed to persist pending membership enrollment" }
        return StoredPendingAndroidMembership(value.copyState(), authorityPublicKey.copyOf(), challengeEnc.copyOf(), challengeCiphertext.copyOf(), null, PendingMembershipPhase.REGISTERED)
    }

    @Synchronized
    override fun bindProof(value: PendingAndroidMembership, canonicalProof: ByteArray) {
        validateProof(value, canonicalProof)
        val existing = requireExact(value)
        try {
            existing.canonicalProof?.let { check(it.contentEquals(canonicalProof)) { "A different membership proof is already durable" }; return }
            val plaintext = pack(existing.pending.authToken, canonicalProof)
            val wrapped = try { wrap(plaintext, aad(existing.pending, existing.authorityPublicKey, existing.challengeEnc, existing.challengeCiphertext)) } finally { plaintext.fill(0) }
            check(preferences.edit().putString(KEY_CIPHERTEXT, wrapped.ciphertext.b64()).putString(KEY_IV, wrapped.iv.b64()).commit()) { "Failed to persist pending membership proof" }
        } finally { existing.clearSecrets() }
    }

    @Synchronized
    override fun markProofAttempted(value: PendingAndroidMembership, canonicalProof: ByteArray) {
        val existing = requireExact(value)
        try {
            check(existing.canonicalProof?.contentEquals(canonicalProof) == true) { "Exact pending membership proof is not prepared" }
            advance(existing.phase, PendingMembershipPhase.PROOF_ATTEMPTED)
        } finally { existing.clearSecrets() }
    }

    @Synchronized
    override fun markPendingApproval(value: PendingAndroidMembership) {
        val existing = requireExact(value)
        try { check(existing.canonicalProof != null) { "Pending membership proof is missing" }; advance(existing.phase, PendingMembershipPhase.PENDING_APPROVAL) }
        finally { existing.clearSecrets() }
    }

    @Synchronized
    override fun load(): StoredPendingAndroidMembership? {
        val values = KEYS.map { preferences.getString(it, null) }
        val present = values.count { it != null }
        if (present == 0) return null
        check(present == values.size) { "Partial pending membership state; refusing recovery" }
        val pendingMetadata = PendingAndroidMembership(
            AndroidTransportCredentialStore.normalizeServerOrigin(values[0]!!), values[1]!!.decodeB64(),
            values[2]!!.decodeB64(), ByteArray(32), values[3]!!.decodeB64(),
        )
        val authority = values[4]!!.decodeB64(); val enc = values[5]!!.decodeB64(); val challenge = values[6]!!.decodeB64()
        validateRegistration(pendingMetadata, authority, enc, challenge)
        val phase = runCatching { PendingMembershipPhase.valueOf(values[9]!!) }.getOrElse { error("Pending membership phase is corrupt") }
        val plaintext = unwrap(values[7]!!.decodeB64(), values[8]!!.decodeB64(), aad(pendingMetadata, authority, enc, challenge))
        try {
            val unpacked = unpack(plaintext)
            val pending = pendingMetadata.copy(authToken = unpacked.first)
            unpacked.second?.let { validateProof(pending, it) }
            check(phase == PendingMembershipPhase.REGISTERED || unpacked.second != null) { "Pending membership phase requires a proof" }
            return StoredPendingAndroidMembership(pending, authority, enc, challenge, unpacked.second, phase)
        } finally { plaintext.fill(0) }
    }

    @Synchronized
    override fun clear() { check(preferences.edit().clear().commit()) { "Failed to clear pending membership state" }; keyStore().let { if (it.containsAlias(keyAlias)) it.deleteEntry(keyAlias) } }

    private fun requireExact(value: PendingAndroidMembership): StoredPendingAndroidMembership {
        val existing = checkNotNull(load()) { "Exact pending membership enrollment is not prepared" }
        check(samePending(existing.pending, value)) { existing.clearSecrets(); "Exact pending membership enrollment is not prepared" }
        return existing
    }
    private fun advance(current: PendingMembershipPhase, target: PendingMembershipPhase) { if (target.ordinal > current.ordinal) check(preferences.edit().putString(KEY_PHASE, target.name).commit()) { "Failed to persist pending membership phase" } }
    private fun validateRegistration(value: PendingAndroidMembership, authority: ByteArray, enc: ByteArray, challenge: ByteArray) {
        check(AndroidTransportCredentialStore.normalizeServerOrigin(value.serverOrigin) == value.serverOrigin) { "serverOrigin must be canonical" }
        require(value.workspaceId.size == 16 && value.workspaceId.any { it != 0.toByte() } && value.deviceId.size == 16 && value.deviceId.any { it != 0.toByte() }) { "Pending membership device binding is invalid" }
        require(value.authToken.size == 32 && value.identityKeyId.size == 32 && value.identityKeyId.any { it != 0.toByte() }) { "Pending membership credential binding is invalid" }
        require(authority.size == 32 && authority.any { it != 0.toByte() } && enc.size == 65 && challenge.size in 17..2048) { "Pending membership challenge metadata is invalid" }
    }
    private fun validateProof(value: PendingAndroidMembership, proof: ByteArray) { require(proof.size in 1..1024); WorkspaceMembershipV1.requireProofBinding(proof, value.workspaceId, value.deviceId, value.identityKeyId) }
    private fun samePending(left: PendingAndroidMembership, right: PendingAndroidMembership) = left.serverOrigin == right.serverOrigin && left.workspaceId.contentEquals(right.workspaceId) && left.deviceId.contentEquals(right.deviceId) && left.authToken.contentEquals(right.authToken) && left.identityKeyId.contentEquals(right.identityKeyId)
    private fun sameRegistration(stored: StoredPendingAndroidMembership, value: PendingAndroidMembership, authority: ByteArray, enc: ByteArray, challenge: ByteArray) = samePending(stored.pending, value) && stored.authorityPublicKey.contentEquals(authority) && stored.challengeEnc.contentEquals(enc) && stored.challengeCiphertext.contentEquals(challenge)

    private fun pack(token: ByteArray, proof: ByteArray?): ByteArray = ByteBuffer.allocate(36 + (proof?.size ?: 0)).put(token).putInt(proof?.size ?: 0).apply { proof?.let { put(it) } }.array()
    private fun unpack(value: ByteArray): Pair<ByteArray, ByteArray?> { check(value.size >= 36); val input = ByteBuffer.wrap(value); val token = ByteArray(32).also { input.get(it) }; val size = input.int; check(size in 0..1024 && input.remaining() == size) { token.fill(0); "Wrapped pending membership proof is corrupt" }; return token to if (size == 0) null else ByteArray(size).also { input.get(it) } }
    private fun aad(value: PendingAndroidMembership, authority: ByteArray, enc: ByteArray, challenge: ByteArray): ByteArray { val origin = value.serverOrigin.encodeToByteArray(); return ByteBuffer.allocate(AAD_DOMAIN.size + 4 + origin.size + 16 + 16 + 32 + 32 + 65 + 4 + challenge.size).put(AAD_DOMAIN).putInt(origin.size).put(origin).put(value.workspaceId).put(value.deviceId).put(value.identityKeyId).put(authority).put(enc).putInt(challenge.size).put(challenge).array() }
    private fun wrap(value: ByteArray, aad: ByteArray): Wrapped { val cipher = Cipher.getInstance(TRANSFORMATION); cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey()); cipher.updateAAD(aad); return Wrapped(cipher.doFinal(value), cipher.iv) }
    private fun unwrap(ciphertext: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray { val key = keyStore().getKey(keyAlias, null) as? SecretKey ?: error("Pending membership wrapping key is missing"); val cipher = Cipher.getInstance(TRANSFORMATION); cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)); cipher.updateAAD(aad); return cipher.doFinal(ciphertext) }
    private fun getOrCreateKey(): SecretKey { (keyStore().getKey(keyAlias, null) as? SecretKey)?.let { return it }; return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).setRandomizedEncryptionRequired(true).build()) }.generateKey() }
    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun ByteArray.b64() = Base64.encodeToString(this, Base64.NO_WRAP)
    private fun String.decodeB64(): ByteArray = Base64.decode(this, Base64.NO_WRAP)
    private fun PendingAndroidMembership.copyState() = copy(workspaceId = workspaceId.copyOf(), deviceId = deviceId.copyOf(), authToken = authToken.copyOf(), identityKeyId = identityKeyId.copyOf())
    private fun StoredPendingAndroidMembership.copyState() = copy(pending = pending.copyState(), authorityPublicKey = authorityPublicKey.copyOf(), challengeEnc = challengeEnc.copyOf(), challengeCiphertext = challengeCiphertext.copyOf(), canonicalProof = canonicalProof?.copyOf())
    private fun StoredPendingAndroidMembership.clearSecrets() { pending.authToken.fill(0); canonicalProof?.fill(0) }
    private data class Wrapped(val ciphertext: ByteArray, val iv: ByteArray)
    private companion object {
        val AAD_DOMAIN = "SyncNotifications-pending-membership-store-v1\u0000".encodeToByteArray(); const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val KEY_ORIGIN = "server_origin"; const val KEY_WORKSPACE = "workspace_id"; const val KEY_DEVICE = "device_id"; const val KEY_IDENTITY = "identity_key_id"; const val KEY_AUTHORITY = "authority_public_key"; const val KEY_CHALLENGE_ENC = "challenge_enc"; const val KEY_CHALLENGE_CIPHERTEXT = "challenge_ciphertext"; const val KEY_CIPHERTEXT = "secret_ciphertext"; const val KEY_IV = "secret_iv"; const val KEY_PHASE = "phase"
        val KEYS = listOf(KEY_ORIGIN, KEY_WORKSPACE, KEY_DEVICE, KEY_IDENTITY, KEY_AUTHORITY, KEY_CHALLENGE_ENC, KEY_CHALLENGE_CIPHERTEXT, KEY_CIPHERTEXT, KEY_IV, KEY_PHASE)
    }
}
