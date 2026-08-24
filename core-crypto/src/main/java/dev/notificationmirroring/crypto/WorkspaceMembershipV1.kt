package dev.notificationmirroring.crypto

import com.google.protobuf.ByteString
import com.google.protobuf.CodedInputStream
import dev.notificationmirroring.protocol.generated.membership.v1.AuthorityKeyTransition
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceCertificate
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceRole
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceType
import dev.notificationmirroring.protocol.generated.membership.v1.IdentityPossessionChallenge
import dev.notificationmirroring.protocol.generated.membership.v1.PendingIdentityProof
import dev.notificationmirroring.protocol.generated.membership.v1.RevokedCertificate
import dev.notificationmirroring.protocol.generated.membership.v1.SignedAuthorityKeyTransition
import dev.notificationmirroring.protocol.generated.membership.v1.SignedDeviceCertificate
import dev.notificationmirroring.protocol.generated.membership.v1.SignedWorkspaceRoster
import dev.notificationmirroring.protocol.generated.membership.v1.WorkspaceRoster
import java.security.MessageDigest
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

object WorkspaceMembershipV1 {
    data class AuthorityTransitionMetadata(val transitionEpoch: Long, val activationRosterEpoch: Long)
    enum class TransportDeviceType { ANDROID, CHROME }

    private const val VERSION = 1
    private const val ID_SIZE = 16
    private const val DIGEST_SIZE = 32
    private const val SIGNATURE_SIZE = 64
    private const val MAX_MESSAGE_SIZE = 1 shl 20
    private const val MAX_NAME_BYTES = 100
    private const val MAX_ACTIVE = 256
    private const val MAX_REVOCATIONS = 4096
    private const val MAX_CHALLENGE_MS = 600_000L
    private const val HPKE_INFO_DOMAIN = "SyncNotifications-membership-possession-hpke-info-v1\u0000"
    private const val CHALLENGE_DIGEST_DOMAIN = "SyncNotifications-membership-possession-challenge-digest-v1\u0000"
    private const val CERTIFICATE_ID_DOMAIN = "SyncNotifications-membership-device-certificate-id-v1\u0000"
    private const val CERTIFICATE_SIGNATURE_DOMAIN = "SyncNotifications-membership-device-certificate-signature-v1\u0000"
    private const val ROSTER_DIGEST_DOMAIN = "SyncNotifications-membership-workspace-roster-digest-v1\u0000"
    private const val ROSTER_SIGNATURE_DOMAIN = "SyncNotifications-membership-workspace-roster-signature-v1\u0000"
    private const val TRANSITION_DIGEST_DOMAIN = "SyncNotifications-membership-authority-transition-digest-v1\u0000"
    private const val TRANSITION_OLD_SIGNATURE_DOMAIN = "SyncNotifications-membership-authority-transition-old-signature-v1\u0000"
    private const val TRANSITION_NEW_SIGNATURE_DOMAIN = "SyncNotifications-membership-authority-transition-new-signature-v1\u0000"

    fun decodeChallenge(encoded: ByteArray): IdentityPossessionChallenge {
        validateSize(encoded)
        validateWire(encoded, Wire.CHALLENGE)
        return IdentityPossessionChallenge.parseFrom(encoded).also {
            validateChallenge(it)
            require(it.toByteArray().contentEquals(encoded)) { "Challenge is not canonically encoded" }
        }
    }

    fun decodeProof(encoded: ByteArray): PendingIdentityProof {
        validateSize(encoded)
        validateWire(encoded, Wire.PROOF)
        return PendingIdentityProof.parseFrom(encoded).also {
            validateBinding(it.workspaceId.toByteArray(), it.deviceId.toByteArray(), it.identityKeyId.toByteArray())
            require(it.protocolVersion == VERSION) { "Proof version is unsupported" }
            requireNonZero(it.challengeDigest.toByteArray(), DIGEST_SIZE, "Challenge digest")
            requireNonZero(it.challengeSecret.toByteArray(), DIGEST_SIZE, "Challenge secret")
            require(it.toByteArray().contentEquals(encoded)) { "Proof is not canonically encoded" }
        }
    }

    fun requireProofBinding(
        canonicalProof: ByteArray,
        workspaceId: ByteArray,
        deviceId: ByteArray,
        identityKeyId: ByteArray,
    ) {
        val proof = decodeProof(canonicalProof)
        require(
            proof.workspaceId.toByteArray().contentEquals(workspaceId) &&
                proof.deviceId.toByteArray().contentEquals(deviceId) &&
                proof.identityKeyId.toByteArray().contentEquals(identityKeyId),
        ) { "Pending membership proof binding does not match" }
    }

    fun createProof(canonicalChallenge: ByteArray): ByteArray {
        val challenge = decodeChallenge(canonicalChallenge)
        return PendingIdentityProof.newBuilder()
            .setProtocolVersion(VERSION)
            .setWorkspaceId(challenge.workspaceId)
            .setDeviceId(challenge.deviceId)
            .setIdentityKeyId(challenge.identityKeyId)
            .setChallengeDigest(ByteString.copyFrom(domainHash(CHALLENGE_DIGEST_DOMAIN, canonicalChallenge)))
            .setChallengeSecret(challenge.challengeSecret)
            .build()
            .toByteArray()
    }

    fun decodeCertificate(encoded: ByteArray, authorityPublicKey: ByteArray): SignedDeviceCertificate {
        validateSize(encoded)
        validateWire(encoded, Wire.SIGNED_CERTIFICATE)
        return SignedDeviceCertificate.parseFrom(encoded).also {
            validateSignedCertificate(it, authorityPublicKey)
            require(it.toByteArray().contentEquals(encoded)) { "Certificate is not canonically encoded" }
        }
    }

    fun decodeRoster(encoded: ByteArray, authorityPublicKey: ByteArray): SignedWorkspaceRoster {
        validateSize(encoded)
        validateWire(encoded, Wire.SIGNED_ROSTER)
        return SignedWorkspaceRoster.parseFrom(encoded).also {
            validateSignedRoster(it, authorityPublicKey)
            require(it.toByteArray().contentEquals(encoded)) { "Roster is not canonically encoded" }
        }
    }

    fun decodeAuthorityTransition(encoded: ByteArray): SignedAuthorityKeyTransition {
        validateSize(encoded)
        validateWire(encoded, Wire.SIGNED_AUTHORITY_TRANSITION)
        return SignedAuthorityKeyTransition.parseFrom(encoded).also {
            require(it.hasTransition()) { "Authority transition is required" }
            validateAuthorityTransition(it.transition)
            val body = it.transition.toByteArray()
            require(MessageDigest.isEqual(domainHash(TRANSITION_DIGEST_DOMAIN, body), it.transitionDigest.toByteArray())) {
                "Authority transition digest is invalid"
            }
            verifyEd25519(it.transition.previousAuthorityPublicKey.toByteArray(), TRANSITION_OLD_SIGNATURE_DOMAIN.toByteArray() + body, it.previousAuthoritySignature.toByteArray(), "Previous authority transition signature is invalid")
            verifyEd25519(it.transition.newAuthorityPublicKey.toByteArray(), TRANSITION_NEW_SIGNATURE_DOMAIN.toByteArray() + body, it.newAuthoritySignature.toByteArray(), "New authority transition signature is invalid")
            require(it.toByteArray().contentEquals(encoded)) { "Authority transition is not canonically encoded" }
        }
    }

    fun inspectAuthorityTransition(encoded: ByteArray): AuthorityTransitionMetadata =
        decodeAuthorityTransition(encoded).transition.let {
            AuthorityTransitionMetadata(it.transitionEpoch, it.activationRosterEpoch)
        }

    fun inspectRosterEpoch(encoded: ByteArray): Long {
        validateSize(encoded)
        validateWire(encoded, Wire.SIGNED_ROSTER)
        return SignedWorkspaceRoster.parseFrom(encoded).also {
            require(it.toByteArray().contentEquals(encoded)) { "Roster is not canonically encoded" }
        }.roster.rosterEpoch
    }

    fun requireTransportCertificateBinding(
        encoded: ByteArray,
        authorityPublicKey: ByteArray,
        workspaceId: ByteArray,
        deviceId: ByteArray,
        identityKeyId: ByteArray,
        expectedDeviceType: TransportDeviceType,
        nowUnixMs: Long,
    ) {
        require(nowUnixMs > 0) { "Current time is invalid" }
        val certificate = decodeCertificate(encoded, authorityPublicKey).certificate
        val expectedProtocolType = when (expectedDeviceType) {
            TransportDeviceType.ANDROID -> DeviceType.DEVICE_TYPE_ANDROID
            TransportDeviceType.CHROME -> DeviceType.DEVICE_TYPE_CHROME
        }
        require(
            certificate.workspaceId.toByteArray().contentEquals(workspaceId) &&
                certificate.deviceId.toByteArray().contentEquals(deviceId) &&
                certificate.identityKeyId.toByteArray().contentEquals(identityKeyId) &&
                certificate.deviceType == expectedProtocolType,
        ) { "Device certificate is not bound to this transport identity" }
        require(certificate.issuedAtUnixMs <= nowUnixMs) { "Device certificate is not yet valid" }
        require(certificate.expiresAtUnixMs == 0L || certificate.expiresAtUnixMs > nowUnixMs) {
            "Device certificate has expired"
        }
    }

    fun openChallengeCanonical(
        recipientPublicKey: ByteArray,
        recipientPrivateKey: ByteArray,
        workspaceId: ByteArray,
        deviceId: ByteArray,
        identityKeyId: ByteArray,
        encapsulatedKey: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray = openChallenge(
        recipientPublicKey,
        recipientPrivateKey,
        workspaceId,
        deviceId,
        identityKeyId,
        encapsulatedKey,
        ciphertext,
    ).toByteArray()

    fun openChallenge(
        recipientPublicKey: ByteArray,
        recipientPrivateKey: ByteArray,
        workspaceId: ByteArray,
        deviceId: ByteArray,
        identityKeyId: ByteArray,
        encapsulatedKey: ByteArray,
        ciphertext: ByteArray,
    ): IdentityPossessionChallenge {
        validateBinding(workspaceId, deviceId, identityKeyId)
        val hpke = HPKE(HPKE.mode_base, HPKE.kem_P256_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128)
        val recipient = hpke.deserializePrivateKey(recipientPrivateKey, recipientPublicKey)
        val info = HPKE_INFO_DOMAIN.toByteArray() + workspaceId + deviceId + identityKeyId
        val plaintext = hpke.open(encapsulatedKey, recipient, info, ByteArray(0), ciphertext, null, null, null)
        return decodeChallenge(plaintext).also {
            require(it.workspaceId.toByteArray().contentEquals(workspaceId) && it.deviceId.toByteArray().contentEquals(deviceId) && it.identityKeyId.toByteArray().contentEquals(identityKeyId)) {
                "Challenge binding does not match"
            }
        }
    }

    private fun validateAuthorityTransition(value: AuthorityKeyTransition) {
        require(value.protocolVersion == VERSION && value.workspaceId.size() == ID_SIZE && value.workspaceId.any { it.toInt() != 0 } && value.transitionEpoch >= 2) {
            "Authority transition version, workspace, or epoch is invalid"
        }
        val previousDigest = value.previousTransitionDigest.toByteArray()
        require(previousDigest.size == DIGEST_SIZE && if (value.transitionEpoch == 2L) previousDigest.all { it == 0.toByte() } else previousDigest.any { it != 0.toByte() }) {
            "Authority transition previous digest is invalid"
        }
        val previousKey = value.previousAuthorityPublicKey.toByteArray()
        val newKey = value.newAuthorityPublicKey.toByteArray()
        requireNonZero(previousKey, 32, "Previous authority public key")
        requireNonZero(newKey, 32, "New authority public key")
        require(!MessageDigest.isEqual(previousKey, newKey)) { "Authority transition keys must differ" }
        require(value.activationRosterEpoch >= 2) { "Authority activation roster epoch is invalid" }
        requireNonZero(value.previousRosterDigest.toByteArray(), DIGEST_SIZE, "Authority transition previous roster digest")
        require(value.issuedAtUnixMs > 0) { "Authority transition issue time is invalid" }
    }

    private fun validateChallenge(value: IdentityPossessionChallenge) {
        require(value.protocolVersion == VERSION) { "Challenge version is unsupported" }
        validateBinding(value.workspaceId.toByteArray(), value.deviceId.toByteArray(), value.identityKeyId.toByteArray())
        requireNonZero(value.challengeSecret.toByteArray(), DIGEST_SIZE, "Challenge secret")
        require(value.issuedAtUnixMs > 0 && value.expiresAtUnixMs > value.issuedAtUnixMs && value.expiresAtUnixMs - value.issuedAtUnixMs <= MAX_CHALLENGE_MS) {
            "Challenge lifetime is invalid"
        }
    }

    private fun validateSignedCertificate(value: SignedDeviceCertificate, authorityPublicKey: ByteArray) {
        require(value.hasCertificate()) { "Certificate is required" }
        validateCertificate(value.certificate)
        val body = value.certificate.toByteArray()
        val expectedId = domainHash(CERTIFICATE_ID_DOMAIN, body)
        require(MessageDigest.isEqual(expectedId, value.certificateId.toByteArray())) { "Certificate ID is invalid" }
        verifyEd25519(authorityPublicKey, CERTIFICATE_SIGNATURE_DOMAIN.toByteArray() + body, value.authoritySignature.toByteArray(), "Certificate signature is invalid")
    }

    private fun validateCertificate(value: DeviceCertificate) {
        require(value.protocolVersion == VERSION) { "Certificate version is unsupported" }
        validateBinding(value.workspaceId.toByteArray(), value.deviceId.toByteArray(), value.identityKeyId.toByteArray())
        require(value.deviceType == DeviceType.DEVICE_TYPE_ANDROID || value.deviceType == DeviceType.DEVICE_TYPE_CHROME) { "Device type is unsupported" }
        require(value.displayName.isNotBlank() && value.displayName.toByteArray().size <= MAX_NAME_BYTES) { "Display name is invalid" }
        require(value.rolesCount > 0) { "Certificate requires roles" }
        var previous = DeviceRole.DEVICE_ROLE_UNSPECIFIED_VALUE
        for (role in value.rolesValueList) {
            require(role in DeviceRole.DEVICE_ROLE_SEND_NOTIFICATIONS_VALUE..DeviceRole.DEVICE_ROLE_MANAGE_DEVICES_VALUE && role > previous) { "Certificate roles are not sorted" }
            previous = role
        }
        val identityPublicKey = value.identityPublicKey.toByteArray()
        AuthenticatedHpke.requireValidPublicKey(identityPublicKey)
        require(MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(identityPublicKey), value.identityKeyId.toByteArray())) { "Identity key ID is invalid" }
        require(value.issuedAtUnixMs > 0 && (value.expiresAtUnixMs == 0L || value.expiresAtUnixMs > value.issuedAtUnixMs) && value.membershipEpoch > 0) { "Certificate time or epoch is invalid" }
    }

    private fun validateSignedRoster(value: SignedWorkspaceRoster, authorityPublicKey: ByteArray) {
        require(value.hasRoster()) { "Roster is required" }
        validateRoster(value.roster, authorityPublicKey)
        val body = value.roster.toByteArray()
        require(MessageDigest.isEqual(domainHash(ROSTER_DIGEST_DOMAIN, body), value.rosterDigest.toByteArray())) { "Roster digest is invalid" }
        verifyEd25519(authorityPublicKey, ROSTER_SIGNATURE_DOMAIN.toByteArray() + body, value.authoritySignature.toByteArray(), "Roster signature is invalid")
    }

    private fun validateRoster(value: WorkspaceRoster, authorityPublicKey: ByteArray) {
        require(value.protocolVersion == VERSION && value.workspaceId.size() == ID_SIZE && value.workspaceId.any { it.toInt() != 0 } && value.rosterEpoch > 0) { "Roster version, workspace, or epoch is invalid" }
        val previousDigest = value.previousRosterDigest.toByteArray()
        require(previousDigest.size == DIGEST_SIZE && if (value.rosterEpoch == 1L) previousDigest.all { it == 0.toByte() } else previousDigest.any { it != 0.toByte() }) { "Previous roster digest is invalid" }
        require(value.activeCertificatesCount <= MAX_ACTIVE && value.revocationsCount <= MAX_REVOCATIONS) { "Roster entry limit exceeded" }
        var previousDevice: ByteArray? = null
        val activeIds = mutableSetOf<String>()
        for (signed in value.activeCertificatesList) {
            validateSignedCertificate(signed, authorityPublicKey)
            val certificate = signed.certificate
            val device = certificate.deviceId.toByteArray()
            require(certificate.workspaceId == value.workspaceId && certificate.membershipEpoch <= value.rosterEpoch && (previousDevice == null || compareUnsigned(previousDevice, device) < 0)) { "Active certificate roster binding or order is invalid" }
            previousDevice = device
            activeIds += signed.certificateId.toByteArray().toHex()
        }
        var previousCertificate: ByteArray? = null
        for (revoked in value.revocationsList) {
            validateRevocation(revoked)
            val id = revoked.certificateId.toByteArray()
            require((previousCertificate == null || compareUnsigned(previousCertificate, id) < 0) && id.toHex() !in activeIds) { "Roster revocation is invalid" }
            previousCertificate = id
        }
    }

    private fun validateRevocation(value: RevokedCertificate) {
        requireNonZero(value.certificateId.toByteArray(), DIGEST_SIZE, "Revoked certificate ID")
        requireNonZero(value.deviceId.toByteArray(), ID_SIZE, "Revoked device ID")
        require(value.revokedAtUnixMs > 0) { "Revocation time is invalid" }
    }

    private fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray, error: String) {
        require(publicKey.size == 32 && signature.size == SIGNATURE_SIZE) { error }
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(message, 0, message.size)
        require(verifier.verifySignature(signature)) { error }
    }

    private fun domainHash(domain: String, value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(domain.toByteArray() + value)
    private fun validateBinding(workspace: ByteArray, device: ByteArray, key: ByteArray) { requireNonZero(workspace, ID_SIZE, "Workspace ID"); requireNonZero(device, ID_SIZE, "Device ID"); requireNonZero(key, DIGEST_SIZE, "Identity key ID") }
    private fun requireNonZero(value: ByteArray, size: Int, name: String) { require(value.size == size && value.any { it != 0.toByte() }) { "$name is invalid" } }
    private fun validateSize(value: ByteArray) { require(value.isNotEmpty() && value.size <= MAX_MESSAGE_SIZE) { "Membership message size is invalid" } }
    private fun compareUnsigned(left: ByteArray, right: ByteArray): Int { for (index in 0 until minOf(left.size, right.size)) { val result = (left[index].toInt() and 255) - (right[index].toInt() and 255); if (result != 0) return result }; return left.size - right.size }
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private enum class Wire { CHALLENGE, PROOF, CERTIFICATE, SIGNED_CERTIFICATE, REVOCATION, ROSTER, SIGNED_ROSTER, AUTHORITY_TRANSITION, SIGNED_AUTHORITY_TRANSITION }

    private fun validateWire(encoded: ByteArray, wire: Wire) {
        val input = CodedInputStream.newInstance(encoded)
        val seen = mutableSetOf<Int>()
        while (!input.isAtEnd) {
            val tag = input.readTag()
            val repeated = wire == Wire.ROSTER && (tag == 42 || tag == 50)
            require(repeated || seen.add(tag)) { "Membership message contains duplicate fields" }
            when (wire to tag) {
                Wire.CHALLENGE to 8, Wire.PROOF to 8, Wire.CERTIFICATE to 8, Wire.ROSTER to 8, Wire.AUTHORITY_TRANSITION to 8 -> input.readUInt32()
                Wire.CHALLENGE to 18, Wire.CHALLENGE to 26, Wire.CHALLENGE to 34, Wire.CHALLENGE to 42,
                Wire.PROOF to 18, Wire.PROOF to 26, Wire.PROOF to 34, Wire.PROOF to 42, Wire.PROOF to 50,
                Wire.CERTIFICATE to 18, Wire.CERTIFICATE to 26, Wire.CERTIFICATE to 42, Wire.CERTIFICATE to 50, Wire.CERTIFICATE to 58, Wire.CERTIFICATE to 66,
                Wire.SIGNED_CERTIFICATE to 18, Wire.SIGNED_CERTIFICATE to 26,
                Wire.REVOCATION to 10, Wire.REVOCATION to 18,
                Wire.ROSTER to 18, Wire.ROSTER to 34,
                Wire.SIGNED_ROSTER to 18, Wire.SIGNED_ROSTER to 26,
                Wire.AUTHORITY_TRANSITION to 18, Wire.AUTHORITY_TRANSITION to 34, Wire.AUTHORITY_TRANSITION to 42,
                Wire.AUTHORITY_TRANSITION to 50, Wire.AUTHORITY_TRANSITION to 66,
                Wire.SIGNED_AUTHORITY_TRANSITION to 18, Wire.SIGNED_AUTHORITY_TRANSITION to 26,
                Wire.SIGNED_AUTHORITY_TRANSITION to 34 -> input.readByteArray()
                Wire.CHALLENGE to 48, Wire.CHALLENGE to 56, Wire.CERTIFICATE to 72, Wire.CERTIFICATE to 80, Wire.CERTIFICATE to 88,
                Wire.REVOCATION to 24, Wire.ROSTER to 24,
                Wire.AUTHORITY_TRANSITION to 24, Wire.AUTHORITY_TRANSITION to 56,
                Wire.AUTHORITY_TRANSITION to 72 -> input.readUInt64()
                Wire.CERTIFICATE to 32 -> input.readEnum()
                Wire.SIGNED_CERTIFICATE to 10 -> validateWire(input.readByteArray(), Wire.CERTIFICATE)
                Wire.ROSTER to 42 -> validateWire(input.readByteArray(), Wire.SIGNED_CERTIFICATE)
                Wire.ROSTER to 50 -> validateWire(input.readByteArray(), Wire.REVOCATION)
                Wire.SIGNED_ROSTER to 10 -> validateWire(input.readByteArray(), Wire.ROSTER)
                Wire.SIGNED_AUTHORITY_TRANSITION to 10 -> validateWire(input.readByteArray(), Wire.AUTHORITY_TRANSITION)
                else -> throw IllegalArgumentException("Membership message contains unknown fields")
            }
        }
    }
}
