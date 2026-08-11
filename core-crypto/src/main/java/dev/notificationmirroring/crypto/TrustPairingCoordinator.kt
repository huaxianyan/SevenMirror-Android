package dev.notificationmirroring.crypto

import dev.notificationmirroring.protocol.TrustApprovalV1
import dev.notificationmirroring.protocol.TrustOfferV1
import dev.notificationmirroring.protocol.TrustedDevicePairingCodecV1
import java.security.SecureRandom
import kotlin.math.min

data class LocalTrustIdentity(
    val workspaceId: ByteArray,
    val deviceId: ByteArray,
    val publicKey: ByteArray,
)

sealed interface TrustPairingView {
    val expiresAtUnixMs: Long

    data class OfferCreated(
        val offerQr: String,
        override val expiresAtUnixMs: Long,
    ) : TrustPairingView

    data class CompareSafetyCode(
        val role: TrustPairingRole,
        val safetyCode: String,
        val approvalQr: String?,
        val peerDeviceId: ByteArray,
        override val expiresAtUnixMs: Long,
    ) : TrustPairingView
}

/** Durable local workflow; QR exchange is out-of-band and never delegates trust to the relay. */
class TrustPairingCoordinator(
    private val sessions: AndroidTrustPairingSessionStore,
    private val peers: AndroidTrustedPeerStore,
    private val randomBytes: (Int) -> ByteArray = DEFAULT_RANDOM,
) {
    fun createOffer(local: LocalTrustIdentity, nowUnixMs: Long = System.currentTimeMillis()):
        TrustPairingView.OfferCreated {
        validateLocal(local)
        validateNow(nowUnixMs)
        val expiresAtUnixMs = Math.addExact(nowUnixMs, TrustedDevicePairingCodecV1.MAX_TTL_MS)
        val offerBytes = TrustedDevicePairingCodecV1.encodeOffer(
            TrustOfferV1(
                workspaceId = local.workspaceId,
                deviceId = local.deviceId,
                publicKey = local.publicKey,
                nonce = randomNonZero(16),
                createdAtUnixMs = nowUnixMs,
                expiresAtUnixMs = expiresAtUnixMs,
            ),
        )
        sessions.create(
            TrustPairingSession(TrustPairingRole.OFFERER, offerBytes, null, expiresAtUnixMs),
        )
        return TrustPairingView.OfferCreated(
            TrustedDevicePairingCodecV1.encodeQr(offerBytes),
            expiresAtUnixMs,
        )
    }

    fun acceptOffer(
        offerQr: String,
        local: LocalTrustIdentity,
        nowUnixMs: Long = System.currentTimeMillis(),
    ): TrustPairingView.CompareSafetyCode {
        validateLocal(local)
        validateNow(nowUnixMs)
        val offerBytes = TrustedDevicePairingCodecV1.decodeQr(offerQr)
        val offer = TrustedDevicePairingCodecV1.decodeOffer(offerBytes)
        TrustedDevicePairingCodecV1.validateActive(
            offer.createdAtUnixMs, offer.expiresAtUnixMs, nowUnixMs,
        )
        requireEqual(offer.workspaceId, local.workspaceId, "Trust offer belongs to a different workspace")
        requireDifferent(offer.deviceId, local.deviceId, "Cannot approve the local device ID")
        requireDifferent(offer.publicKey, local.publicKey, "Cannot approve the local identity key")
        val expiresAtUnixMs = min(
            offer.expiresAtUnixMs,
            Math.addExact(nowUnixMs, TrustedDevicePairingCodecV1.MAX_TTL_MS),
        )
        val approvalBytes = TrustedDevicePairingCodecV1.encodeApproval(
            TrustApprovalV1(
                offerHash = TrustedDevicePairingCodecV1.offerHash(offerBytes),
                deviceId = local.deviceId,
                publicKey = local.publicKey,
                nonce = randomNonZero(16),
                createdAtUnixMs = nowUnixMs,
                expiresAtUnixMs = expiresAtUnixMs,
            ),
        )
        TrustedDevicePairingCodecV1.validatePair(offerBytes, approvalBytes)
        sessions.create(
            TrustPairingSession(
                TrustPairingRole.APPROVER, offerBytes, approvalBytes, expiresAtUnixMs,
            ),
        )
        return comparisonView(
            TrustPairingRole.APPROVER, offerBytes, approvalBytes, local, nowUnixMs,
        )
    }

    fun acceptApproval(
        approvalQr: String,
        local: LocalTrustIdentity,
        nowUnixMs: Long = System.currentTimeMillis(),
    ): TrustPairingView.CompareSafetyCode {
        validateLocal(local)
        validateNow(nowUnixMs)
        val session = sessions.load()
        check(session != null && session.role == TrustPairingRole.OFFERER &&
            session.approvalBytes == null) { "No offer is awaiting a trust approval" }
        val offer = TrustedDevicePairingCodecV1.decodeOffer(session.offerBytes)
        requireEqual(offer.workspaceId, local.workspaceId, "Active offer belongs to a different workspace")
        requireEqual(offer.deviceId, local.deviceId, "Active offer belongs to a different local device")
        requireEqual(offer.publicKey, local.publicKey, "Active offer belongs to a different identity key")
        TrustedDevicePairingCodecV1.validateActive(
            offer.createdAtUnixMs, offer.expiresAtUnixMs, nowUnixMs,
        )
        val approvalBytes = TrustedDevicePairingCodecV1.decodeQr(approvalQr)
        val approval = TrustedDevicePairingCodecV1.decodeApproval(approvalBytes)
        TrustedDevicePairingCodecV1.validateActive(
            approval.createdAtUnixMs, approval.expiresAtUnixMs, nowUnixMs,
        )
        TrustedDevicePairingCodecV1.validatePair(session.offerBytes, approvalBytes)
        sessions.attachApproval(session.offerBytes, approvalBytes)
        return comparisonView(
            TrustPairingRole.OFFERER, session.offerBytes, approvalBytes, local, nowUnixMs,
        )
    }

    fun resume(
        local: LocalTrustIdentity,
        nowUnixMs: Long = System.currentTimeMillis(),
    ): TrustPairingView? {
        validateLocal(local)
        validateNow(nowUnixMs)
        val session = sessions.load() ?: return null
        val offer = TrustedDevicePairingCodecV1.decodeOffer(session.offerBytes)
        TrustedDevicePairingCodecV1.validateActive(
            offer.createdAtUnixMs, offer.expiresAtUnixMs, nowUnixMs,
        )
        if (session.role == TrustPairingRole.OFFERER) {
            requireEqual(offer.workspaceId, local.workspaceId, "Active offer belongs to a different workspace")
            requireEqual(offer.deviceId, local.deviceId, "Active offer belongs to a different local device")
            requireEqual(offer.publicKey, local.publicKey, "Active offer belongs to a different identity key")
            if (session.approvalBytes == null) {
                return TrustPairingView.OfferCreated(
                    TrustedDevicePairingCodecV1.encodeQr(session.offerBytes),
                    offer.expiresAtUnixMs,
                )
            }
        }
        return comparisonView(
            session.role,
            session.offerBytes,
            checkNotNull(session.approvalBytes),
            local,
            nowUnixMs,
        )
    }

    fun confirmSafetyCode(
        displayedSafetyCode: String,
        local: LocalTrustIdentity,
        nowUnixMs: Long = System.currentTimeMillis(),
    ): AndroidTrustedPeerStore.PinResult {
        validateLocal(local)
        validateNow(nowUnixMs)
        val session = sessions.load()
        check(session?.approvalBytes != null) { "No safety code is awaiting confirmation" }
        val view = comparisonView(
            session.role, session.offerBytes, session.approvalBytes, local, nowUnixMs,
        )
        check(view.safetyCode == displayedSafetyCode) {
            "Safety code confirmation does not match the active transcript"
        }
        val offer = TrustedDevicePairingCodecV1.decodeOffer(session.offerBytes)
        val approval = TrustedDevicePairingCodecV1.decodeApproval(session.approvalBytes)
        val peerDeviceId = if (session.role == TrustPairingRole.OFFERER) {
            approval.deviceId
        } else {
            offer.deviceId
        }
        val peerPublicKey = if (session.role == TrustPairingRole.OFFERER) {
            approval.publicKey
        } else {
            offer.publicKey
        }
        val result = peers.pinApproved(local.workspaceId, peerDeviceId, peerPublicKey)
        sessions.removeExact(session.offerBytes, session.approvalBytes)
        return result
    }

    fun cancel() = sessions.cancel()

    private fun comparisonView(
        role: TrustPairingRole,
        offerBytes: ByteArray,
        approvalBytes: ByteArray,
        local: LocalTrustIdentity,
        nowUnixMs: Long,
    ): TrustPairingView.CompareSafetyCode {
        val offer = TrustedDevicePairingCodecV1.decodeOffer(offerBytes)
        val approval = TrustedDevicePairingCodecV1.decodeApproval(approvalBytes)
        TrustedDevicePairingCodecV1.validateActive(
            offer.createdAtUnixMs, offer.expiresAtUnixMs, nowUnixMs,
        )
        TrustedDevicePairingCodecV1.validateActive(
            approval.createdAtUnixMs, approval.expiresAtUnixMs, nowUnixMs,
        )
        TrustedDevicePairingCodecV1.validatePair(offerBytes, approvalBytes)
        requireEqual(
            offer.workspaceId, local.workspaceId, "Pairing transcript belongs to a different workspace",
        )
        val expectedDevice = if (role == TrustPairingRole.OFFERER) offer.deviceId else approval.deviceId
        val expectedKey = if (role == TrustPairingRole.OFFERER) offer.publicKey else approval.publicKey
        requireEqual(expectedDevice, local.deviceId, "Pairing transcript belongs to another local device")
        requireEqual(expectedKey, local.publicKey, "Pairing transcript belongs to another identity key")
        return TrustPairingView.CompareSafetyCode(
            role = role,
            safetyCode = TrustedDevicePairingCodecV1.safetyCode(offerBytes, approvalBytes),
            approvalQr = if (role == TrustPairingRole.APPROVER) {
                TrustedDevicePairingCodecV1.encodeQr(approvalBytes)
            } else {
                null
            },
            peerDeviceId = if (role == TrustPairingRole.OFFERER) {
                approval.deviceId.copyOf()
            } else {
                offer.deviceId.copyOf()
            },
            expiresAtUnixMs = approval.expiresAtUnixMs,
        )
    }

    private fun randomNonZero(size: Int): ByteArray = randomBytes(size).also { value ->
        require(value.size == size && value.any { it.toInt() != 0 }) {
            "Secure random source returned an invalid nonce"
        }
    }.copyOf()

    private fun validateLocal(value: LocalTrustIdentity) {
        validateNonZero(value.workspaceId, 16, "workspaceId")
        validateNonZero(value.deviceId, 16, "deviceId")
        AuthenticatedHpke.requireValidPublicKey(value.publicKey)
    }

    private fun validateNow(value: Long) {
        require(value >= 0 && value <= Long.MAX_VALUE - TrustedDevicePairingCodecV1.MAX_TTL_MS) {
            "nowUnixMs is out of range"
        }
    }

    private fun validateNonZero(value: ByteArray, size: Int, name: String) {
        require(value.size == size && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero $size-byte value"
        }
    }

    private fun requireEqual(left: ByteArray, right: ByteArray, message: String) {
        require(left.contentEquals(right)) { message }
    }

    private fun requireDifferent(left: ByteArray, right: ByteArray, message: String) {
        require(!left.contentEquals(right)) { message }
    }

    private companion object {
        val SECURE_RANDOM = SecureRandom()
        val DEFAULT_RANDOM: (Int) -> ByteArray = { size -> ByteArray(size).also(SECURE_RANDOM::nextBytes) }
    }
}
