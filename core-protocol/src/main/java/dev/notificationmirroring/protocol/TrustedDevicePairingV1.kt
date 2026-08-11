package dev.notificationmirroring.protocol

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Base64

data class TrustOfferV1(
    val workspaceId: ByteArray,
    val deviceId: ByteArray,
    val publicKey: ByteArray,
    val nonce: ByteArray,
    val createdAtUnixMs: Long,
    val expiresAtUnixMs: Long,
)

data class TrustApprovalV1(
    val offerHash: ByteArray,
    val deviceId: ByteArray,
    val publicKey: ByteArray,
    val nonce: ByteArray,
    val createdAtUnixMs: Long,
    val expiresAtUnixMs: Long,
)

object TrustedDevicePairingCodecV1 {
    const val OFFER_SIZE = 133
    const val APPROVAL_SIZE = 149
    const val QR_PREFIX = "sntrust1:"
    const val MAX_TTL_MS = 10 * 60 * 1_000L
    const val MAX_FUTURE_CLOCK_SKEW_MS = 5 * 60 * 1_000L
    private const val SAFETY_DOMAIN = "SyncNotifications-Trust-SAS-v1"
    private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    private val offerMagic = byteArrayOf(0x53, 0x4e, 0x54, 0x31)
    private val approvalMagic = byteArrayOf(0x53, 0x4e, 0x54, 0x32)

    fun encodeOffer(value: TrustOfferV1): ByteArray {
        validateOffer(value)
        return ByteBuffer.allocate(OFFER_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(offerMagic)
            put(value.workspaceId)
            put(value.deviceId)
            put(value.publicKey)
            put(value.nonce)
            putLong(value.createdAtUnixMs)
            putLong(value.expiresAtUnixMs)
        }.array()
    }

    fun decodeOffer(encoded: ByteArray): TrustOfferV1 {
        require(encoded.size == OFFER_SIZE) { "trust offer must be $OFFER_SIZE bytes" }
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(buffer.readBytes(4).contentEquals(offerMagic)) {
            "unsupported trust offer magic/version"
        }
        return TrustOfferV1(
            workspaceId = buffer.readBytes(16),
            deviceId = buffer.readBytes(16),
            publicKey = buffer.readBytes(65),
            nonce = buffer.readBytes(16),
            createdAtUnixMs = buffer.long,
            expiresAtUnixMs = buffer.long,
        ).also(::validateOffer)
    }

    fun encodeApproval(value: TrustApprovalV1): ByteArray {
        validateApproval(value)
        return ByteBuffer.allocate(APPROVAL_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(approvalMagic)
            put(value.offerHash)
            put(value.deviceId)
            put(value.publicKey)
            put(value.nonce)
            putLong(value.createdAtUnixMs)
            putLong(value.expiresAtUnixMs)
        }.array()
    }

    fun decodeApproval(encoded: ByteArray): TrustApprovalV1 {
        require(encoded.size == APPROVAL_SIZE) { "trust approval must be $APPROVAL_SIZE bytes" }
        val buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(buffer.readBytes(4).contentEquals(approvalMagic)) {
            "unsupported trust approval magic/version"
        }
        return TrustApprovalV1(
            offerHash = buffer.readBytes(32),
            deviceId = buffer.readBytes(16),
            publicKey = buffer.readBytes(65),
            nonce = buffer.readBytes(16),
            createdAtUnixMs = buffer.long,
            expiresAtUnixMs = buffer.long,
        ).also(::validateApproval)
    }

    fun encodeQr(record: ByteArray): String {
        decodeRecord(record)
        return QR_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(record)
    }

    fun decodeQr(text: String): ByteArray {
        require(text == text.trim() && text.startsWith(QR_PREFIX)) {
            "trust QR prefix or whitespace is invalid"
        }
        val body = text.removePrefix(QR_PREFIX)
        require(body.isNotEmpty() && '=' !in body && body.matches(Regex("[A-Za-z0-9_-]+"))) {
            "trust QR base64url is not canonical"
        }
        val decoded = try {
            Base64.getUrlDecoder().decode(body)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("trust QR base64url is invalid", error)
        }
        require(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == body) {
            "trust QR base64url is not canonical"
        }
        decodeRecord(decoded)
        return decoded
    }

    fun validatePair(offerBytes: ByteArray, approvalBytes: ByteArray) {
        val offer = decodeOffer(offerBytes)
        val approval = decodeApproval(approvalBytes)
        require(MessageDigest.isEqual(sha256(offerBytes), approval.offerHash)) {
            "approval does not bind the exact trust offer"
        }
        require(approval.expiresAtUnixMs <= offer.expiresAtUnixMs) {
            "approval expiry exceeds offer expiry"
        }
        require(!MessageDigest.isEqual(offer.deviceId, approval.deviceId)) {
            "offerer and approver device IDs must differ"
        }
        require(!MessageDigest.isEqual(offer.publicKey, approval.publicKey)) {
            "offerer and approver public keys must differ"
        }
    }

    fun validateActive(recordCreatedAtUnixMs: Long, recordExpiresAtUnixMs: Long, nowUnixMs: Long) {
        require(nowUnixMs >= 0) { "nowUnixMs must be non-negative" }
        require(recordCreatedAtUnixMs <= Math.addExact(nowUnixMs, MAX_FUTURE_CLOCK_SKEW_MS)) {
            "trust record creation time exceeds clock-skew allowance"
        }
        require(recordExpiresAtUnixMs > nowUnixMs) { "trust record is expired" }
    }

    fun safetyCode(offerBytes: ByteArray, approvalBytes: ByteArray): String {
        validatePair(offerBytes, approvalBytes)
        val digest = MessageDigest.getInstance("SHA-256").apply {
            update(SAFETY_DOMAIN.toByteArray(Charsets.UTF_8))
            update(offerBytes)
            update(approvalBytes)
        }.digest()
        val raw = CharArray(12) { index ->
            val bit = index * 5
            val byteIndex = bit / 8
            val shift = 11 - (bit % 8)
            val pair = ((digest[byteIndex].toInt() and 0xff) shl 8) or
                (digest.getOrElse(byteIndex + 1) { 0 }.toInt() and 0xff)
            CROCKFORD[(pair ushr shift) and 31]
        }.concatToString()
        return "${raw.substring(0, 4)}-${raw.substring(4, 8)}-${raw.substring(8, 12)}"
    }

    fun offerHash(offerBytes: ByteArray): ByteArray {
        decodeOffer(offerBytes)
        return sha256(offerBytes)
    }

    private fun decodeRecord(record: ByteArray) {
        require(record.size >= 4) { "trust record is truncated" }
        when {
            record.copyOfRange(0, 4).contentEquals(offerMagic) -> decodeOffer(record)
            record.copyOfRange(0, 4).contentEquals(approvalMagic) -> decodeApproval(record)
            else -> throw IllegalArgumentException("unsupported trust record magic/version")
        }
    }

    private fun validateOffer(value: TrustOfferV1) {
        validateNonZero(value.workspaceId, 16, "workspaceId")
        validateNonZero(value.deviceId, 16, "deviceId")
        validatePublicKey(value.publicKey)
        validateNonZero(value.nonce, 16, "nonce")
        validateTtl(value.createdAtUnixMs, value.expiresAtUnixMs)
    }

    private fun validateApproval(value: TrustApprovalV1) {
        validateNonZero(value.offerHash, 32, "offerHash")
        validateNonZero(value.deviceId, 16, "deviceId")
        validatePublicKey(value.publicKey)
        validateNonZero(value.nonce, 16, "nonce")
        validateTtl(value.createdAtUnixMs, value.expiresAtUnixMs)
    }

    private fun validateTtl(createdAtUnixMs: Long, expiresAtUnixMs: Long) {
        require(createdAtUnixMs >= 0 && expiresAtUnixMs > createdAtUnixMs &&
            expiresAtUnixMs - createdAtUnixMs <= MAX_TTL_MS) {
            "trust record TTL must be in (0, 10 minutes]"
        }
    }

    private fun validateNonZero(value: ByteArray, size: Int, name: String) {
        require(value.size == size && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero $size-byte value"
        }
    }

    private fun validatePublicKey(value: ByteArray) {
        require(value.size == 65 && value[0] == 4.toByte()) {
            "trust public key must be an uncompressed P-256 point"
        }
        val x = BigInteger(1, value.copyOfRange(1, 33))
        val y = BigInteger(1, value.copyOfRange(33, 65))
        require(x < P256_P && y < P256_P &&
            y.modPow(TWO, P256_P) == x.modPow(THREE, P256_P)
                .subtract(THREE.multiply(x)).add(P256_B).mod(P256_P)) {
            "trust public key is not a valid P-256 point"
        }
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private fun ByteBuffer.readBytes(size: Int): ByteArray = ByteArray(size).also(::get)

    private val TWO = BigInteger.valueOf(2)
    private val THREE = BigInteger.valueOf(3)
    private val P256_P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val P256_B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
}
