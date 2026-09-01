package dev.notificationmirroring.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceType
import org.junit.Assert.assertThrows
import org.junit.Test

class WorkspaceMembershipV1Test {
    private val vector = Vector.load()

    @Test
    fun opensBaseHpkeChallengeAndMatchesCanonicalProof() {
        val challenge = WorkspaceMembershipV1.openChallenge(
            vector.identityPublicKey,
            vector.identityPrivateScalar,
            vector.workspaceId,
            vector.deviceId,
            vector.identityKeyId,
            vector.encapsulatedKey,
            vector.ciphertext,
        )
        assertArrayEquals(vector.challengeEncoded, challenge.toByteArray())
        val proof = WorkspaceMembershipV1.decodeProof(vector.proofEncoded)
        assertArrayEquals(vector.proofEncoded, WorkspaceMembershipV1.createProof(vector.challengeEncoded))
        assertArrayEquals(vector.proofEncoded, proof.toByteArray())
        assertArrayEquals(challenge.challengeSecret.toByteArray(), proof.challengeSecret.toByteArray())
    }

    @Test
    fun verifiesCanonicalCertificateAndLinkedRosters() {
        val certificate = WorkspaceMembershipV1.decodeCertificate(vector.certificateEncoded, vector.authorityPublicKey)
        assertArrayEquals(vector.certificateId, certificate.certificateId.toByteArray())
        val initial = WorkspaceMembershipV1.decodeRoster(vector.initialRosterEncoded, vector.authorityPublicKey)
        val revoked = WorkspaceMembershipV1.decodeRoster(vector.revokedRosterEncoded, vector.authorityPublicKey)
        assertArrayEquals(initial.rosterDigest.toByteArray(), revoked.roster.previousRosterDigest.toByteArray())
        assertEquals(1L, initial.roster.rosterEpoch)
        assertEquals(2L, revoked.roster.rosterEpoch)

        val renamed = WorkspaceMembershipV1.decodeCertificate(
            vector.renamedCertificateEncoded,
            vector.authorityPublicKey,
        )
        val renameRoster = WorkspaceMembershipV1.decodeRoster(
            vector.renameRosterEncoded,
            vector.authorityPublicKey,
        )
        assertEquals("Chrome-Renamed", renamed.certificate.displayName)
        WorkspaceMembershipV1.validateRosterCertificateTransitions(initial, renameRoster)
        val transition = renameRoster.roster.certificateTransitionsList.single()
        WorkspaceMembershipV1.validateDisplayNameCertificateTransition(
            certificate,
            renamed,
            transition,
        )
        val changedType = renamed.toBuilder().setCertificate(
            renamed.certificate.toBuilder().setDeviceType(DeviceType.DEVICE_TYPE_ANDROID),
        ).build()
        assertThrows(IllegalArgumentException::class.java) {
            WorkspaceMembershipV1.validateDisplayNameCertificateTransition(
                certificate,
                changedType,
                transition,
            )
        }

        val tampered = vector.certificateEncoded.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(IllegalArgumentException::class.java) {
            WorkspaceMembershipV1.decodeCertificate(tampered, vector.authorityPublicKey)
        }
        val unknown = vector.challengeEncoded + byteArrayOf(0x40, 0x01)
        assertThrows(IllegalArgumentException::class.java) {
            WorkspaceMembershipV1.decodeChallenge(unknown)
        }
    }

    private data class Vector(
        val authorityPublicKey: ByteArray,
        val workspaceId: ByteArray,
        val deviceId: ByteArray,
        val identityPrivateScalar: ByteArray,
        val identityPublicKey: ByteArray,
        val identityKeyId: ByteArray,
        val challengeEncoded: ByteArray,
        val proofEncoded: ByteArray,
        val encapsulatedKey: ByteArray,
        val ciphertext: ByteArray,
        val certificateEncoded: ByteArray,
        val certificateId: ByteArray,
        val initialRosterEncoded: ByteArray,
        val revokedRosterEncoded: ByteArray,
        val renamedCertificateEncoded: ByteArray,
        val renameRosterEncoded: ByteArray,
    ) {
        companion object {
            fun load(): Vector {
                val text = checkNotNull(Vector::class.java.classLoader?.getResourceAsStream("workspace-membership-v1.json"))
                    .bufferedReader().use { it.readText() }
                fun hex(name: String): ByteArray {
                    val value = checkNotNull(Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"").find(text)?.groupValues?.get(1))
                    return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                }
                return Vector(
                    hex("authorityPublicKeyHex"), hex("workspaceIdHex"), hex("deviceIdHex"),
                    hex("identityPrivateScalarHex"), hex("identityPublicKeyHex"), hex("identityKeyIdHex"),
                    hex("challengeEncodedHex"), hex("proofEncodedHex"),
                    hex("possessionHpkeEncapsulatedKeyHex"), hex("possessionHpkeCiphertextHex"),
                    hex("certificateEncodedHex"), hex("certificateIdHex"),
                    hex("initialRosterEncodedHex"), hex("revokedRosterEncodedHex"),
                    hex("renamedCertificateEncodedHex"), hex("renameRosterEncodedHex"),
                )
            }
        }
    }
}
