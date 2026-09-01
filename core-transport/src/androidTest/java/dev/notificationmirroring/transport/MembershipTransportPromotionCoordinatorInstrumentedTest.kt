package dev.notificationmirroring.transport

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.crypto.AndroidWorkspaceMembershipStore
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceType
import dev.notificationmirroring.protocol.generated.membership.v1.SignedDeviceCertificate
import dev.notificationmirroring.protocol.generated.membership.v1.SignedWorkspaceRoster
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MembershipTransportPromotionCoordinatorInstrumentedTest {
    @Test
    fun approvedCredentialPromotesRecoverablyAndClearsJournalLast() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val vector = Vector.load(context)
        val fixture = androidFixture(vector)
        val suffix = UUID.randomUUID().toString()
        val pendingStore = AndroidPendingMembershipStore(context, "promotion-$suffix")
        val membershipStore = AndroidWorkspaceMembershipStore(context, "promotion-$suffix")
        val transportStore = AndroidTransportCredentialStore(context, "promotion-$suffix")
        val enrollment = PendingAndroidMembership(
            "https://notify.example", vector.workspaceId, vector.deviceId,
            ByteArray(32) { 9 }, vector.identityKeyId,
        )
        try {
            pendingStore.prepareRegistration(
                enrollment, fixture.authorityPublicKey, ByteArray(65) { 7 }, ByteArray(48) { 8 },
            )
            pendingStore.bindProof(enrollment, vector.proof)
            pendingStore.markPendingApproval(enrollment)
            membershipStore.pinAuthority(vector.workspaceId, vector.deviceId, fixture.authorityPublicKey)
            membershipStore.reconcileApproved(
                vector.workspaceId, vector.deviceId, fixture.signedCertificate, fixture.signedRoster,
            )

            // Simulate a process death after transport saveNew() but before journal clear().
            transportStore.saveNew(
                StoredTransportCredential(
                    enrollment.serverOrigin, enrollment.workspaceId, enrollment.deviceId,
                    enrollment.authToken, enrollment.identityKeyId,
                ),
            )
            val promoted = MembershipTransportPromotionCoordinator(
                pendingStore,
                membershipStore,
                AndroidTransportCredentialStore(context, "promotion-$suffix"),
                { 1_800_000_000_001L },
            ).promoteApproved()

            assertArrayEquals(enrollment.authToken, promoted.authToken)
            assertArrayEquals(enrollment.identityKeyId, promoted.identityKeyId)
            assertNull(pendingStore.load())
            assertArrayEquals(enrollment.authToken, transportStore.load()?.authToken)
            promoted.authToken.fill(0)
        } finally {
            pendingStore.clear()
            transportStore.clear()
            membershipStore.clear()
            membershipStore.close()
        }
    }

    private fun androidFixture(vector: Vector): Fixture {
        val privateKey = Ed25519PrivateKeyParameters(SecureRandom())
        val authority = privateKey.generatePublicKey().encoded
        val originalSignedCertificate = SignedDeviceCertificate.parseFrom(vector.signedCertificate)
        val certificate = originalSignedCertificate.certificate.toBuilder()
            .setDeviceType(DeviceType.DEVICE_TYPE_ANDROID)
            .setDisplayName("Android-Test")
            .build()
        val certificateBytes = certificate.toByteArray()
        val signedCertificate = SignedDeviceCertificate.newBuilder()
            .setCertificate(certificate)
            .setCertificateId(ByteString.copyFrom(domainHash(CERTIFICATE_ID_DOMAIN, certificateBytes)))
            .setAuthoritySignature(ByteString.copyFrom(sign(privateKey, CERTIFICATE_SIGNATURE_DOMAIN.toByteArray() + certificateBytes)))
            .build()

        val originalRoster = SignedWorkspaceRoster.parseFrom(vector.signedRoster).roster
        val roster = originalRoster.toBuilder()
            .clearActiveCertificates()
            .addActiveCertificates(signedCertificate)
            .build()
        val rosterBytes = roster.toByteArray()
        val signedRoster = SignedWorkspaceRoster.newBuilder()
            .setRoster(roster)
            .setRosterDigest(ByteString.copyFrom(domainHash(ROSTER_DIGEST_DOMAIN, rosterBytes)))
            .setAuthoritySignature(ByteString.copyFrom(sign(privateKey, ROSTER_SIGNATURE_DOMAIN.toByteArray() + rosterBytes)))
            .build()
        return Fixture(authority, signedCertificate.toByteArray(), signedRoster.toByteArray())
    }

    private fun domainHash(domain: String, value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(domain.toByteArray() + value)

    private fun sign(key: Ed25519PrivateKeyParameters, value: ByteArray): ByteArray =
        Ed25519Signer().apply { init(true, key); update(value, 0, value.size) }.generateSignature()

    private data class Fixture(
        val authorityPublicKey: ByteArray,
        val signedCertificate: ByteArray,
        val signedRoster: ByteArray,
    )

    private data class Vector(
        val workspaceId: ByteArray,
        val deviceId: ByteArray,
        val identityKeyId: ByteArray,
        val proof: ByteArray,
        val signedCertificate: ByteArray,
        val signedRoster: ByteArray,
    ) {
        companion object {
            fun load(context: Context): Vector {
                val json = JSONObject(
                    context.assets.open("workspace-membership-v1.json")
                        .bufferedReader().use { it.readText() },
                )
                fun hex(name: String): ByteArray = json.getString(name).chunked(2)
                    .map { it.toInt(16).toByte() }.toByteArray()
                return Vector(
                    hex("workspaceIdHex"), hex("deviceIdHex"), hex("identityKeyIdHex"),
                    hex("proofEncodedHex"), hex("certificateEncodedHex"),
                    hex("initialRosterEncodedHex"),
                )
            }
        }
    }

    private companion object {
        const val CERTIFICATE_ID_DOMAIN = "SyncNotifications-membership-device-certificate-id-v1\u0000"
        const val CERTIFICATE_SIGNATURE_DOMAIN = "SyncNotifications-membership-device-certificate-signature-v1\u0000"
        const val ROSTER_DIGEST_DOMAIN = "SyncNotifications-membership-workspace-roster-digest-v1\u0000"
        const val ROSTER_SIGNATURE_DOMAIN = "SyncNotifications-membership-workspace-roster-signature-v1\u0000"
    }
}
