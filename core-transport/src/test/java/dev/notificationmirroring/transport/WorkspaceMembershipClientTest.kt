package dev.notificationmirroring.transport

import dev.notificationmirroring.crypto.AndroidWorkspaceMembershipStore
import dev.notificationmirroring.crypto.AuthenticatedHpke
import dev.notificationmirroring.crypto.WorkspaceMembershipTrustStore
import java.util.Base64
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WorkspaceMembershipClientTest {
    @Test
    fun possessionProofAndApprovedRosterGateTransportEligibility() {
        val vector = Vector.load()
        val server = MockWebServer()
        val token = ByteArray(32) { 8 }
        server.enqueue(jsonResponse(201, """{
            "workspace_id":"${b64(vector.workspaceId)}","device_id":"${b64(vector.deviceId)}",
            "auth_token":"${b64(token)}","authority_public_key":"${b64(vector.authority)}",
            "challenge_enc":"${b64(vector.enc)}","challenge_ciphertext":"${b64(vector.ciphertext)}"
        }"""))
        server.enqueue(jsonResponse(200, """{"state":"pending_approval"}"""))
        server.enqueue(jsonResponse(200, """{
            "state":"approved","authority_public_key":"${b64(vector.authority)}","authority_transitions":[],
            "signed_certificate":"${b64(vector.certificate)}","rosters":["${b64(vector.initialRoster)}"],
            "latest_roster_epoch":"1"
        }"""))
        server.enqueue(jsonResponse(200, """{
            "state":"approved","authority_public_key":"${b64(vector.newAuthority)}",
            "authority_transitions":["${b64(vector.authorityTransition)}"],
            "signed_certificate":"${b64(vector.activationCertificate)}",
            "rosters":["${b64(vector.activationRoster)}"],
            "latest_roster_epoch":"2"
        }"""))
        server.start()
        val store = FakeTrustStore(vector)
        val journal = FakePendingStore()
        try {
            val client = WorkspaceMembershipClient(OkHttpClient(), store, journal)
            val pending = client.begin(AndroidMembershipRegistration(
                server.url("/").toString().removeSuffix("/"),
                "A".repeat(32),
                "Phone",
                AuthenticatedHpke.KeyPair(vector.identityPublicKey, vector.identityPrivateKey),
            ))
            assertEquals("/v1/membership/register", server.takeRequest().path)
            val proofRequest = server.takeRequest()
            assertEquals("/v1/membership/prove", proofRequest.path)
            assertTrue(proofRequest.body.readUtf8().contains("\"proof\":\"${b64(vector.proof)}\""))
            assertEquals(PendingMembershipPhase.PENDING_APPROVAL, journal.stored!!.phase)
            assertArrayEquals(vector.authority, store.state!!.authorityPublicKey)
            assertEquals(0L, store.state!!.rosterEpoch)

            val approved = client.refresh(pending)
            assertTrue(approved.transportEligible)
            assertEquals(1L, approved.state.rosterEpoch)
            assertTrue(server.takeRequest().body.readUtf8().contains("\"after_roster_epoch\":\"0\""))

            val rotated = checkNotNull(client.refreshActive(StoredTransportCredential(
                pending.serverOrigin,
                pending.workspaceId,
                pending.deviceId,
                pending.authToken,
                pending.identityKeyId,
            )))
            assertTrue(rotated.transportEligible)
            assertEquals(2L, rotated.state.authorityEpoch)
            assertEquals(2L, rotated.state.rosterEpoch)
            assertArrayEquals(vector.newAuthority, rotated.state.authorityPublicKey)
            assertTrue(server.takeRequest().body.readUtf8().contains("\"after_roster_epoch\":\"1\""))
        } finally {
            server.shutdown()
            token.fill(0)
        }
    }

    @Test
    fun exactProofResumesAfterAmbiguousAttempt() {
        val vector = Vector.load()
        val server = MockWebServer()
        server.enqueue(jsonResponse(200, """{
            "state":"pending_proof","authority_public_key":"${b64(vector.authority)}","authority_transitions":[],
            "rosters":[],"latest_roster_epoch":"0"
        }"""))
        server.enqueue(jsonResponse(200, """{"state":"pending_approval"}"""))
        server.enqueue(jsonResponse(200, """{
            "state":"pending_approval","authority_public_key":"${b64(vector.authority)}","authority_transitions":[],
            "rosters":[],"latest_roster_epoch":"0"
        }"""))
        server.start()
        val trust = FakeTrustStore(vector)
        val journal = FakePendingStore()
        val pending = PendingAndroidMembership(
            server.url("/").toString().removeSuffix("/"), vector.workspaceId, vector.deviceId,
            ByteArray(32) { 8 }, vector.identityKeyId,
        )
        trust.pinAuthority(vector.workspaceId, vector.deviceId, vector.authority)
        journal.prepareRegistration(pending, vector.authority, vector.enc, vector.ciphertext)
        journal.bindProof(pending, vector.proof)
        journal.markProofAttempted(pending, vector.proof)
        try {
            val result = WorkspaceMembershipClient(OkHttpClient(), trust, journal).resume(
                AuthenticatedHpke.KeyPair(vector.identityPublicKey, vector.identityPrivateKey),
            )
            assertEquals("pending_approval", result.serverState)
            server.takeRequest()
            assertTrue(server.takeRequest().body.readUtf8().contains("\"proof\":\"${b64(vector.proof)}\""))
            server.takeRequest()
            assertEquals(PendingMembershipPhase.PENDING_APPROVAL, journal.stored!!.phase)
        } finally {
            server.shutdown()
        }
    }

    private class FakePendingStore : PendingAndroidMembershipStore {
        var stored: StoredPendingAndroidMembership? = null
        override fun prepareRegistration(value: PendingAndroidMembership, authorityPublicKey: ByteArray, challengeEnc: ByteArray, challengeCiphertext: ByteArray): StoredPendingAndroidMembership {
            return StoredPendingAndroidMembership(value, authorityPublicKey, challengeEnc, challengeCiphertext, null, PendingMembershipPhase.REGISTERED).also { stored = it }
        }
        override fun bindProof(value: PendingAndroidMembership, canonicalProof: ByteArray) {
            stored = checkNotNull(stored).copy(canonicalProof = canonicalProof.copyOf())
        }
        override fun markProofAttempted(value: PendingAndroidMembership, canonicalProof: ByteArray) {
            stored = checkNotNull(stored).copy(phase = PendingMembershipPhase.PROOF_ATTEMPTED)
        }
        override fun markPendingApproval(value: PendingAndroidMembership) {
            stored = checkNotNull(stored).copy(phase = PendingMembershipPhase.PENDING_APPROVAL)
        }
        override fun load(): StoredPendingAndroidMembership? = stored
        override fun clear() { stored = null }
    }

    private class FakeTrustStore(private val vector: Vector) : WorkspaceMembershipTrustStore {
        var state: AndroidWorkspaceMembershipStore.State? = null
        override fun pinAuthority(workspaceId: ByteArray, deviceId: ByteArray, authorityPublicKey: ByteArray): AndroidWorkspaceMembershipStore.PinResult {
            val current = state
            if (current != null) {
                check(current.authorityPublicKey.contentEquals(authorityPublicKey))
                return AndroidWorkspaceMembershipStore.PinResult.ALREADY_PINNED
            }
            state = AndroidWorkspaceMembershipStore.State(workspaceId.copyOf(), deviceId.copyOf(), authorityPublicKey.copyOf(), 1, ByteArray(32), null, 0, null, null, false)
            return AndroidWorkspaceMembershipStore.PinResult.PINNED
        }
        override fun reconcileApproved(workspaceId: ByteArray, deviceId: ByteArray, signedCertificate: ByteArray, signedRoster: ByteArray): AndroidWorkspaceMembershipStore.ReconcileResult {
            val current = checkNotNull(state)
            val epoch = when {
                signedRoster.contentEquals(vector.initialRoster) -> 1L
                signedRoster.contentEquals(vector.revokedRoster) -> 2L
                else -> error("Unexpected test roster")
            }
            state = AndroidWorkspaceMembershipStore.State(
                workspaceId.copyOf(), deviceId.copyOf(), current.authorityPublicKey.copyOf(),
                current.authorityEpoch, current.authorityTransitionDigest.copyOf(),
                signedCertificate.copyOf(), epoch, ByteArray(32) { epoch.toByte() },
                signedRoster.copyOf(), epoch == 1L,
            )
            return AndroidWorkspaceMembershipStore.ReconcileResult.APPLIED
        }
        override fun reconcileAuthorityTransition(workspaceId: ByteArray, deviceId: ByteArray, signedTransition: ByteArray, signedActivationRoster: ByteArray): AndroidWorkspaceMembershipStore.ReconcileResult {
            check(signedTransition.contentEquals(vector.authorityTransition) && signedActivationRoster.contentEquals(vector.activationRoster))
            val current = checkNotNull(state)
            state = AndroidWorkspaceMembershipStore.State(
                workspaceId.copyOf(), deviceId.copyOf(), vector.newAuthority.copyOf(), 2,
                vector.transitionDigest.copyOf(), vector.activationCertificate.copyOf(), 2,
                vector.activationRosterDigest.copyOf(), signedActivationRoster.copyOf(), true,
            )
            check(current.authorityEpoch == 1L && current.rosterEpoch == 1L)
            return AndroidWorkspaceMembershipStore.ReconcileResult.APPLIED
        }
        override fun load(workspaceId: ByteArray, deviceId: ByteArray): AndroidWorkspaceMembershipStore.State? = state
    }

    private data class Vector(
        val authority: ByteArray, val workspaceId: ByteArray, val deviceId: ByteArray,
        val identityPrivateKey: ByteArray, val identityPublicKey: ByteArray,
        val identityKeyId: ByteArray, val enc: ByteArray, val ciphertext: ByteArray, val proof: ByteArray,
        val certificate: ByteArray, val initialRoster: ByteArray, val revokedRoster: ByteArray,
        val newAuthority: ByteArray, val authorityTransition: ByteArray, val transitionDigest: ByteArray,
        val activationCertificate: ByteArray, val activationRoster: ByteArray, val activationRosterDigest: ByteArray,
    ) {
        companion object {
            fun load(): Vector {
                val text = checkNotNull(Vector::class.java.classLoader?.getResourceAsStream("workspace-membership-v1.json")).bufferedReader().use { it.readText() }
                fun hex(name: String): ByteArray { val value = checkNotNull(Regex("\\\"$name\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"").find(text)?.groupValues?.get(1)); return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray() }
                return Vector(hex("authorityPublicKeyHex"), hex("workspaceIdHex"), hex("deviceIdHex"), hex("identityPrivateScalarHex"), hex("identityPublicKeyHex"), hex("identityKeyIdHex"), hex("possessionHpkeEncapsulatedKeyHex"), hex("possessionHpkeCiphertextHex"), hex("proofEncodedHex"), hex("certificateEncodedHex"), hex("initialRosterEncodedHex"), hex("revokedRosterEncodedHex"),
                    hex("newAuthorityPublicKeyHex"), hex("authorityTransitionEncodedHex"), hex("authorityTransitionDigestHex"),
                    hex("authorityActivationCertificateEncodedHex"), hex("authorityActivationRosterEncodedHex"), hex("authorityActivationRosterDigestHex"))
            }
        }
    }

    private fun jsonResponse(code: Int, body: String) = MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)
    private companion object { fun b64(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value) }
}
