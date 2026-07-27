package dev.notificationmirroring.crypto

import java.nio.charset.StandardCharsets
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.hpke.HPKE

/**
 * RFC 9180 authenticated HPKE interoperability candidate for SPIKE-004.
 * Key persistence and replay protection are intentionally out of scope here.
 */
object AuthenticatedHpke {
    const val PROTOCOL_INFO = "SyncNotifications-E2EE-v1"

    data class KeyPair(
        val publicKey: ByteArray,
        val privateKey: ByteArray,
    )

    data class Ciphertext(
        val encapsulatedKey: ByteArray,
        val ciphertext: ByteArray,
    )

    fun generateKeyPair(): KeyPair {
        val hpke = newEngine()
        return hpke.generatePrivateKey().serialize(hpke)
    }

    fun deriveKeyPair(ikm: ByteArray): KeyPair {
        require(ikm.size >= 32) { "HPKE test IKM must contain at least 32 bytes" }
        val hpke = newEngine()
        return hpke.deriveKeyPair(ikm).serialize(hpke)
    }

    fun seal(
        recipientPublicKey: ByteArray,
        sender: KeyPair,
        plaintext: ByteArray,
        aad: ByteArray,
    ): Ciphertext {
        val hpke = newEngine()
        val recipient = hpke.deserializePublicKey(recipientPublicKey)
        val senderPair = hpke.deserializePrivateKey(sender.privateKey, sender.publicKey)
        val output = hpke.seal(
            recipient,
            protocolInfo,
            aad,
            plaintext,
            null,
            null,
            senderPair,
        )
        return Ciphertext(
            encapsulatedKey = output[1].copyOf(),
            ciphertext = output[0].copyOf(),
        )
    }

    fun open(
        recipient: KeyPair,
        senderPublicKey: ByteArray,
        encrypted: Ciphertext,
        aad: ByteArray,
    ): ByteArray {
        val hpke = newEngine()
        val recipientPair = hpke.deserializePrivateKey(recipient.privateKey, recipient.publicKey)
        val sender = hpke.deserializePublicKey(senderPublicKey)
        return hpke.open(
            encrypted.encapsulatedKey,
            recipientPair,
            protocolInfo,
            aad,
            encrypted.ciphertext,
            null,
            null,
            sender,
        )
    }

    private fun AsymmetricCipherKeyPair.serialize(hpke: HPKE): KeyPair = KeyPair(
        publicKey = hpke.serializePublicKey(public).copyOf(),
        privateKey = hpke.serializePrivateKey(private).copyOf(),
    )

    private fun newEngine(): HPKE = HPKE(
        HPKE.mode_auth,
        HPKE.kem_P256_SHA256,
        HPKE.kdf_HKDF_SHA256,
        HPKE.aead_AES_GCM128,
    )

    private val protocolInfo = PROTOCOL_INFO.toByteArray(StandardCharsets.UTF_8)
}
