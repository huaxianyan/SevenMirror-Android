import java.security.MessageDigest

plugins {
    id("com.android.application") version "8.7.3" apply false
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}

tasks.register("verifyVendoredProtocol") {
    group = "verification"
    description = "Verifies SHA-256 hashes of vendored protocol assets."
    doLast {
        fun verify(assetPath: String, hashPath: String) {
            val asset = file(assetPath)
            val expected = file(hashPath).readText().trim()
            val actual = MessageDigest.getInstance("SHA-256")
                .digest(asset.readBytes())
                .joinToString("") { "%02x".format(it) }
            check(actual == expected) {
                "Vendored protocol hash mismatch for $assetPath: expected $expected, got $actual"
            }
            println("Protocol asset verified: $assetPath $actual")
        }

        verify("protocol/vendor/notification/v1/envelope.proto", "protocol/SCHEMA_SHA256")
        verify("protocol/vendor/notification/v1/payload.proto", "protocol/PAYLOAD_SCHEMA_SHA256")
        verify("protocol/encrypted-payload-v1.md", "protocol/PAYLOAD_SPEC_SHA256")
        verify(
            "protocol/test-vectors/encrypted-payload-v1.json",
            "protocol/PAYLOAD_VECTOR_SHA256",
        )
        verify("protocol/routing-header-v1.md", "protocol/ROUTING_HEADER_SPEC_SHA256")
        verify(
            "protocol/test-vectors/routing-header-v1.json",
            "protocol/ROUTING_HEADER_VECTOR_SHA256",
        )
        verify(
            "protocol/encrypted-envelope-v1.md",
            "protocol/ENCRYPTED_ENVELOPE_SPEC_SHA256",
        )
        verify(
            "protocol/test-vectors/encrypted-envelope-v1.json",
            "protocol/ENCRYPTED_ENVELOPE_VECTOR_SHA256",
        )
        verify("protocol/device-auth-frame-v1.md", "protocol/DEVICE_AUTH_SPEC_SHA256")
        verify(
            "protocol/transport-heartbeat-v1.md",
            "protocol/TRANSPORT_HEARTBEAT_SPEC_SHA256",
        )
        verify(
            "protocol/transport-credential-rotation-v1.md",
            "protocol/TRANSPORT_CREDENTIAL_ROTATION_SPEC_SHA256",
        )
        verify(
            "protocol/test-vectors/device-auth-frame-v1.json",
            "protocol/DEVICE_AUTH_VECTOR_SHA256",
        )
        verify(
            "protocol/trusted-device-pairing-v1.md",
            "protocol/TRUST_PAIRING_SPEC_SHA256",
        )
        verify(
            "protocol/test-vectors/trusted-device-pairing-v1.json",
            "protocol/TRUST_PAIRING_VECTOR_SHA256",
        )
    }
}
