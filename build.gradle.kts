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
        verify("protocol/routing-header-v1.md", "protocol/ROUTING_HEADER_SPEC_SHA256")
        verify(
            "protocol/test-vectors/routing-header-v1.json",
            "protocol/ROUTING_HEADER_VECTOR_SHA256",
        )
    }
}
