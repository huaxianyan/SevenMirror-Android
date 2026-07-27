import java.security.MessageDigest

plugins {
    id("com.android.application") version "8.7.3" apply false
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}

tasks.register("verifyVendoredProtocol") {
    group = "verification"
    description = "Verifies the SHA-256 of the vendored protocol schema."
    doLast {
        val schema = file("protocol/vendor/notification/v1/envelope.proto")
        val expected = file("protocol/SCHEMA_SHA256").readText().trim()
        val actual = MessageDigest.getInstance("SHA-256")
            .digest(schema.readBytes())
            .joinToString("") { "%02x".format(it) }
        check(actual == expected) {
            "Vendored protocol hash mismatch: expected $expected, got $actual"
        }
        println("Protocol schema verified: $actual")
    }
}
