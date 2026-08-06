# Vendored Protocol

This is a fixed copy of the canonical schema from the server repository.

- Version: see `PROTOCOL_VERSION`
- Upstream release/tag: see `UPSTREAM_REF`
- Integrity: see `SCHEMA_SHA256`

Run `./gradlew verifyVendoredProtocol` after updating it. Do not edit the vendored `.proto` file directly.

`test-vectors/` contains vendored cross-platform fixtures from the server repository. Private keys in those JSON fixtures are intentionally public test material and must never be used in production.

`routing-header-v1.md` and `test-vectors/routing-header-v1.json` are vendored copies of the provisional fixed-width HPKE AAD codec specification and canonical vector.

`encrypted-envelope-v1.md` and its vector define the bounded binary frame carrying the exact AAD, P-256 encapsulated key, and ciphertext.
