# Vendored Protocol

This is a fixed copy of the canonical schema from the server repository.

- Version: see `PROTOCOL_VERSION`
- Upstream release/tag: see `UPSTREAM_REF`
- Integrity: see `SCHEMA_SHA256`

Run `./gradlew verifyVendoredProtocol` after updating it. Do not edit the vendored `.proto` file directly.

`test-vectors/` contains vendored cross-platform fixtures from the server repository. Private keys in those JSON fixtures are intentionally public test material and must never be used in production.
