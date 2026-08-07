# Vendored Protocol

This is a fixed copy of the canonical schema from the server repository.

- Version: see `PROTOCOL_VERSION`
- Upstream release/tag: see `UPSTREAM_REF`
- Integrity: see `SCHEMA_SHA256`

Run `./gradlew verifyVendoredProtocol` after updating it. Do not edit the vendored `.proto` file directly.

`test-vectors/` contains vendored cross-platform fixtures from the server repository. Private keys in those JSON fixtures are intentionally public test material and must never be used in production.

`routing-header-v1.md` and `test-vectors/routing-header-v1.json` are vendored copies of the provisional fixed-width HPKE AAD codec specification and canonical vector.

`encrypted-payload-v1.md`, `vendor/notification/v1/payload.proto`, and their vector define canonical encrypted `action.invoke` and `action.result` payloads.

`encrypted-envelope-v1.md` and its vector define the bounded binary frame carrying the exact AAD, P-256 encapsulated key, and ciphertext. The canonical envelope plaintext is the payload vector.

`device-auth-frame-v1.md` and `test-vectors/device-auth-frame-v1.json` define the fixed 68-byte first WebSocket authentication message. `DEVICE_AUTH_SPEC_SHA256` and `DEVICE_AUTH_VECTOR_SHA256` pin the server-owned copies. The fixture credential is public test material and must never be used for a real device.

After updating vendored schemas, regenerate committed Java Lite sources with the pinned configuration:

```sh
buf lint
buf generate
```
