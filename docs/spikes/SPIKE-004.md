# SPIKE-004: Authenticated HPKE interoperability

Status: cryptographic core and Keystore-wrapped persistence validated on API 36; API 29 remains

## Implementation

`core-crypto/AuthenticatedHpke.kt` wraps Bouncy Castle 1.85 RFC 9180 HPKE:

```text
Auth mode
DHKEM(P-256, HKDF-SHA256)
HKDF-SHA256
AES-128-GCM
info = "SyncNotifications-E2EE-v1"
```

`core-crypto/ReplayGuard.kt` demonstrates bounded duplicate and expiry decisions. It is not production persistence.

`core-crypto/AndroidHpkeIdentityStore.kt` encrypts the serialized HPKE private scalar with a non-exportable Android Keystore AES-256-GCM key and fails closed on partial or undecryptable state.

## Evidence

- Android opens the deterministic Chrome-produced authenticated fixture.
- Chrome opens an Android-produced authenticated fixture.
- Both derive identical fixed P-256 key material.
- Sender-key substitution is rejected.
- JVM unit tests pass.
- Instrumented seal/open and sender-substitution test passes on Pixel 10 Pro / Android 16 (API 36).
- Keystore-wrapped identity survives store recreation and remains usable on API 36.

Vendored vector:

```text
protocol/test-vectors/hpke-auth-p256-aes128gcm.json
```

The authoritative vector and ADR-002 live in the server repository.

## Safety boundary

The serialized private scalar and deterministic key derivation exist for spike vectors only. Production Android storage wraps generated HPKE private material with a non-exportable Android Keystore AES-GCM key; application backup is disabled. API 36 persistence/restore is proven without logging or transport, but API 29 and corruption/recovery UX still require validation. Real notification content remains blocked.

## Remaining evidence

- Android 10 / API 29 instrumented execution
- Keystore-wrapped key persistence/restore on API 29
- corruption/lost-Keystore recovery UX
- persistent atomic replay ledger
- final routing-header/AAD codec
- pairing, rotation, revocation, and lost-device behavior
