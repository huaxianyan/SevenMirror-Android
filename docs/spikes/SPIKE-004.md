# SPIKE-004: Authenticated HPKE interoperability

Status: cryptographic core and Keystore-wrapped persistence validated on API 29 and API 36

## Implementation

`core-crypto/AuthenticatedHpke.kt` wraps Bouncy Castle 1.85 RFC 9180 HPKE:

```text
Auth mode
DHKEM(P-256, HKDF-SHA256)
HKDF-SHA256
AES-128-GCM
info = "SyncNotifications-E2EE-v1"
```

`core-crypto/ReplayGuard.kt` retains the in-memory policy model. `core-crypto/AndroidReplayLedger.kt` implements the production persistence boundary with an atomic SQLite transaction keyed by the 32-byte sender key ID and 16-byte message ID. It purges expired entries, rejects duplicates after process/store recreation, and fails closed instead of evicting live entries when capacity is exhausted.

`core-crypto/AndroidHpkeIdentityStore.kt` encrypts the serialized HPKE private scalar with a non-exportable Android Keystore AES-256-GCM key and fails closed on partial or undecryptable state.

`core-protocol/RoutingHeaderV1.kt` implements the fixed 160-byte big-endian Routing Header v1 codec. The exact encoded bytes are HPKE AAD; business message type and notification/action fields remain encrypted.

`core-protocol/EncryptedEnvelopeV1.kt` implements the bounded binary frame. `core-crypto/AuthenticatedEnvelopeReceiver.kt` validates recipient identity and expiry, authenticates HPKE with the original header bytes, and returns plaintext only after the replay tuple is atomically accepted.

`core-protocol/EncryptedPayloadV1.kt` strictly validates canonical protobuf `action.invoke` and `action.result` payloads. `core-crypto/AndroidOperationLedger.kt` persists 30-day sender/idempotency tuples plus completed canonical result bytes. `AuthenticatedActionReceiver.kt` commits replay and operation records before exposing an action, recovers completed results without re-execution, and returns `OUTCOME_UNKNOWN` for reserved operations whose result was lost.

`core-notification/AuthenticatedNotificationActionHandler.kt` resolves a random per-revision 16-byte action ID against the process-local `PendingIntent`/`RemoteInput` table. No executable Android capability is serialized.

## Evidence

- Android opens the deterministic Chrome-produced authenticated fixture.
- Chrome opens an Android-produced authenticated fixture.
- Both derive identical fixed P-256 key material.
- Sender-key substitution is rejected.
- JVM unit tests pass.
- Instrumented seal/open and sender-substitution test passes on Pixel 10 Pro / Android 16 (API 36).
- Keystore-wrapped identity survives store recreation and remains usable on API 36.
- Persistent replay tuples remain rejected after ledger recreation; expired entries and capacity exhaustion follow fail-closed policy on API 36.
- GitHub Actions Android 10 / API 29 emulator runs HPKE, Keystore persistence, and replay-ledger instrumented tests.
- Kotlin encodes and decodes the same Routing Header v1 bytes as Go and TypeScript and rejects malformed magic, suite, flags, IDs, sequence, and timestamps.
- Kotlin matches the Encrypted Envelope v1 vector, opens its Chrome-generated Auth HPKE ciphertext, and rejects truncation, trailing bytes, bad magic, invalid points, and invalid ciphertext lengths.
- Instrumented receiver tests prove tampered HPKE ciphertext does not consume replay state, a valid frame is accepted once, and its repeat is rejected.
- Kotlin matches the canonical encrypted payload bytes and rejects unknown, duplicate, non-canonical, oversized, and semantically invalid action/result fields.
- Android opens the Chrome-produced canonical action envelope and parses its notification ID and revision.
- Instrumented action tests prove replay and persistent operation-idempotency records commit before the side-effect callback; a new envelope with the same idempotency key recovers the stored result without executing twice, an invalid payload still consumes its authenticated replay tuple, and an uncertain crash window fails closed as `OUTCOME_UNKNOWN`.
- Android notification instrumented tests invoke a local test `PendingIntent` exactly once through the encrypted handler, then verify duplicate recovery, `STALE_NOTIFICATION_VERSION`, and `ACTION_NOT_FOUND` without further side effects.
- Pixel 10 Pro / Android 16 (API 36) runtime execution passes all 8 `core-crypto` and 1 `core-notification` instrumented tests, including runtime encryption of a cached result envelope. The user explicitly confirmed that the follow-up ordinary-action and free-form `RemoteInput` UI regression showed no problems after replacing action indexes with per-revision opaque action IDs; this UI conclusion is supported by, but distinct from, the instrumented test evidence.
- `ActionReceipt` exposes the exact canonical `action.result` payload persisted by the operation ledger, and `ActionResultEnvelopeSender` encrypts those bytes independently for one Chrome recipient without exposing result semantics in the frame.
- `AndroidTrustedPeerStore` persists only locally approved workspace/device/P-256 pins, validates the canonical curve point and SHA-256 binding on load, treats an identical pin as idempotent, and refuses replacement until explicit removal. No server directory path can populate it.
- `AndroidActionResultOutbox` durably binds exact canonical result bytes to the Chrome recipient device/key and idempotency key before any network send. It fails closed at capacity, restores due entries and positive per-recipient sequences after process recreation, records only locally accepted WebSocket send attempts, becomes dormant rather than deleting an unacknowledged result after the bounded short retry budget, and reactivates exact bytes when a duplicate invoke recovers the cached operation result.
- `core-transport` matches the Go `SNA1`/`SNO1` vector, rejects insecure non-loopback origins, performs strict bounded code-gated registration without following redirects, wraps the returned 32-byte credential with Android Keystore AES-GCM bound to server/workspace/device/HPKE identity metadata, sends `SNA1`, and exposes WebSocket `onOpen` to application code only after validating the server's first-message `SNO1` authentication confirmation.
- Pixel 10 Pro / Android 16 (API 36) confirms Keystore-wrapped transport credential restoration and silent-replacement refusal in an instrumented runtime test.
- The Compose app now exposes synthetic-only Android code-gated registration. `NotificationMirroringApplication` owns a process-lifetime transport coordinator that restores an existing credential, requires the existing Keystore-wrapped HPKE identity, verifies the full SHA-256 key ID binding, reports `ONLINE` only after `SNO1`, and clears temporary token and decrypted identity byte arrays. Corrupt/partial identity or credential state enters `SECURITY_ERROR` without replacement. Socket termination schedules one jittered exponential retry sequence bounded from 1 to 60 seconds; duplicate terminal callbacks are collapsed by connection generation, authentication resets backoff, explicit requests cancel stale retries, and `ConnectivityManager` availability triggers an immediate attempt. Inbound business frames close fail-closed until the E2EE dispatcher is connected.
- Android Network Security Configuration denies cleartext globally and permits it only for loopback development origins; production non-loopback registration remains HTTPS/WSS-only.
- GitHub Actions run `31453307739` passed protocol verification, unit tests, lint, fixed-signature APK builds, and API 29 crypto/notification/transport instrumentation for commit `300ca32`. The malformed-acknowledgement WebSocket test waits for the server-side terminal callback and tolerates only the subsequent `MockWebServer.shutdown()` upgrade-task race; the fail-closed and application-not-opened assertions remain mandatory.
- Pixel 10 Pro / Android 16 manual transport lifecycle validation used a dedicated loopback test server through `adb reverse` and synthetic registration data only. The user explicitly observed initial registration reaching `ONLINE`, then observed `ONLINE` again after an ADB force-stop and application restart without re-entering a pairing code. After the server was stopped, the user observed `OFFLINE` and the `Retry connection` button; after the server became ready and the button was pressed, the user observed `ONLINE` and the button disappearing. A later validation installed the bounded-reconnect build while preserving the same credential and identity: the user observed automatic `ONLINE`, then `OFFLINE` after server shutdown, and finally `ONLINE` after the server recovered without clicking Retry, restarting the app, reinstalling, or taking any connection action. These UI observations establish the manual conclusions separately from automated API 29 instrumentation and pure backoff tests; no real notification content was transported.

Vendored vectors:

```text
protocol/test-vectors/hpke-auth-p256-aes128gcm.json
protocol/test-vectors/routing-header-v1.json
protocol/test-vectors/encrypted-payload-v1.json
protocol/test-vectors/encrypted-envelope-v1.json
```

The authoritative vector and ADR-002 live in the server repository.

## Safety boundary

The serialized private scalar and deterministic key derivation exist for spike vectors only. Production Android storage wraps generated HPKE private material with a non-exportable Android Keystore AES-GCM key; application backup is disabled. API 29 and API 36 persistence/restore are proven without logging or transport; corruption/recovery UX still requires validation. Real notification content remains blocked.

## Remaining evidence

- corruption/lost-Keystore recovery UX
- connect authenticated `action.invoke` dispatch to the approved-peer store and durable result outbox
- encrypt/drain outbox entries over the authenticated WebSocket and reconcile Chrome pending operations
- physical-device validation of network-availability-triggered immediate recovery against a non-loopback HTTPS endpoint
- pairing approval, rotation, revocation, and lost-device behavior
