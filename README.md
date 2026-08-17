# Notification Mirroring Android

Android source device for private, end-to-end encrypted notification mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SyncNotifications-Android>

> Status: local notification actions, authenticated HPKE, replay/idempotency recovery, strict registration, recoverable Keystore-wrapped transport credential rotation, and authenticated WebSocket transport are validated. The app exposes synthetic-only registration/rotation, process-start restoration, network-change recovery, and bounded reconnect; real notification synchronization remains disabled.

## Requirements

- JDK 17
- Android SDK 35
- Android Studio or the included Gradle wrapper
- Minimum runtime: Android 10 / API 29

## Build

```sh
./gradlew verifyVendoredProtocol test lint assembleDebug
```

On Windows PowerShell or Command Prompt, use `gradlew.bat`.

## Signing

Distributable debug and release APKs use the project's fixed Android signing
identity so later builds remain update-compatible. Local secret files are
ignored by Git, and GitHub Actions reconstructs the keystore from repository
secrets and verifies the certificate fingerprint. See
[`docs/SIGNING.md`](docs/SIGNING.md) for fingerprints, backup locations, CI
secret names, and recovery rules.

## Modules

- `app`: Compose application, permission guidance, synthetic-only registration UI, and process-lifetime authenticated transport/action coordinator
- `core-notification`: `NotificationListenerService` integration and approved-sender action dispatcher
- `core-protocol`: protocol models and generated code location
- `core-crypto`: authenticated HPKE, replay/operation ledgers, immutable approved-peer pins, pre-execution result reservations, durable outbox/sequence allocation, and bounded encrypted result draining
- `core-storage`: local persistence boundary
- `core-transport`: strict code-gated registration, Keystore-wrapped current/pending transport credentials, recoverable rotation, Device Auth Frame v1, and authenticated OkHttp WebSocket boundary

## Protocol

The server repository is the canonical protocol source. This repository vendors a fixed copy under `protocol/vendor` with an upstream reference and SHA-256. The current `0.1.0-dev` schema is unreleased and provisional.

## Security status

Debug builds may trust a CA explicitly installed by the device user so physical-device non-loopback HTTPS/WSS can be validated against a private development PKI. This exception is expressed through Android Network Security Configuration `debug-overrides`; non-debuggable release builds do not trust user-added CAs and continue to require a system-trusted server certificate. Cleartext remains denied outside the existing explicit loopback domains.

Transport Credential Rotation v1 stores current and at most one pending token as distinct Android Keystore AES-GCM ciphertexts bound to the same server/workspace/device/HPKE identity metadata. `prepared` and `attempted` are committed before the strict no-redirect HTTPS request. HTTP 200 does not promote. After process death or ambiguous response loss, attempted pending is retried exactly; pre-`SNO1` denial falls back to current, while only pending `SNO1` permits atomic re-wrapping and promotion. Raw tokens are absent from SharedPreferences and loaded working copies are cleared.

The listener maintains notification/action capabilities only in process memory. The authenticated transport now serializes inbound envelopes through active-route checks, immutable approved-peer pins, Auth HPKE, replay/operation ledgers, execute-once, pre-execution result reservation, and bounded encrypted result draining. Any inbound rejection enters `SECURITY_ERROR`. There is still no production approved-peer provisioning, so an unapproved sender cannot reach HPKE, replay, or action execution; registration and transport remain synthetic-only. Socket failures use jittered exponential retry from 1 to 60 seconds; duplicate terminal callbacks are collapsed per connection generation, successful `SNO1` resets the sequence, and Android network availability triggers an immediate fresh attempt. Persistent credential/identity failures remain `SECURITY_ERROR` and are not retried as network failures. Real notification content must not be transmitted until E2EE identity rotation, lost-device recovery, offline convergence, and security-review gates pass. Cleartext transport is denied globally except explicit loopback development origins.

## License

Current revisions are licensed under [`GPL-3.0-only`](LICENSE). Commercial use is permitted subject to GPLv3. See [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md) for the exact non-retroactive MIT-to-GPL boundary; the boundary revision and its ancestors remain available under MIT.
