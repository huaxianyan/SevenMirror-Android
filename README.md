# Notification Mirroring Android

Android source device for private, end-to-end encrypted notification mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SyncNotifications-Android>

> Status: local notification actions, authenticated HPKE, replay/idempotency recovery, strict registration, Keystore-wrapped transport credentials, and authenticated WebSocket transport are validated. The app now exposes synthetic-only code-gated registration, process-start restoration, network-change recovery, and bounded reconnect; business-envelope dispatch remains deliberately disconnected until trusted-device approval is complete.

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

- `app`: Compose application, permission guidance, synthetic-only registration UI, and process-lifetime authenticated transport coordinator
- `core-notification`: `NotificationListenerService` integration
- `core-protocol`: protocol models and generated code location
- `core-crypto`: authenticated HPKE, replay/operation ledgers, encrypted action/result boundaries
- `core-storage`: local persistence boundary
- `core-transport`: strict code-gated registration, Keystore-wrapped transport credentials, Device Auth Frame v1, and authenticated OkHttp WebSocket boundary

## Protocol

The server repository is the canonical protocol source. This repository vendors a fixed copy under `protocol/vendor` with an upstream reference and SHA-256. The current `0.1.0-dev` schema is unreleased and provisional.

## Security status

The listener maintains notification/action capabilities only in process memory. Registration and authenticated transport may use synthetic test data, but inbound business envelopes are closed rather than discarded because trusted-device approval and the E2EE dispatcher are not connected. Socket failures use jittered exponential retry from 1 to 60 seconds; duplicate terminal callbacks are collapsed per connection generation, successful `SNO1` resets the sequence, and Android network availability triggers an immediate fresh attempt. Persistent credential/identity failures remain `SECURITY_ERROR` and are not retried as network failures. Real notification content must not be transmitted until approval, revocation/rotation, offline convergence, and security-review gates pass. Cleartext transport is denied globally except explicit loopback development origins.

## License

MIT
