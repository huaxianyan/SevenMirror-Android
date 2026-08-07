# Notification Mirroring Android

Android source device for private, end-to-end encrypted notification mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SyncNotifications-Android>

> Status: local notification actions, authenticated HPKE, replay/idempotency recovery, strict registration, Keystore-wrapped transport credentials, and authenticated WebSocket transport cores are validated. The notification listener deliberately remains disconnected from networking until pairing trust and lifecycle integration are complete.

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

- `app`: Compose application and permission guidance
- `core-notification`: `NotificationListenerService` integration
- `core-protocol`: protocol models and generated code location
- `core-crypto`: authenticated HPKE, replay/operation ledgers, encrypted action/result boundaries
- `core-storage`: local persistence boundary
- `core-transport`: strict code-gated registration, Keystore-wrapped transport credentials, Device Auth Frame v1, and authenticated OkHttp WebSocket boundary; not yet wired to the app UI or notification listener

## Protocol

The server repository is the canonical protocol source. This repository vendors a fixed copy under `protocol/vendor` with an upstream reference and SHA-256. The current `0.1.0-dev` schema is unreleased and provisional.

## Security status

The listener currently discards callbacks. It must not log, persist or transmit real notification content before the E2EE ADR and implementation are verified on API 29.

## License

MIT
