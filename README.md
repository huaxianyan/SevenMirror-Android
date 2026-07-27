# Notification Mirroring Android

Android source device for private, end-to-end encrypted notification mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SyncNotifications-Android>

> Status: foundation scaffold. The notification listener deliberately performs no networking until mandatory E2EE is implemented.

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

## Modules

- `app`: Compose application and permission guidance
- `core-notification`: `NotificationListenerService` integration
- `core-protocol`: protocol models and generated code location
- `core-crypto`: E2EE boundary; currently hard-disabled
- `core-storage`: local persistence boundary

## Protocol

The server repository is the canonical protocol source. This repository vendors a fixed copy under `protocol/vendor` with an upstream reference and SHA-256. The current `0.1.0-dev` schema is unreleased and provisional.

## Security status

The listener currently discards callbacks. It must not log, persist or transmit real notification content before the E2EE ADR and implementation are verified on API 29.

## License

MIT
