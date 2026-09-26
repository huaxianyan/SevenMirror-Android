# SevenMirror Android

Source device for SevenMirror: it captures notifications locally and sends them, end-to-end encrypted, to the user's own browsers. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SevenMirror-Android>

> Status: local notification actions, authenticated HPKE, replay/idempotency recovery, strict registration, recoverable Keystore-wrapped transport credential rotation, and authenticated WebSocket transport are validated. The app ties the user's explicit application selection to the encrypted notification upsert, removal, snapshot, and remote-operation path, detects a half-dead relay socket instead of queueing into it, and originates the post-authentication `SNH1`／`SNH2` heartbeat. It starts its foreground service from `BOOT_COMPLETED`, so a device restart no longer requires opening the app. OEM compatibility, the notification-permission fallback, and first-release product validation remain incomplete.

## What this is

SevenMirror shows Android notifications on a desktop browser. This app is the only
source: the browser never asks for notification access on the desktop, and what
leaves the phone is ciphertext addressed to one recipient. Notification content
and `PendingIntent` capabilities stay in process memory.

Two permissions drive everything. Notification access is how the app sees what the
system posts. The notification permission is what keeps the foreground service —
and with it the relay connection — alive, so revoking it stops mirroring until the
app surfaces the pending-permission entry on its home screen. Battery-optimization
exemption is offered as a fallback for the case where the foreground service loses
its foreground state; it is not required and does not affect power use.

To use it:

1. Install the APK from GitHub Releases, or build it locally (see below).
2. Open the app and finish onboarding, including the background-sync decision.
3. Join the workspace with a joining code the relay operator issues.
4. Pick which applications to mirror; ongoing notifications are excluded by default.
5. The relay operator sets the display name; the app shows it read-only.

The app reconnects on its own after a socket failure, and after a device restart it
restores the connection once the device is unlocked, without being opened.

## Requirements

- JDK 17
- Android SDK 37, which is the `compileSdk`; `targetSdk` is 35
- Android Studio or the included Gradle wrapper
- Minimum runtime: Android 10 / API 29

## Build

```sh
./gradlew verifyKotlinKaptAdvisoryGuard verifyVendoredProtocol test lint assembleDebug
```

On Windows PowerShell or Command Prompt, use `gradlew.bat`.

## Dependency integrity

All resolvable build, runtime, unit-test, instrumentation-test, and Kotlin
compiler-plugin configurations use Gradle strict dependency locking. AGP's
synthetic `*DependenciesMetadata` configurations are excluded because AGP
9.4／Gradle 9.6 do not expose persistable lock state for them; they duplicate
dependencies already covered by the real classpaths.

To update dependency versions intentionally, run:

```sh
./gradlew \
  :app:dependencies \
  :core-crypto:dependencies \
  :core-notification:dependencies \
  :core-protocol:dependencies \
  :core-transport:dependencies \
  writeReleaseRuntimeDependencyInventory \
  --write-locks
./gradlew verifyKotlinKaptAdvisoryGuard verifyVendoredProtocol test lint assembleDebug \
  --write-verification-metadata sha256
```

Review every lockfile and every new artifact checksum in
`gradle/verification-metadata.xml` before committing. Do not use lenient
verification or generate checksums in CI. CI verifies inventory stability and
rejects artifacts absent from the checked-in SHA-256 metadata. SHA-pinned OSV
Scanner v2.5.1 blocks known vulnerabilities in the exact release runtime
inventory. A separate supply-chain audit scans the complete artifact and
Gradle/plugin inventory in `verification-metadata.xml`; known upstream Android
build-tool findings remain visible there and are not misrepresented as APK
runtime dependencies. The remaining Kotlin Gradle Plugin advisory records and
the enforced no-KAPT reachability boundary are documented in
[`docs/kotlin-kapt-advisory-analysis.md`](docs/kotlin-kapt-advisory-analysis.md).

## Development CI flow

Every feature-branch push runs CI. The exact branch SHA must pass the required
`build` and `api29-secure-runtime` checks before it is fast-forwarded to `main`;
the resulting `main` SHA must pass the same checks before the topic branch is
removed. The API 29 emulator starts only after the build and dependency-integrity
job succeeds. These ordering rules reduce duplicate runner failures; they do not
relax any build, OSV, instrumentation, or release gate.

Gradle tasks named `connected*AndroidTest` depend on
`verifyConnectedTestsUseEmulators`. The guard rejects every attached physical
device before instrumentation starts because Android Gradle Plugin connected
tasks may uninstall the target package and erase its private app data. Run these
tasks only against disposable emulators. Physical-device product validation uses
release/debug APK installation and explicit user-flow checks, not Gradle
connected-test tasks.

## Sensitive local data

The API 29 instrumentation suite uses real Android Keystore-backed stores and
canary credentials to reject raw or encoded transport tokens and HPKE private
scalars in SharedPreferences, databases, app files, cache, own-process logcat,
and generated errors. Expected endpoint-local protocol state and remaining OS,
backup, crash, screenshot, and business-content boundaries are documented in
[`docs/SENSITIVE_DATA.md`](docs/SENSITIVE_DATA.md).

## Signing

Distributable debug and release APKs use the project's fixed Android signing
identity so later builds remain update-compatible. Local secret files are
ignored by Git, and GitHub Actions reconstructs the keystore from repository
secrets and verifies the certificate fingerprint. See
[`docs/SIGNING.md`](docs/SIGNING.md) for the canonical identity, backup
boundary, CI secret names, and recovery rules. Signed-APK provenance, offline
verification, distribution-channel trust and monotonic `versionCode` rollback
are documented in [`docs/release-provenance.md`](docs/release-provenance.md);
the pinned release Actions are reviewed in
[`docs/release-actions.md`](docs/release-actions.md).

## Modules

- `app`: Material 3 Compose onboarding, adaptive bottom-bar/navigation-rail layout with bounded wide-screen content, persisted explicit application selection with search and ordinary/system filtering, default exclusion of ongoing notifications, global silent-notification control, per-app content and ongoing-notification settings, a user-controlled low-priority foreground service for the persistent encrypted relay connection, a boot receiver that restores that connection after a device restart, battery-optimization exemption offered as an optional fallback, global and per-app remote-operation permissions, authority-verified read-only device presentation, user-facing connection recovery and privacy/settings surfaces, an application-private transport diagnostics ring, and a debug-only synthetic fixture entry; see [`docs/background-connection.md`](docs/background-connection.md) for the foreground-service boundary and [`docs/transport-diagnostics.md`](docs/transport-diagnostics.md) for the ring
- `core-notification`: `NotificationListenerService` integration, user-visible update deduplication, deterministic 200-item active-set selection with group-summary deduplication, approved-sender action dispatcher, and source-application remote-operation authorization enforced before local execution
- `core-protocol`: protocol models and generated code location
- `core-crypto`: authenticated HPKE, replay/operation ledgers, immutable approved-peer pins, Workspace Membership authority/certificate/roster verification, authority-signed read-only device directory and durable rollback floor, pre-execution result reservations, durable outbox/sequence allocation, and bounded encrypted result draining
- `core-transport`: strict code-gated registration, provisional ADR-005 membership register/prove/state HTTP client, Keystore-wrapped pending enrollment journal and transport credentials, recoverable proof/rotation state, authority-verified recoverable membership-to-transport promotion, process-start enrollment recovery before transport credential loading, Device Auth Frame v1, an authenticated OkHttp WebSocket boundary with ping-based half-dead socket detection and `SNH1`／`SNH2` origination, and a sixty-second stall check that keeps a scheduled reconnect behind every state that is not `ONLINE`
- `notification-fixture`: development-only third-party application for controlled notification lifecycle, action, reply, grouping, status, and media acceptance; it has an independent application ID and no dependency on SevenMirror modules, and is excluded from published artifacts

## Protocol

The server repository is the canonical protocol source. This repository vendors a fixed copy under `protocol/`: `protocol/UPSTREAM_REF` records the upstream revision, `protocol/PROTOCOL_VERSION` the version those assets are released under, and a `*_SHA256` file beside each asset pins its exact bytes. `verifyVendoredProtocol` fails the build when a copy drifts. The schema is at `0.1.0` and stays provisional — a version number is not a compatibility promise until protocol v1 is frozen.

## Security status

Debug builds may trust a CA explicitly installed by the device user so physical-device non-loopback HTTPS/WSS can be validated against a private development PKI. This exception is expressed through Android Network Security Configuration `debug-overrides`; non-debuggable release builds do not trust user-added CAs and continue to require a system-trusted server certificate. Cleartext remains denied outside the existing explicit loopback domains.

Transport Credential Rotation v1 stores current and at most one pending token as distinct Android Keystore AES-GCM ciphertexts bound to the same server/workspace/device/HPKE identity metadata. `prepared` and `attempted` are committed before the strict no-redirect HTTPS request. HTTP 200 does not promote. After process death or ambiguous response loss, attempted pending is retried exactly; pre-`SNO1` denial falls back to current, while only pending `SNO1` permits atomic re-wrapping and promotion. Raw tokens are absent from SharedPreferences and loaded working copies are cleared.

Relay Delivery v1 wraps selected-application notification upserts, removals, reconnect snapshots, and authenticated action-result envelopes as explicit durable submissions. After exact `SNO1`, Android resumes its exact workspace/device cursor; an inbound durable frame advances and cumulatively ACKs only after action/result-ACK reconciliation is durable. Snapshot-required high-water is persisted and never skipped automatically. Snapshot-required request/response recovery is enabled for authority-authorized recipients.

The listener maintains notification content and `PendingIntent` capabilities only in process memory. An unselected application's notification is retained only for local listener bookkeeping and never enters the mirror sink. Saving a changed selection assigns fresh revisions, emits upserts or removals as needed, and follows them with a new active-set snapshot barrier. Remote actions, replies, and clearing additionally require the existing default-off per-application authorization at the final side-effect boundary. Socket failures use jittered exponential retry from 1 to 60 seconds; persistent credential or identity failures remain `SECURITY_ERROR` and are not retried as network failures. A failure in local handling abandons the connection and schedules a reconnect instead of parking the device; only the three inbound paths that judge the peer's own bytes park it, and a sixty-second check re-arms a stalled connection whenever a connection owner exists without `ONLINE`. Cleartext transport is denied globally except explicit loopback development origins.

Two boundaries are worth stating explicitly. A remote clear is refused unless the notification is ongoing, because the system's `NotificationManagerService` only checks `FLAG_ONGOING_EVENT` when a listener cancels a single notification; the browser reports that refusal rather than waiting in silence. The application-private diagnostics ring records transport states and timings only — never notification content, credentials, or identities — and release builds write it too, because logcat alone proved too small to reconstruct a connection drop after the fact.

## License

Current revisions are licensed under [`GPL-3.0-only`](LICENSE). Commercial use is permitted subject to GPLv3. See [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md) for the exact non-retroactive MIT-to-GPL boundary; the boundary revision and its ancestors remain available under MIT.
