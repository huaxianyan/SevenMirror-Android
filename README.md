# Notification Mirroring Android

Android source device for private, end-to-end encrypted notification mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SevenMirror-Android>

> Status: local notification actions, authenticated HPKE, replay/idempotency recovery, strict registration, recoverable Keystore-wrapped transport credential rotation, and authenticated WebSocket transport are validated. The app now connects the user's explicit application selection to the encrypted notification upsert, removal, snapshot, and remote-operation path. Broader real-device compatibility and first-release product validation remain incomplete.

## Requirements

- JDK 17
- Android SDK 35
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

Feature-branch pushes do not automatically run CI. Before opening a pull request,
push the branch and explicitly dispatch the `CI` workflow against that branch:

```sh
gh workflow run CI --ref <branch>
```

Wait for that run before opening the pull request. This preflight resolves Linux
and platform-specific Gradle artifacts that a Windows checkout cannot discover;
if dependency verification fails, add only checksums independently downloaded
from the named upstream repository, amend the branch, and dispatch once more.
Do not open a pull request merely to use required checks as a dependency metadata
probe.

Pull requests run one required-check set. A newer commit cancels an obsolete run,
and the API 29 emulator starts only after the build and dependency-integrity job
succeeds. Pushes to `main` still run the complete required-check set. These
ordering rules reduce duplicate runner failures; they do not relax any build,
OSV, instrumentation, or release gate.

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

- `app`: Material 3 Compose onboarding, adaptive bottom-bar/navigation-rail layout with bounded wide-screen content, persisted explicit application selection with search and ordinary/system filtering, default exclusion of ongoing notifications, global silent-notification control, per-app content and ongoing-notification settings, global and per-app remote-operation permissions, authority-verified read-only device presentation, user-facing connection recovery and privacy/settings surfaces, debug-only synthetic fixture entry, and process-lifetime authenticated transport/action coordinator
- `core-notification`: `NotificationListenerService` integration, approved-sender action dispatcher, and source-application remote-operation authorization enforced before local execution
- `core-protocol`: protocol models and generated code location
- `core-crypto`: authenticated HPKE, replay/operation ledgers, immutable approved-peer pins, Workspace Membership authority/certificate/roster verification, authority-signed read-only device directory and durable rollback floor, pre-execution result reservations, durable outbox/sequence allocation, and bounded encrypted result draining
- `core-transport`: strict code-gated registration, provisional ADR-005 membership register/prove/state HTTP client, Keystore-wrapped pending enrollment journal and transport credentials, recoverable proof/rotation state, authority-verified recoverable membership-to-transport promotion, process-start enrollment recovery before transport credential loading, Device Auth Frame v1, and authenticated OkHttp WebSocket boundary

## Protocol

The server repository is the canonical protocol source. This repository vendors a fixed copy under `protocol/vendor` with an upstream reference and SHA-256. The current `0.1.0-dev` schema is unreleased and provisional.

## Security status

Debug builds may trust a CA explicitly installed by the device user so physical-device non-loopback HTTPS/WSS can be validated against a private development PKI. This exception is expressed through Android Network Security Configuration `debug-overrides`; non-debuggable release builds do not trust user-added CAs and continue to require a system-trusted server certificate. Cleartext remains denied outside the existing explicit loopback domains.

Transport Credential Rotation v1 stores current and at most one pending token as distinct Android Keystore AES-GCM ciphertexts bound to the same server/workspace/device/HPKE identity metadata. `prepared` and `attempted` are committed before the strict no-redirect HTTPS request. HTTP 200 does not promote. After process death or ambiguous response loss, attempted pending is retried exactly; pre-`SNO1` denial falls back to current, while only pending `SNO1` permits atomic re-wrapping and promotion. Raw tokens are absent from SharedPreferences and loaded working copies are cleared.

Relay Delivery v1 wraps selected-application notification upserts, removals, reconnect snapshots, and authenticated action-result envelopes as explicit durable submissions. After exact `SNO1`, Android resumes its exact workspace/device cursor; an inbound durable frame advances and cumulatively ACKs only after action/result-ACK reconciliation is durable. Snapshot-required high-water is persisted and never skipped automatically. Snapshot-required request/response recovery is enabled for authority-authorized recipients.

The listener maintains notification content and `PendingIntent` capabilities only in process memory. An unselected application's notification is retained only for local listener bookkeeping and never enters the mirror sink. Saving a changed selection assigns fresh revisions, emits upserts or removals as needed, and follows them with a new active-set snapshot barrier. Remote actions, replies, and clearing additionally require the existing default-off per-application authorization at the final side-effect boundary. Socket failures use jittered exponential retry from 1 to 60 seconds; persistent credential or identity failures remain `SECURITY_ERROR` and are not retried as network failures. Cleartext transport is denied globally except explicit loopback development origins.

## License

Current revisions are licensed under [`GPL-3.0-only`](LICENSE). Commercial use is permitted subject to GPLv3. See [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md) for the exact non-retroactive MIT-to-GPL boundary; the boundary revision and its ancestors remain available under MIT.
