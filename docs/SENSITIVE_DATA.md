# Android sensitive-data inventory and canary audit

Status: **internal implementation evidence; not an independent privacy or security approval**

## Classification

### Secrets forbidden in app persistence and diagnostics

The following values may exist briefly in process memory but must not appear raw
or Base64-encoded in SharedPreferences, SQLite, app files, cache, routine
exceptions, or application logcat:

- current and pending transport authentication tokens;
- pending enrollment transport tokens;
- HPKE identity private scalars;
- Android Keystore AES wrapping keys;
- administrator pairing and credential-rotation codes after their immediate UI
  submission lifecycle.

Current and pending transport tokens, pending enrollment token/proof bytes, and
the HPKE private scalar are persisted only as AES-GCM ciphertext under distinct
Android Keystore aliases and domain-bound AAD. The Keystore wrapping keys are
non-exportable through the application API. HPKE execution still requires a
software-accessible scalar in process memory; Keystore wrapping does not claim
to eliminate that memory boundary.

### Sensitive endpoint-local state intentionally persisted

The Android endpoint must retain enough authenticated state to survive process
recreation and enforce replay, authorization, idempotency, and recovery. The
following are expected app-private plaintext or public protocol state, not
relay-visible business plaintext:

- canonical Server origin and workspace/device/key identifiers;
- HPKE and authority public keys, certificates, signed rosters, revocations,
  digests, epochs, roles, and public signatures;
- registration request identifiers, challenge encapsulation/ciphertext, and
  pending enrollment phase;
- replay tuples, notification IDs/revisions, relay delivery cursor/high-water,
  snapshot request IDs, operation idempotency keys, attempt counters, result
  digests, timestamps, and terminal result status;
- canonical `action.result` payloads retained by the operation ledger and result
  outbox until their bounded retention/acknowledgement lifecycle completes;
- app-owned synthetic test counters and status in Debug builds.

These values remain sensitive against local correlation and are protected by
Android app sandboxing. They are not described as secret merely because they are
not shown in the normal product UI.

### Business content

Notification title, body, source application label, action labels, media, and
reply text are used in process memory and Android system notification/action
boundaries. The Android implementation does not maintain a durable plaintext
notification mirror database. Reply text is passed to the exact source
`RemoteInput`; the durable operation/result state stores the canonical result,
not the reply text.

The Android OS, notification shade, source application, input method, device
backup/debug tooling, screenshots, crash capture, and a compromised endpoint are
separate trust boundaries. This inventory does not claim that content visible to
those components is encrypted from the device owner or OS.

## Runtime canary gate

`AndroidSensitiveDataCanaryInstrumentedTest` runs on the API 29 CI emulator. It
uses the real production stores to create:

- one Android Keystore-wrapped HPKE identity;
- one current and one pending transport token;
- one pending membership record containing the same canary token;
- one rejected credential replacement error.

While those records are live, the test searches each secret's raw bytes,
standard Base64 form, and unpadded Base64URL form in:

- `filesDir`;
- `cacheDir`;
- `noBackupFilesDir`;
- app-private `shared_prefs` files;
- app-private `databases` files, including any live SQLite side files visible in
  that directory;
- logcat restricted to the instrumentation target process;
- the generated rejection exception text.

Every match is blocking. The failure reports only the secret class and artifact
name, not the matched bytes. The test clears all dedicated stores and overwrites
its working secret arrays in `finally`.

`code_cache` is intentionally not classified as mutable application state: it
may contain compiled instrumentation bytecode and therefore the public canary
fixture itself. Release APK/source secret scanning is handled separately by the
repository Gitleaks gate. No general app-data path or keyword allowlist is used.

## Backup boundary

The production application manifest sets `android:allowBackup="false"`.
Release builds therefore do not opt app-private state into Android Auto Backup.
This setting does not erase existing OS/cloud backups made by older builds and
does not replace physical-device verification across supported OEM backup and
restore behavior.

## Remaining evidence

This automated slice does not cover:

- system-wide logcat available only to privileged tooling;
- native/JVM heap snapshots or guaranteed private-scalar zeroization;
- crash tombstones, ANR traces, bugreports, screenshots, screen recording, or
  keyboard history;
- OEM backup transports and device-to-device migration on two physical devices;
- exported Debug acceptance artifacts and operator support bundles;
- a full business-content canary through notification extraction, reply, media,
  process death, and cleanup.

Those items remain release-review work under `SR-006`, `SR-008`, and `SR-013`.
