# Android signing identity

All distributable debug and release APKs use one fixed project-owned signing
identity. Losing this identity prevents future APK updates from being installed
over existing installations. Disclosure allows an attacker to sign malicious
updates, so the keystore and passwords must never be committed or logged.

## Certificate identity

The key alias remains `syncnotifications-android`; the current key is RSA 4096
with a SHA256withRSA certificate. Canonical application/version values and
certificate SHA-1／SHA-256 fingerprints are defined once in
[`release/release-identity.properties`](../release/release-identity.properties).
Gradle and the release verifier both consume that file.

The certificate fingerprints and alias are public metadata. Passwords and the
keystore are secrets.

## Local storage

The active local copy is stored in the ignored directory:

```text
.signing/syncnotifications-android.jks
.signing/signing.properties
```

A second local backup was created at:

```text
C:\Users\7inaWork-Windows\SyncNotifications-Android-Signing-Backup
```

Copy the backup directory to encrypted offline/removable storage. Two copies on
the same physical disk do not protect against disk loss or ransomware.

Gradle loads `.signing/signing.properties` automatically. If all four values are
present, both `debug` and `release` use the fixed identity. This makes locally
built debug APKs update-compatible with project release APKs.

## GitHub Actions secrets

The `SyncNotifications-Android` repository uses these Actions secrets:

- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_SIGNING_STORE_PASSWORD`
- `ANDROID_SIGNING_KEY_ALIAS`
- `ANDROID_SIGNING_KEY_PASSWORD`

Push builds fail closed if the secrets are unavailable. Pull requests that
cannot access repository secrets may build a temporary debug-key APK for tests,
but that APK is not a distributable project build. CI verifies the release APK
against the canonical certificate and embedded application/version identity,
then uploads both APKs as a short-lived workflow artifact. The separate release
workflow attests only the fixed-signed release APK and its public manifest; see
[`release-provenance.md`](release-provenance.md).

## Existing debug-key installations

An APK previously installed with Android's generated debug key cannot be
updated directly to this identity. It must be uninstalled once, which clears
its app data and notification-listener grant, and then the fixed-signed APK must
be installed. Every later build signed by this identity can update it with
`adb install -r` as long as `versionCode` does not decrease.

## Rotation and recovery

Do not generate a replacement key when loading fails. Stop the release and
restore the keystore and credentials from the encrypted backup. Signing-key
rotation requires a separately reviewed Android-supported upgrade procedure;
it must never happen silently in CI or local builds.

The current secondary copy is still on the same physical disk and is not an
independently durable backup. `SR-009` remains open until an encrypted copy on
separate durable media is retrieved and its public certificate is verified
without exposing passwords or private-key material.
