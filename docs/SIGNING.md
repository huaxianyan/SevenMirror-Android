# Android signing identity

All distributable debug and release APKs use one fixed project-owned signing
identity. Losing this identity prevents future APK updates from being installed
over existing installations. Disclosure allows an attacker to sign malicious
updates, so the keystore and passwords must never be committed or logged.

## Certificate identity

- Key alias: `syncnotifications-android`
- Key algorithm: RSA 4096
- Signature algorithm: SHA256withRSA
- Certificate SHA-1:
  `CC:23:AF:81:71:05:B8:FE:F4:63:83:D7:5D:99:0A:3B:6D:32:88:B3`
- Certificate SHA-256:
  `3E:42:2A:F3:D3:0A:5A:40:83:B4:8F:7C:A5:B1:31:1B:E2:AF:8F:CF:61:87:FD:02:A8:54:1D:30:52:F2:8F:70`

These certificate fingerprints and the alias are public metadata. Passwords and
the keystore are secrets.

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
against the expected SHA-256 certificate fingerprint and uploads both APKs as a
short-lived workflow artifact.

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
