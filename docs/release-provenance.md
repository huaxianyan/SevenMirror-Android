# Android release provenance and rollback

Status: **protected release-candidate baseline; independent review and distribution-channel evidence remain required**

## Release authority

The release job targets the GitHub `release-candidate` environment. Only
protected branches may deploy to it, and an explicit repository-administrator
approval is required before signing secrets, job permissions, or provenance
steps become available. The `main` branch separately requires a pull request,
Android build and API 29 runtime checks, blocks force-push and deletion, and
applies those rules to administrators.

Only `huaxianyan` currently has repository access. The environment gate is
therefore a deliberate second action by the same identity, not independent
approval. Before production release, add a second trusted reviewer, require an
approval from someone other than the last pusher, enable environment self-review
prevention, and verify that signing-secret access remains limited to the gated
job.

## Canonical public release identity

`release/release-identity.properties` is the single checked-in definition of:

- application ID;
- `versionCode` and `versionName`;
- expected signing-certificate SHA-256 and SHA-1.

Gradle reads the application/version values directly from this file. The release
artifact verifier reads the same file for APK application, version and signer
checks. Changing it is a release identity change, not routine build metadata.

The signing certificate fingerprints are public. The JKS, store password, key
password and repository secret values remain confidential and must never enter
manifests, attestations, logs or workflow artifacts.

## Release artifact set

A release set contains exactly:

- `sevenmirror-android-<versionName>-<versionCode>.apk`;
- `release-manifest.json`;
- `SHA256SUMS`.

`scripts/build_release_artifacts.py` invokes Android SDK `apksigner` and
`apkanalyzer` against the APK itself. It requires one signer with the canonical
certificate, then extracts and binds application ID, version code, version name,
minimum SDK and target SDK. The manifest also binds the exact 40-character source
revision plus APK name, size and SHA-256.

Verify a downloaded set against an approved source checkout and installed Android
SDK tools:

```sh
python3 scripts/build_release_artifacts.py \
  --output ./sevenmirror-android-release \
  --revision <40-character-commit> \
  --apksigner "$ANDROID_HOME/build-tools/<version>/apksigner" \
  --apkanalyzer "$ANDROID_HOME/cmdline-tools/latest/bin/apkanalyzer" \
  --verify-only
```

The verifier rejects missing/extra output, symlinks, a changed APK digest/size,
source mismatch, multiple or wrong signers, and application/version metadata that
differs from the canonical release identity.

Signed APK bytes are not claimed to be reproducible. ZIP alignment, Android build
tools and signing can affect bytes. The accepted release identity is the exact
attested APK digest, verified certificate and embedded application/version
metadata—not an assumption that a second build will have the same hash.

## OSV query evidence

Before signing material is reconstructed, the workflow regenerates and verifies
the 90-package release-runtime inventory, then runs checksum-pinned OSV Scanner
once against that inventory and the complete 473-package Gradle artifact/plugin
inventory. Runtime findings stop the release job. Build-tool findings remain
visible in a separately attested three-file evidence set and require disposition
before production approval; they are not mislabeled as APK runtime. Audited
resolution pins have reduced the build-tool baseline from 21 affected packages／
86 records to 5／7 without scanner ignores. The residual Android Gradle Plugin
and Kotlin toolchain findings remain explicitly open.

The evidence binds the exact two input hashes, normalized package inventories,
scanner build identity, OSV API, source revision, command completion time and
complete raw report. The provider does not expose database publication time, so
that field remains explicitly null. See
[`vulnerability-evidence.md`](vulnerability-evidence.md) for the verifier and
scope boundary.

## GitHub provenance

`.github/workflows/release-artifacts.yml` runs protocol verification, tests, lint
and OSV evidence generation before reconstructing the JKS in the ephemeral runner
temporary directory. All four signing secrets are mandatory. It builds only the
release APK, verifies its public identity, then passes the APK, manifest and
checksum to the official
`actions/attest` action pinned at
`1e69f48acb82d1966a394da916b4c1698aa569d6` (`v4.2.2`, GitHub-verified commit).
GitHub OIDC and a short-lived Sigstore certificate produce SLSA provenance; no
additional long-lived provenance key is introduced. Reconstructed signing
material is removed in an `always()` cleanup step.

Verify all three downloaded release subjects, then separately verify every OSV
evidence subject:

```sh
for artifact in sevenmirror-android-release/* sevenmirror-android-osv-evidence/*; do
  gh attestation verify "$artifact" \
    --repo huaxianyan/SevenMirror-Android
done
```

A tag must equal `v<versionName>` and a `-dev` version cannot be tag-released.
Manual dispatch may create release-candidate evidence without claiming a
production release. GitHub artifact retention is 30 days; durable hosting remains
undecided.

GitHub provenance does not prove control of a future app-store account, store
processing, staged rollout, served APK/App Bundle, or Play App Signing identity.
Those require separate channel evidence. Introducing an upload key or Play App
Signing must explicitly document whether the existing project certificate stays
the app-signing identity; it must not silently replace this identity.

## Rollback rule

Android package updates require the same application ID, compatible signing
identity and a strictly higher `versionCode`. A published build therefore cannot
normally be rolled back by reinstalling its older APK over user data.

Release rollback means selecting an exact approved prior source revision,
applying only reviewed compatibility/fix changes, assigning a new higher
`versionCode`, rebuilding with the same signing identity and producing a new
attested APK digest. The decision must address local database/protocol
compatibility and whether users need an explicit data recovery path.

Do not lower `versionCode`, silently generate another key, change application ID,
or select source by mutable tag, filename, workflow status or “last known good”
label. A signing mismatch is a release stop, not a reason to uninstall users'
existing app or discard data.

## Remaining key-recovery evidence

The current secondary signing-key copy is on the same physical disk as the active
copy. It does not satisfy independent durable encrypted backup. Before release,
an operator must place and verify a copy on separately durable encrypted media,
perform a non-destructive certificate-recovery check, document custody and
recovery access, and retain no passwords in the evidence. This workflow does not
close `SR-009`.
