# Android release GitHub Actions review

Status: **internal identity and permission review; not independent approval**

The release workflow uses official GitHub Actions pinned to immutable commits
that GitHub reports as valid verified signatures.

## `actions/attest`

- Commit: `1e69f48acb82d1966a394da916b4c1698aa569d6`
- Release: `v4.2.2`
- Input: only the verified signed APK, public release manifest and checksum
- Purpose: subject hashing, GitHub OIDC/Sigstore signing and attestation upload
- Permissions: `contents: read`, `id-token: write`, `attestations: write`,
  `artifact-metadata: write`
- Long-lived provenance key: none

The signing JKS and passwords are inputs only to Gradle. They are not action
inputs and are outside the attested artifact directory.

## `actions/upload-artifact`

- Commit: `b7c566a772e6b6bfb58ed0dc250532a479d7789f`
- Release: `v6.0.0`
- Input: the already verified and attested three-file release set
- Missing-file behavior: fail closed
- Retention: 30 days

The upload's generated container ZIP and artifact name are transport metadata,
not the APK release identity. Consumers verify each inner subject and the
source-bound manifest.

## Secret boundary and remaining review

The job requires all four existing Android signing secrets, reconstructs the JKS
with mode `0600` under the ephemeral runner temporary directory, and removes that
directory in an `always()` step. Runner compromise, GitHub repository
administration, secret rotation/recovery, workflow approval rules and terminal
retention remain trust boundaries.

Before production release, recheck both Action commits and source, configure an
approved release environment or equivalent protected release authority, review
who can dispatch/tag the workflow, and complete the independently durable signing
key backup. Future app-store upload tooling and credentials require a separate
least-privilege review.
