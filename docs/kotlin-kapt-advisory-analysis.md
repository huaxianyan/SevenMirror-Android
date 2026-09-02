# Kotlin KAPT cache advisory analysis

This document records the project-specific analysis for
`GHSA-r937-wjx7-w2jp`／`CVE-2026-53914`. It is not a vulnerability exception or
an independent risk acceptance.

## Advisory and fixed version

The reviewed advisory describes code execution through unsafe Java
deserialization of Kotlin build-cache metadata and assigns CVSS 3.1 score 6.7
(`AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:L`). Its affected Maven package is
`org.jetbrains.kotlin:kotlin-gradle-plugin`; the first fixed ecosystem version
is `2.4.20-Beta1`.

The linked upstream fix is Kotlin commit
[`bf51df6`](https://github.com/JetBrains/kotlin/commit/bf51df665b458fda7c3eaf436c4d88dc119d7ec6),
whose subject is "KAPT: Deserialize only a handful of classes from KAPT
incremental cache". The patch replaces unrestricted `ObjectInputStream` reads
of KAPT's `apt-cache.bin` and `java-cache.bin` with an allow-listed input
stream. The affected execution path is therefore KAPT incremental-cache
loading, not ordinary Kotlin compilation or the Compose compiler by itself.

As observed on 2026-09-02, Kotlin's official
[release list](https://kotlinlang.org/docs/releases.html) identifies `2.4.10`
as the latest stable release. The official
[EAP page](https://kotlinlang.org/docs/whatsnew-eap.html) identifies
`2.4.20-RC3` as a pre-release. SevenMirror does not replace stable Android build
tooling with a beta or release candidate solely to reduce a scanner count.

## Exact SevenMirror exposure

The complete Gradle verification inventory intentionally reports two affected
package versions:

- `2.2.10` contributes only `kotlin-gradle-plugin-2.2.10.module` to
  `gradle/verification-metadata.xml`. Gradle's resolved root build classpath
  records `kotlin-gradle-plugin:2.2.10 -> 2.3.20`; no `2.2.10` plugin JAR is
  verified or executed.
- `2.3.20` contributes the executable
  `kotlin-gradle-plugin-2.3.20-gradle813.jar`. It is selected because the stable
  Compose compiler plugin is `2.3.20` and AGP's `2.2.10` request is resolved to
  the same version.

No project applies the KAPT plugin, no project declares a `kapt` dependency,
and the configured task graph contains no task whose name begins with `kapt`.
The vulnerable KAPT cache-loading path is therefore not reachable in the
current build. The package finding remains visible because package-level OSV
evidence cannot encode that project-specific reachability fact.

## Enforced guard

`verifyKotlinKaptAdvisoryGuard` fails the build if any of these conditions
changes:

1. Gradle build caching is enabled, including by a command-line override.
2. `kapt.incremental.apt` is not explicitly `false`.
3. Any configured project exposes a task whose name begins with `kapt`.

CI and the protected release workflow execute the guard before compilation and
signing. `org.gradle.caching=false` and `kapt.incremental.apt=false` are
additional defenses; absence of KAPT is the project-specific reason the patched
cache reader is unreachable.

## Disposition

Both OSV records remain open. This analysis does not add a scanner ignore, does
not delete complete inventory metadata and does not enter an exception in the
canonical vulnerability-exception registry. Resolution requires either:

- a compatible stable Kotlin／Compose／AGP toolchain containing the upstream
  fix, followed by regenerated locks, verification metadata and protected OSV
  evidence; or
- an exact, time-bounded disposition approved by identities that satisfy the
  project's independent owner／approver rule.

Until one of those conditions is met, enabling KAPT or Gradle build caching is a
release-blocking configuration change.
