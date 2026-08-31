#!/usr/bin/env python3
"""Build metadata and offline verification for a signed SevenMirror Android APK."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

REPOSITORY = "https://github.com/huaxianyan/SevenMirror-Android"
SCHEMA = "sevenmirror-android-release-v1"
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
APPLICATION_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
VERSION_NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
IDENTITY_KEYS = {
    "applicationId",
    "versionCode",
    "versionName",
    "signingCertificateSha256",
    "signingCertificateSha1",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--apksigner", required=True, type=Path)
    parser.add_argument("--apkanalyzer", required=True, type=Path)
    parser.add_argument(
        "--identity", type=Path,
        default=Path(__file__).resolve().parents[1] / "release" / "release-identity.properties",
    )
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_identity(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("release identity must be a regular file")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values or not key or not value:
            raise RuntimeError("release identity properties are invalid")
        values[key] = value
    if set(values) != IDENTITY_KEYS:
        raise RuntimeError("release identity property set is invalid")
    if not APPLICATION_ID.fullmatch(values["applicationId"]):
        raise RuntimeError("release application ID is invalid")
    if not values["versionCode"].isdigit() or int(values["versionCode"]) < 1:
        raise RuntimeError("release versionCode is invalid")
    if not VERSION_NAME.fullmatch(values["versionName"]):
        raise RuntimeError("release versionName is invalid")
    if not DIGEST.fullmatch(values["signingCertificateSha256"]):
        raise RuntimeError("release signing certificate SHA-256 is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", values["signingCertificateSha1"]):
        raise RuntimeError("release signing certificate SHA-1 is invalid")
    return values


def run_tool(arguments: list[str]) -> str:
    completed = subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout


def inspect_apk(
    apk: Path, apksigner: Path, apkanalyzer: Path, identity: dict[str, str],
) -> dict[str, object]:
    if not apk.is_file() or apk.is_symlink():
        raise RuntimeError("release APK must be a regular file")
    signer_output = run_tool([
        str(apksigner), "verify", "--verbose", "--print-certs", str(apk),
    ])
    certificate_matches = re.findall(
        r"Signer #(\d+) certificate SHA-256 digest: ([0-9a-fA-F]{64})",
        signer_output,
    )
    if certificate_matches != [("1", identity["signingCertificateSha256"])]:
        normalized = [(number, digest.lower()) for number, digest in certificate_matches]
        if normalized != [("1", identity["signingCertificateSha256"])]:
            raise RuntimeError("APK signer certificate identity is invalid")

    def manifest_value(command: str) -> str:
        return run_tool([str(apkanalyzer), "manifest", command, str(apk)]).strip()

    application_id = manifest_value("application-id")
    version_code = manifest_value("version-code")
    version_name = manifest_value("version-name")
    min_sdk = manifest_value("min-sdk")
    target_sdk = manifest_value("target-sdk")
    expected = (
        identity["applicationId"], identity["versionCode"], identity["versionName"],
    )
    if (application_id, version_code, version_name) != expected:
        raise RuntimeError("APK application or version identity is invalid")
    if not min_sdk.isdigit() or not target_sdk.isdigit():
        raise RuntimeError("APK SDK metadata is invalid")
    return {
        "application_id": application_id,
        "version_code": int(version_code),
        "version_name": version_name,
        "min_sdk": int(min_sdk),
        "target_sdk": int(target_sdk),
        "signing_certificate_sha256": identity["signingCertificateSha256"],
        "signer_count": 1,
    }


def build(
    apk: Path,
    output: Path,
    revision: str,
    apksigner: Path,
    apkanalyzer: Path,
    identity_path: Path,
) -> None:
    if not REVISION.fullmatch(revision):
        raise RuntimeError("release revision must be a canonical 40-character commit")
    if output.exists() or output.is_symlink():
        raise RuntimeError("release output must not already exist")
    identity = read_identity(identity_path)
    apk_metadata = inspect_apk(apk, apksigner, apkanalyzer, identity)
    output.mkdir(mode=0o700)
    apk_name = (
        f"sevenmirror-android-{apk_metadata['version_name']}-"
        f"{apk_metadata['version_code']}.apk"
    )
    destination = output / apk_name
    shutil.copyfile(apk, destination)
    archive = {
        "name": apk_name,
        "sha256": sha256(destination),
        "size": destination.stat().st_size,
    }
    manifest = {
        "schema": SCHEMA,
        "source_repository": REPOSITORY,
        "source_revision": revision,
        "apk": archive,
        **apk_metadata,
    }
    (output / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    (output / "SHA256SUMS").write_text(
        f"{archive['sha256']}  {apk_name}\n", encoding="ascii",
    )


def verify(
    output: Path,
    revision: str,
    apksigner: Path,
    apkanalyzer: Path,
    identity_path: Path,
) -> None:
    if not REVISION.fullmatch(revision):
        raise RuntimeError("expected revision must be a canonical commit")
    if not output.is_dir() or output.is_symlink():
        raise RuntimeError("release output must be a non-symlink directory")
    try:
        manifest = json.loads(
            (output / "release-manifest.json").read_text(encoding="utf-8"),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("release manifest is invalid") from error
    if manifest.get("schema") != SCHEMA or \
            manifest.get("source_repository") != REPOSITORY or \
            manifest.get("source_revision") != revision:
        raise RuntimeError("release manifest source binding is invalid")
    apk_record = manifest.get("apk")
    if not isinstance(apk_record, dict):
        raise RuntimeError("release APK record is invalid")
    identity = read_identity(identity_path)
    expected_name = (
        f"sevenmirror-android-{identity['versionName']}-{identity['versionCode']}.apk"
    )
    expected_entries = {expected_name, "release-manifest.json", "SHA256SUMS"}
    entries = list(output.iterdir())
    if {entry.name for entry in entries} != expected_entries or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise RuntimeError("release output has missing, extra, or unsafe entries")
    apk = output / expected_name
    digest = apk_record.get("sha256")
    size = apk_record.get("size")
    if apk_record.get("name") != expected_name or not isinstance(digest, str) or \
            not DIGEST.fullmatch(digest) or not isinstance(size, int) or size < 1 or \
            apk.stat().st_size != size or sha256(apk) != digest:
        raise RuntimeError("release APK does not match its manifest")
    metadata = inspect_apk(apk, apksigner, apkanalyzer, identity)
    for key, value in metadata.items():
        if manifest.get(key) != value:
            raise RuntimeError(f"release APK metadata {key} does not match its manifest")
    if (output / "SHA256SUMS").read_text(encoding="ascii") != \
            f"{digest}  {expected_name}\n":
        raise RuntimeError("release checksum does not match the manifest")


def main() -> None:
    args = parse_args()
    output = args.output.resolve()
    if not args.verify_only:
        if args.apk is None:
            raise RuntimeError("--apk is required for building")
        build(
            args.apk.resolve(), output, args.revision, args.apksigner.resolve(),
            args.apkanalyzer.resolve(), args.identity.resolve(),
        )
    verify(
        output, args.revision, args.apksigner.resolve(), args.apkanalyzer.resolve(),
        args.identity.resolve(),
    )
    print("SevenMirror Android release artifact set verified.")


if __name__ == "__main__":
    main()
