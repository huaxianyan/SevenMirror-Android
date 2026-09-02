#!/usr/bin/env python3
"""Generate and verify bounded Android OSV query evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOL_CONFIG = ROOT / "security" / "osv-scanner.json"
INPUTS = (
    ("release-runtime", ROOT / "gradle" / "release-runtime" / "gradle.lockfile"),
    ("build-tool", ROOT / "gradle" / "verification-metadata.xml"),
)
MAX_REPORT_BYTES = 4 * 1024 * 1024
REVISION = re.compile(r"^[0-9a-f]{40}$")
SCHEMA = "sevenmirror-android-osv-evidence-v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--scanner", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path, description: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{description} is invalid JSON") from error


def tool_config(path: Path = TOOL_CONFIG) -> dict[str, str]:
    value = read_json(path, "OSV Scanner tool configuration")
    expected_keys = {
        "commit", "linux_amd64_sha256", "osv_scalibr_version", "provider_api",
        "schema", "version",
    }
    if not isinstance(value, dict) or set(value) != expected_keys or \
            value.get("schema") != "sevenmirror-osv-scanner-tool-v1":
        raise RuntimeError("OSV Scanner tool configuration shape is invalid")
    for key in expected_keys - {"schema"}:
        if not isinstance(value.get(key), str) or not value[key]:
            raise RuntimeError(f"OSV Scanner tool configuration field {key} is invalid")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"]) or \
            not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["osv_scalibr_version"]) or \
            not re.fullmatch(r"[0-9a-f]{40}", value["commit"]) or \
            not re.fullmatch(r"[0-9a-f]{64}", value["linux_amd64_sha256"]) or \
            value["provider_api"] != "https://api.osv.dev/v1/querybatch":
        raise RuntimeError("OSV Scanner tool configuration identity is invalid")
    return value  # type: ignore[return-value]


def parse_scanner_version(output: str, config: dict[str, str]) -> None:
    expected = (
        f"osv-scanner version: {config['version']}\n"
        f"osv-scalibr version: {config['osv_scalibr_version']}\n"
        f"commit: {config['commit']}\n"
    )
    if not output.startswith(expected) or "\nbuilt at: " not in output or not output.endswith("Z\n"):
        raise RuntimeError("unexpected OSV Scanner build identity")


def canonical_source_path(value: object) -> str:
    if not isinstance(value, str):
        raise RuntimeError("OSV result source path is invalid")
    normalized = value.replace("\\", "/")
    matches = [
        path.relative_to(ROOT).as_posix()
        for _, path in INPUTS
        if normalized == path.relative_to(ROOT).as_posix()
        or normalized.endswith("/" + path.relative_to(ROOT).as_posix())
    ]
    if len(matches) != 1:
        raise RuntimeError("OSV result source is outside the two approved inventories")
    return matches[0]


def normalize_report(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"results", "experimental_config"} or \
            not isinstance(value.get("results"), list):
        raise RuntimeError("OSV report shape is invalid")
    by_path: dict[str, dict[str, object]] = {}
    for result in value["results"]:
        if not isinstance(result, dict) or set(result) != {"source", "packages"} or \
                not isinstance(result.get("source"), dict) or \
                not isinstance(result.get("packages"), list):
            raise RuntimeError("OSV result shape is invalid")
        source = result["source"]
        if set(source) != {"path", "type"} or source.get("type") != "lockfile":
            raise RuntimeError("OSV result source type is invalid")
        path = canonical_source_path(source.get("path"))
        if path in by_path:
            raise RuntimeError("OSV report contains a duplicate inventory result")
        normalized_result = dict(result)
        normalized_result["source"] = {"path": path, "type": "lockfile"}
        by_path[path] = normalized_result
    expected_paths = [path.relative_to(ROOT).as_posix() for _, path in INPUTS]
    if set(by_path) != set(expected_paths):
        raise RuntimeError("OSV report is missing an approved inventory result")
    return {
        "results": [by_path[path] for path in expected_paths],
        "experimental_config": value["experimental_config"],
    }


def summarize_result(result: object, scope: str, input_path: Path) -> dict[str, object]:
    if not isinstance(result, dict) or not isinstance(result.get("packages"), list):
        raise RuntimeError("OSV result packages are invalid")
    inventory: list[str] = []
    affected_packages = 0
    finding_count = 0
    vulnerability_ids: set[str] = set()
    for item in result["packages"]:
        if not isinstance(item, dict) or set(item) - {"package", "vulnerabilities", "groups"} or \
                not isinstance(item.get("package"), dict):
            raise RuntimeError("OSV package record shape is invalid")
        package = item["package"]
        name = package.get("name")
        version = package.get("version")
        ecosystem = package.get("ecosystem")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version or \
                ecosystem != "Maven":
            raise RuntimeError("OSV package identity is invalid")
        inventory.append(f"Maven\0{name}\0{version}")
        vulnerabilities = item.get("vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise RuntimeError("OSV package vulnerabilities are invalid")
        if vulnerabilities:
            affected_packages += 1
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str) or \
                    not vulnerability["id"]:
                raise RuntimeError("OSV vulnerability identity is invalid")
            finding_count += 1
            vulnerability_ids.add(vulnerability["id"])
    if inventory != sorted(set(inventory)):
        raise RuntimeError("OSV package inventory must be unique and sorted")
    return {
        "affected_package_count": affected_packages,
        "finding_count": finding_count,
        "input": input_path.relative_to(ROOT).as_posix(),
        "input_sha256": sha256_file(input_path),
        "inventory_sha256": sha256_bytes(("\n".join(inventory) + "\n").encode("utf-8")),
        "package_count": len(inventory),
        "scope": scope,
        "vulnerability_ids": sorted(vulnerability_ids),
    }


def report_summaries(report: dict[str, object]) -> list[dict[str, object]]:
    results = report["results"]
    if not isinstance(results, list) or len(results) != len(INPUTS):
        raise RuntimeError("OSV report inventory count is invalid")
    return [
        summarize_result(result, scope, path)
        for result, (scope, path) in zip(results, INPUTS, strict=True)
    ]


def build(output: Path, revision: str, scanner: Path) -> None:
    if output.exists() or output.is_symlink():
        raise RuntimeError("OSV evidence output must not already exist")
    if not scanner.is_file() or scanner.is_symlink():
        raise RuntimeError("OSV Scanner must be a regular file")
    config = tool_config()
    version = subprocess.run(
        [str(scanner), "--version"], check=True, capture_output=True, text=True,
    ).stdout
    parse_scanner_version(version, config)
    for _, input_path in INPUTS:
        if not input_path.is_file() or input_path.is_symlink():
            raise RuntimeError("OSV inventory input must be a regular file")
    with tempfile.TemporaryDirectory() as temporary:
        raw_path = Path(temporary) / "osv-report.json"
        command = [str(scanner), "scan", "source"]
        command.extend(f"--lockfile={path}" for _, path in INPUTS)
        command.extend([
            "--no-resolve", "--format=json", "--all-packages",
            f"--output-file={raw_path}",
        ])
        completed = subprocess.run(command, check=False)
        if completed.returncode not in {0, 1}:
            raise RuntimeError(f"OSV Scanner failed with exit code {completed.returncode}")
        if not raw_path.is_file() or raw_path.stat().st_size > MAX_REPORT_BYTES:
            raise RuntimeError("OSV Scanner report is missing or exceeds the evidence bound")
        report = normalize_report(read_json(raw_path, "OSV Scanner report"))
    summaries = report_summaries(report)
    if summaries[0]["finding_count"] != 0:
        raise RuntimeError("Android release runtime inventory has OSV findings")
    query_completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z",
    )
    output.mkdir(mode=0o700)
    report_content = canonical_json(report)
    (output / "osv-report.json").write_bytes(report_content)
    manifest = {
        "database_last_modified": None,
        "provider_api": config["provider_api"],
        "query_completed_at": query_completed_at,
        "report": "osv-report.json",
        "report_sha256": sha256_bytes(report_content),
        "scans": summaries,
        "schema": SCHEMA,
        "source_revision": revision,
        "timestamp_semantics": "osv-scanner-command-completed-at",
        "tool_config_sha256": sha256_file(TOOL_CONFIG),
        "tool_identity": {
            "commit": config["commit"],
            "osv_scalibr_version": config["osv_scalibr_version"],
            "version": config["version"],
        },
    }
    (output / "android-osv-evidence.json").write_bytes(canonical_json(manifest))
    names = ("android-osv-evidence.json", "osv-report.json")
    (output / "SHA256SUMS").write_text(
        "".join(f"{sha256_file(output / name)}  {name}\n" for name in names),
        encoding="ascii",
    )


def verify(output: Path, revision: str) -> None:
    if not output.is_dir() or output.is_symlink():
        raise RuntimeError("OSV evidence must be a non-symlink directory")
    manifest = read_json(output / "android-osv-evidence.json", "Android OSV evidence")
    if not isinstance(manifest, dict) or set(manifest) != {
        "database_last_modified", "provider_api", "query_completed_at", "report",
        "report_sha256", "scans", "schema", "source_revision", "timestamp_semantics",
        "tool_config_sha256", "tool_identity",
    } or manifest.get("schema") != SCHEMA or manifest.get("source_revision") != revision or \
            manifest.get("database_last_modified") is not None or \
            manifest.get("timestamp_semantics") != "osv-scanner-command-completed-at":
        raise RuntimeError("Android OSV evidence identity is invalid")
    config = tool_config()
    if manifest.get("provider_api") != config["provider_api"] or \
            manifest.get("tool_config_sha256") != sha256_file(TOOL_CONFIG) or \
            manifest.get("tool_identity") != {
                "commit": config["commit"],
                "osv_scalibr_version": config["osv_scalibr_version"],
                "version": config["version"],
            }:
        raise RuntimeError("Android OSV tool binding is invalid")
    timestamp = manifest.get("query_completed_at")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise RuntimeError("Android OSV query completion time is invalid")
    try:
        datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise RuntimeError("Android OSV query completion time is invalid") from error
    report_path = output / "osv-report.json"
    if not report_path.is_file() or report_path.is_symlink() or \
            report_path.stat().st_size > MAX_REPORT_BYTES:
        raise RuntimeError("OSV Scanner report is missing, unsafe, or exceeds the evidence bound")
    report = normalize_report(read_json(report_path, "OSV Scanner report"))
    if manifest.get("report") != "osv-report.json" or \
            manifest.get("report_sha256") != sha256_file(report_path) or \
            manifest.get("scans") != report_summaries(report):
        raise RuntimeError("Android OSV report binding is invalid")
    scans = manifest["scans"]
    if not isinstance(scans, list) or scans[0].get("finding_count") != 0:
        raise RuntimeError("Android release runtime inventory has OSV findings")
    expected_names = {"android-osv-evidence.json", "osv-report.json", "SHA256SUMS"}
    entries = list(output.iterdir())
    if {entry.name for entry in entries} != expected_names or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise RuntimeError("OSV evidence has missing, extra, or unsafe entries")
    expected_checksums = "".join(
        f"{sha256_file(output / name)}  {name}\n"
        for name in ("android-osv-evidence.json", "osv-report.json")
    )
    if (output / "SHA256SUMS").read_text(encoding="ascii") != expected_checksums:
        raise RuntimeError("OSV evidence checksums are invalid")


def main() -> None:
    args = parse_args()
    if not REVISION.fullmatch(args.revision):
        raise RuntimeError("source revision must be a canonical commit")
    output = args.output.resolve()
    if not args.verify_only:
        if args.scanner is None:
            raise RuntimeError("OSV Scanner is required")
        build(output, args.revision, args.scanner.resolve())
    verify(output, args.revision)
    print("SevenMirror Android OSV query evidence verified.")


if __name__ == "__main__":
    main()
