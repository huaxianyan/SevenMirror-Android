#!/usr/bin/env python3
"""Focused tests for android_osv_evidence.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

MODULE_PATH = Path(__file__).with_name("android_osv_evidence.py")
SPEC = importlib.util.spec_from_file_location("android_osv_evidence", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load android_osv_evidence.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def package(name: str, version: str, vulnerabilities: list[dict[str, str]] | None = None) -> dict:
    result = {
        "package": {"name": name, "version": version, "ecosystem": "Maven"},
    }
    if vulnerabilities:
        result["vulnerabilities"] = vulnerabilities
    return result


class AndroidOsvEvidenceTest(unittest.TestCase):
    def test_report_separates_runtime_zero_from_visible_build_findings(self) -> None:
        report = MODULE.normalize_report({
            "experimental_config": {},
            "results": [
                {
                    "source": {
                        "path": "/runner/work/project/gradle/verification-metadata.xml",
                        "type": "lockfile",
                    },
                    "packages": [
                        package(
                            "example:build-tool",
                            "2.0.0",
                            [{"id": "GHSA-2222-3333-4444"}, {"id": "CVE-2099-1000"}],
                        ),
                    ],
                },
                {
                    "source": {
                        "path": "/runner/work/project/gradle/release-runtime/gradle.lockfile",
                        "type": "lockfile",
                    },
                    "packages": [package("example:runtime", "1.0.0")],
                },
            ],
        })
        summaries = MODULE.report_summaries(report)
        self.assertEqual(
            [
                {
                    "affected": item["affected_package_count"],
                    "findings": item["finding_count"],
                    "packages": item["package_count"],
                    "scope": item["scope"],
                    "vulnerability_ids": item["vulnerability_ids"],
                }
                for item in summaries
            ],
            [
                {
                    "affected": 0,
                    "findings": 0,
                    "packages": 1,
                    "scope": "release-runtime",
                    "vulnerability_ids": [],
                },
                {
                    "affected": 1,
                    "findings": 2,
                    "packages": 1,
                    "scope": "build-tool",
                    "vulnerability_ids": ["CVE-2099-1000", "GHSA-2222-3333-4444"],
                },
            ],
        )
        self.assertEqual(
            report["results"][0]["source"]["path"],
            "gradle/release-runtime/gradle.lockfile",
        )

    def test_report_rejects_an_unapproved_inventory_source(self) -> None:
        report = {
            "experimental_config": {},
            "results": [
                {
                    "source": {"path": "/tmp/other.lock", "type": "lockfile"},
                    "packages": [],
                },
            ],
        }
        with self.assertRaisesRegex(RuntimeError, "outside the two approved inventories"):
            MODULE.normalize_report(report)

    def test_scanner_build_identity_is_exact(self) -> None:
        config = MODULE.tool_config()
        MODULE.parse_scanner_version(
            "osv-scanner version: 2.5.1\n"
            "osv-scalibr version: 0.5.2\n"
            "commit: c84fa4568f2526d0333e9a914ea8a0a5f74ad68b\n"
            "built at: 2026-08-17T03:44:26Z\n",
            config,
        )
        with self.assertRaisesRegex(RuntimeError, "unexpected OSV Scanner"):
            MODULE.parse_scanner_version(
                "osv-scanner version: 2.5.2\n"
                "osv-scalibr version: 0.5.2\n"
                "commit: c84fa4568f2526d0333e9a914ea8a0a5f74ad68b\n"
                "built at: 2026-08-17T03:44:26Z\n",
                config,
            )


if __name__ == "__main__":
    unittest.main()
