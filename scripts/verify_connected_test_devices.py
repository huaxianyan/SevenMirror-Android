#!/usr/bin/env python3
"""Refuse Gradle connected tests when any attached target is a physical device."""

from __future__ import annotations

import argparse
import subprocess
from collections.abc import Callable


def connected_serials(adb_devices_output: str) -> list[str]:
    serials: list[str] = []
    for line in adb_devices_output.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "device":
            serials.append(fields[0])
    return serials


def physical_devices(
    serials: list[str],
    get_property: Callable[[str, str], str],
) -> list[str]:
    return [serial for serial in serials if get_property(serial, "ro.kernel.qemu").strip() != "1"]


def adb_output(adb: str, *arguments: str) -> str:
    completed = subprocess.run(
        [adb, *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", default="adb")
    args = parser.parse_args()

    serials = connected_serials(adb_output(args.adb, "devices"))
    if not serials:
        raise SystemExit("Connected Android tests require a running emulator; no online device was found.")
    physical = physical_devices(
        serials,
        lambda serial, name: adb_output(args.adb, "-s", serial, "shell", "getprop", name),
    )
    if physical:
        joined = ", ".join(physical)
        raise SystemExit(
            "Refusing Gradle connected Android tests because physical device(s) are attached: "
            f"{joined}. These tasks may uninstall the target app and erase its private data; use an emulator."
        )
    print(f"Connected Android test guard accepted {len(serials)} emulator(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
