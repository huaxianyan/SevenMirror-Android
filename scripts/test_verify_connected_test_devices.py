#!/usr/bin/env python3
"""Tests for the connected Android test device guard."""

from __future__ import annotations

import unittest

from verify_connected_test_devices import connected_serials, physical_devices


class ConnectedTestDeviceGuardTest(unittest.TestCase):
    def test_accepts_online_emulators_and_ignores_offline_devices(self) -> None:
        output = "List of devices attached\nemulator-5554\tdevice\nphone\toffline\n"
        serials = connected_serials(output)

        self.assertEqual(["emulator-5554"], serials)
        self.assertEqual([], physical_devices(serials, lambda _serial, _name: "1\n"))

    def test_identifies_physical_device_before_connected_test_runs(self) -> None:
        serials = ["emulator-5554", "user-phone"]
        values = {"emulator-5554": "1", "user-phone": "0"}

        self.assertEqual(
            ["user-phone"],
            physical_devices(serials, lambda serial, _name: values[serial]),
        )


if __name__ == "__main__":
    unittest.main()
