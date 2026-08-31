from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from build_release_artifacts import build, verify


CERTIFICATE = "ab" * 32
REVISION = "3" * 40


def fake_tool(arguments: list[str]) -> str:
    if "apksigner" in Path(arguments[0]).name:
        return f"Signer #1 certificate SHA-256 digest: {CERTIFICATE}\n"
    command = arguments[2]
    return {
        "application-id": "example.fixture.app\n",
        "version-code": "42\n",
        "version-name": "1.2.3\n",
        "min-sdk": "29\n",
        "target-sdk": "35\n",
    }[command]


class AndroidReleaseArtifactTest(unittest.TestCase):
    @patch("build_release_artifacts.run_tool", side_effect=fake_tool)
    def test_signed_apk_metadata_verifies_and_rejects_tampering(self, _mock: object) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = root / "release-identity.properties"
            identity.write_text(
                "applicationId=example.fixture.app\n"
                "versionCode=42\n"
                "versionName=1.2.3\n"
                f"signingCertificateSha256={CERTIFICATE}\n"
                f"signingCertificateSha1={'cd' * 20}\n",
                encoding="ascii",
            )
            apk = root / "input.apk"
            apk.write_bytes(b"independent signed APK fixture")
            output = root / "release"
            apksigner = root / "apksigner"
            apkanalyzer = root / "apkanalyzer"

            build(apk, output, REVISION, apksigner, apkanalyzer, identity)
            verify(output, REVISION, apksigner, apkanalyzer, identity)
            packaged_apk = output / "sevenmirror-android-1.2.3-42.apk"
            packaged_apk.write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "does not match its manifest"):
                verify(output, REVISION, apksigner, apkanalyzer, identity)


if __name__ == "__main__":
    unittest.main()
