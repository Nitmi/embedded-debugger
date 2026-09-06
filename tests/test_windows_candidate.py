import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows PowerShell host-only smoke gates")
class WindowsCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.candidate = self.root / "embedded-debugger.exe"
        self.candidate.write_bytes(b"not an executable; must never start")
        self.report = self.root / "result.json"
        self.script = (
            Path(__file__).resolve().parents[1] / "scripts/test_windows_candidate.ps1"
        )

    def run_smoke(self):
        return subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-File",
                str(self.script),
                "-Executable",
                str(self.candidate),
                "-ExpectedSha256",
                "0" * 64,
                "-ReportPath",
                str(self.report),
            ],
            capture_output=True,
            timeout=30,
            check=False,
        )

    def test_wrong_digest_is_reported_before_executable_start(self):
        result = self.run_smoke()
        self.assertNotEqual(result.returncode, 0)
        report = json.loads(self.report.read_bytes())
        self.assertFalse(report["ok"])
        self.assertFalse(report["executable_started"])
        self.assertFalse(report["hardware_access"])
        self.assertFalse(report["clean_environment_verified"])
        self.assertEqual(report["checks"], [])
        self.assertIn("checksum mismatch", report["error"])

    def test_existing_report_is_never_overwritten(self):
        self.report.write_bytes(b"previous evidence")
        self.assertNotEqual(self.run_smoke().returncode, 0)
        self.assertEqual(self.report.read_bytes(), b"previous evidence")

    def test_missing_executable_records_failure(self):
        self.candidate.unlink()
        self.assertNotEqual(self.run_smoke().returncode, 0)
        report = json.loads(self.report.read_bytes())
        self.assertFalse(report["executable_started"])
        self.assertFalse(report["ok"])


if __name__ == "__main__":
    unittest.main()
