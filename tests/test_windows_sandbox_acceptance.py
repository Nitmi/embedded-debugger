import copy
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts import windows_sandbox_acceptance as sandbox


class WindowsSandboxAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "run_windows_sandbox_acceptance.ps1").write_bytes(
            b"sandbox script\n"
        )
        self.archive = self.root / "candidate.zip"
        self.executable_hash = "e" * 64
        manifest = {
            "files": [{"path": "embedded-debugger.exe", "sha256": self.executable_hash}]
        }
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "embedded-debugger-0.2.0-x86_64-pc-windows-msvc/release-manifest.json",
                json.dumps(manifest),
            )
        self.checksum = self.archive.with_suffix(".zip.sha256")
        self.archive_hash = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.checksum.write_text(f"{self.archive_hash}  {self.archive.name}\n")
        self.candidate = {
            "sha256": self.archive_hash,
            "version": "0.2.0",
            "target": "x86_64-pc-windows-msvc",
            "source_revision": "a" * 40,
        }
        self.output = self.root / "acceptance"

    def prepare(self):
        with patch.object(
            sandbox.package_binary, "verify", return_value=self.candidate
        ):
            return sandbox.prepare(self.root, self.archive, self.checksum, self.output)

    def prepare_with_installer(self):
        installer = self.root / "download.exe"
        installer.write_bytes(b"signed installer fixture")
        with (
            patch.object(sandbox.package_binary, "verify", return_value=self.candidate),
            patch.object(
                sandbox,
                "authenticode_identity",
                return_value={
                    "status": "Valid",
                    "subject": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
                    "file_version": "14.51.36247.0",
                },
            ),
        ):
            sandbox.prepare(
                self.root, self.archive, self.checksum, self.output, installer
            )

    def write_evidence(self):
        request_data = (self.output / "input/request.json").read_bytes()
        request = json.loads(request_data)
        smoke = {
            "schema_version": "embedded-debugger.windows-host-smoke.v1",
            "ok": True,
            "environment_label": "Windows Sandbox",
            "clean_environment_verified": False,
            "hardware_access": False,
            "executable_started": True,
            "executable": r"C:\temp\embedded-debugger.exe",
            "expected_sha256": self.executable_hash,
            "expected_version": "0.2.0",
            "timestamp_utc": "2026-09-08T00:00:00Z",
            "os_version": "10.0.26200.0",
            "is_64_bit_os": True,
            "checks": [
                {
                    "arguments": "--version",
                    "exit_code": 0,
                    "stdout": "embedded-debugger 0.2.0\n",
                    "stderr": "",
                },
                {
                    "arguments": "runtime --help",
                    "exit_code": 0,
                    "stdout": "inspect\n",
                    "stderr": "",
                },
            ],
            "error": None,
            "actual_sha256": self.executable_hash,
            "system_vcruntime140": "14.51.36247.0",
        }
        smoke_data = sandbox.json_bytes(smoke)
        (self.output / "evidence" / sandbox.SMOKE_NAME).write_bytes(smoke_data)
        result = {
            "schema_version": sandbox.RESULT_SCHEMA,
            "ok": True,
            "nonce": request["nonce"],
            "request_sha256": sandbox.sha256(request_data),
            "archive_sha256": self.archive_hash,
            "executable_sha256": self.executable_hash,
            "input_mapping_read_only_observed": True,
            "network_interfaces_up_non_loopback": 0,
            "hardware_access": False,
            "environment": {
                "os_version": "10.0.26200.0",
                "is_64_bit_os": True,
                "user_name": "WDAGUtilityAccount",
                "computer_name": "sandbox",
                "manufacturer": "Microsoft Corporation",
                "model": "Virtual Machine",
                "system_vcruntime140_before_execution": "14.51.36247.0",
            },
            "smoke_report_sha256": sandbox.sha256(smoke_data),
            "runtime_installation": None,
            "error": None,
        }
        (self.output / "evidence" / sandbox.RESULT_NAME).write_bytes(
            sandbox.json_bytes(result)
        )

    def verify(self):
        with patch.object(
            sandbox.package_binary, "verify", return_value=self.candidate
        ):
            return sandbox.verify(self.output)

    def test_prepare_pins_candidate_and_restricts_sandbox(self):
        result = self.prepare()
        request = json.loads((self.output / "input/request.json").read_bytes())
        config = (self.output / "Run-Clean-Windows-Acceptance.wsb").read_bytes()
        sandbox.validate_configuration(
            config,
            (self.output / "input").resolve(),
            (self.output / "evidence").resolve(),
        )
        self.assertEqual(request["archive_sha256"], self.archive_hash)
        self.assertEqual(request["executable_sha256"], self.executable_hash)
        self.assertEqual(request["controls"]["networking"], "disabled")
        self.assertEqual(request["controls"]["input_mapping"], "read_only")
        self.assertFalse(result["clean_environment_verified"])

    def test_prepare_pins_valid_microsoft_runtime_installer(self):
        self.prepare_with_installer()
        request = json.loads((self.output / "input/request.json").read_bytes())
        self.assertEqual(request["runtime_installer"]["name"], "vc_redist.x64.exe")
        self.assertEqual(
            request["runtime_installer"]["sha256"],
            sandbox.sha256(b"signed installer fixture"),
        )
        self.assertEqual(
            (self.output / "input/vc_redist.x64.exe").read_bytes(),
            b"signed installer fixture",
        )

    def test_valid_runtime_installation_evidence_is_qualified(self):
        self.prepare_with_installer()
        self.write_evidence()
        request = json.loads((self.output / "input/request.json").read_bytes())
        log_data = b"Microsoft VC runtime installation log\n"
        (self.output / "evidence" / sandbox.INSTALL_LOG_NAME).write_bytes(log_data)
        result_path = self.output / "evidence" / sandbox.RESULT_NAME
        result = json.loads(result_path.read_bytes())
        result["runtime_installation"] = {
            "attempted": True,
            "installer_sha256": request["runtime_installer"]["sha256"],
            "signature_status": "Valid",
            "signer_subject": request["runtime_installer"]["signer_subject"],
            "file_version": "14.51.36247.0",
            "exit_code": 0,
            "restart_required": False,
            "vcruntime140_after_installation": "14.51.36247.0",
            "log_sha256": sandbox.sha256(log_data),
        }
        result_path.write_bytes(sandbox.json_bytes(result))
        verified = self.verify()
        self.assertTrue(verified["clean_environment_verified"])
        self.assertEqual(verified["runtime_installation"]["exit_code"], 0)

    def test_prepare_never_overwrites_an_acceptance_directory(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.prepare()

    def test_valid_sandbox_evidence_is_qualified(self):
        self.prepare()
        self.write_evidence()
        result = self.verify()
        self.assertTrue(result["clean_environment_verified"])
        self.assertFalse(result["hardware_access"])
        self.assertFalse(result["publisher_authenticity_verified"])

    def test_result_identity_and_environment_fail_closed(self):
        self.prepare()
        self.write_evidence()
        path = self.output / "evidence" / sandbox.RESULT_NAME
        original = json.loads(path.read_bytes())
        changes = (
            ("nonce", "b" * 64),
            ("input_mapping_read_only_observed", False),
            ("network_interfaces_up_non_loopback", 1),
            ("hardware_access", True),
            ("smoke_report_sha256", "b" * 64),
        )
        for key, value in changes:
            with self.subTest(key=key):
                changed = copy.deepcopy(original)
                changed[key] = value
                path.write_bytes(sandbox.json_bytes(changed))
                with self.assertRaisesRegex(ValueError, "acceptance policy"):
                    self.verify()
        changed = copy.deepcopy(original)
        changed["environment"]["user_name"] = "developer"
        path.write_bytes(sandbox.json_bytes(changed))
        with self.assertRaisesRegex(ValueError, "acceptance policy"):
            self.verify()

    def test_request_config_or_input_tampering_is_rejected(self):
        self.prepare()
        self.write_evidence()
        request_path = self.output / "input/request.json"
        request = json.loads(request_path.read_bytes())
        request["controls"]["networking"] = "enabled"
        request_path.write_bytes(sandbox.json_bytes(request))
        with self.assertRaisesRegex(ValueError, "controls"):
            self.verify()
        self.output = self.root / "second"
        self.prepare()
        self.write_evidence()
        config = self.output / "Run-Clean-Windows-Acceptance.wsb"
        config.write_text(
            config.read_text().replace("<Networking>Disable", "<Networking>Enable")
        )
        with self.assertRaisesRegex(ValueError, "Networking"):
            self.verify()
        self.output = self.root / "third"
        self.prepare()
        self.write_evidence()
        with (self.output / "input" / self.archive.name).open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "immutable sandbox input"):
            self.verify()

    def test_smoke_command_or_environment_tampering_is_rejected(self):
        self.prepare()
        self.write_evidence()
        path = self.output / "evidence" / sandbox.SMOKE_NAME
        original = json.loads(path.read_bytes())
        changed = copy.deepcopy(original)
        changed["checks"][0]["arguments"] = "probes list"
        changed_data = sandbox.json_bytes(changed)
        path.write_bytes(changed_data)
        result_path = self.output / "evidence" / sandbox.RESULT_NAME
        result = json.loads(result_path.read_bytes())
        result["smoke_report_sha256"] = sandbox.sha256(changed_data)
        result_path.write_bytes(sandbox.json_bytes(result))
        with self.assertRaisesRegex(ValueError, "acceptance policy"):
            self.verify()
        self.write_evidence()
        changed = copy.deepcopy(original)
        changed["os_version"] = "10.0.1.0"
        changed_data = sandbox.json_bytes(changed)
        path.write_bytes(changed_data)
        result = json.loads(result_path.read_bytes())
        result["smoke_report_sha256"] = sandbox.sha256(changed_data)
        result_path.write_bytes(sandbox.json_bytes(result))
        with self.assertRaisesRegex(ValueError, "acceptance policy"):
            self.verify()

    def test_duplicate_json_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            sandbox.parse_json(b'{"a":1,"a":1}')
        with self.assertRaises(ValueError):
            sandbox.parse_json(b'{"value":NaN}')

    def test_guest_uses_framework_zip_api_not_optional_archive_module(self):
        script = (
            Path(__file__).resolve().parent.parent
            / "scripts/run_windows_sandbox_acceptance.ps1"
        ).read_text()
        self.assertIn("[IO.Compression.ZipFile]::ExtractToDirectory", script)
        self.assertNotIn("\n    Expand-Archive ", script)


if __name__ == "__main__":
    unittest.main()
