#!/usr/bin/env python3
"""Prepare or verify a bounded Windows Sandbox candidate acceptance run."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

if __package__:
    from . import package_binary
else:
    import package_binary

SCHEMA = "embedded-debugger.windows-sandbox-acceptance.v1"
REQUEST_SCHEMA = "embedded-debugger.windows-sandbox-request.v1"
RESULT_SCHEMA = "embedded-debugger.windows-sandbox-result.v1"
SCRIPT_NAME = "Run-WindowsSandboxAcceptance.ps1"
REQUEST_NAME = "request.json"
RESULT_NAME = "sandbox-result.json"
SMOKE_NAME = "windows-host-smoke.json"
INSTALL_LOG_NAME = "vc-redist-install.log"
MAX_EVIDENCE = 4 * 1024 * 1024
HASH = re.compile(r"[0-9a-f]{64}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes) -> object:
    def reject(value: str) -> None:
        raise ValueError(f"non-JSON numeric constant: {value}")

    return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject)


def exact_fields(value: object, expected: set[str], description: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"unexpected {description} fields")
    return value


def write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)


def authenticode_identity(path: Path) -> dict:
    if os.name != "nt":
        raise ValueError("runtime installer verification requires Windows")
    literal_path = str(path).replace("'", "''")
    command = (
        f"$p='{literal_path}';$s=Get-AuthenticodeSignature -LiteralPath $p;"
        "$f=Get-Item -LiteralPath $p;"
        "[pscustomobject]@{status=[string]$s.Status;"
        "subject=$s.SignerCertificate.Subject;"
        "file_version=$f.VersionInfo.FileVersion}|ConvertTo-Json -Compress"
    )
    environment = os.environ.copy()
    windows = Path(environment.get("SystemRoot", r"C:\Windows"))
    program_files = Path(
        environment.get("ProgramFiles", windows.drive + r"\Program Files")
    )
    # Codex can prepend PowerShell 7 modules to PSModulePath. Windows PowerShell
    # then fails to import its own Security module due to duplicate type data.
    environment["PSModulePath"] = ";".join(
        (
            str(program_files / "WindowsPowerShell/Modules"),
            str(windows / "system32/WindowsPowerShell/v1.0/Modules"),
        )
    )
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        capture_output=True,
        check=False,
        env=environment,
        timeout=30,
    )
    if result.returncode or result.stderr:
        raise ValueError("cannot verify runtime installer Authenticode signature")
    identity = exact_fields(
        parse_json(result.stdout),
        {"status", "subject", "file_version"},
        "runtime installer identity",
    )
    if (
        identity["status"] != "Valid"
        or identity["subject"]
        != "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
        or not isinstance(identity["file_version"], str)
        or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", identity["file_version"])
    ):
        raise ValueError("runtime installer is not the expected valid Microsoft signer")
    return identity


def sandbox_configuration(input_dir: Path, evidence_dir: Path) -> bytes:
    root = ET.Element("Configuration")
    for name, value in (
        ("VGpu", "Disable"),
        ("Networking", "Disable"),
        ("AudioInput", "Disable"),
        ("VideoInput", "Disable"),
        ("PrinterRedirection", "Disable"),
        ("ClipboardRedirection", "Disable"),
        ("ProtectedClient", "Enable"),
    ):
        ET.SubElement(root, name).text = value
    folders = ET.SubElement(root, "MappedFolders")
    for host, guest, readonly in (
        (input_dir, r"C:\eat-input", "true"),
        (evidence_dir, r"C:\eat-evidence", "false"),
    ):
        folder = ET.SubElement(folders, "MappedFolder")
        ET.SubElement(folder, "HostFolder").text = str(host)
        ET.SubElement(folder, "SandboxFolder").text = guest
        ET.SubElement(folder, "ReadOnly").text = readonly
    command = ET.SubElement(ET.SubElement(root, "LogonCommand"), "Command")
    command.text = (
        r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
        r"C:\eat-input\Run-WindowsSandboxAcceptance.ps1 "
        r"-InputDirectory C:\eat-input -EvidenceDirectory C:\eat-evidence"
    )
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def validate_configuration(data: bytes, input_dir: Path, evidence_dir: Path) -> None:
    root = ET.fromstring(data)
    if root.tag != "Configuration":
        raise ValueError("invalid Windows Sandbox configuration root")
    expected_controls = {
        "VGpu": "Disable",
        "Networking": "Disable",
        "AudioInput": "Disable",
        "VideoInput": "Disable",
        "PrinterRedirection": "Disable",
        "ClipboardRedirection": "Disable",
        "ProtectedClient": "Enable",
    }
    for name, value in expected_controls.items():
        matches = root.findall(name)
        if len(matches) != 1 or matches[0].text != value:
            raise ValueError(f"Windows Sandbox control differs: {name}")
    folders = root.findall("MappedFolders/MappedFolder")
    expected_folders = [
        (str(input_dir), r"C:\eat-input", "true"),
        (str(evidence_dir), r"C:\eat-evidence", "false"),
    ]
    actual_folders = [
        (
            folder.findtext("HostFolder"),
            folder.findtext("SandboxFolder"),
            folder.findtext("ReadOnly"),
        )
        for folder in folders
    ]
    if actual_folders != expected_folders:
        raise ValueError("Windows Sandbox mapped folders differ")
    commands = root.findall("LogonCommand/Command")
    if len(commands) != 1 or commands[0].text != (
        r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
        r"C:\eat-input\Run-WindowsSandboxAcceptance.ps1 "
        r"-InputDirectory C:\eat-input -EvidenceDirectory C:\eat-evidence"
    ):
        raise ValueError("Windows Sandbox logon command differs")
    allowed = set(expected_controls) | {"MappedFolders", "LogonCommand"}
    if [child.tag for child in root] != [
        *expected_controls,
        "MappedFolders",
        "LogonCommand",
    ] or any(child.tag not in allowed for child in root):
        raise ValueError("unexpected Windows Sandbox configuration element")


def prepare(
    root: Path,
    archive: Path,
    checksum: Path,
    output_dir: Path,
    runtime_installer: Path | None = None,
) -> dict:
    verification = package_binary.verify(archive, checksum)
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("sandbox acceptance output already exists")
    script = package_binary.bounded_read(
        root / "scripts" / "run_windows_sandbox_acceptance.ps1",
        package_binary.MAX_METADATA,
    )
    archive_data = package_binary.bounded_read(archive, package_binary.MAX_ARCHIVE)
    checksum_data = package_binary.bounded_read(checksum, 1024)
    output_dir.mkdir(parents=True)
    input_dir = output_dir / "input"
    evidence_dir = output_dir / "evidence"
    input_dir.mkdir()
    evidence_dir.mkdir()
    write_new(input_dir / archive.name, archive_data)
    write_new(input_dir / checksum.name, checksum_data)
    write_new(input_dir / SCRIPT_NAME, script)
    immutable_inputs = {
        archive.name: sha256(archive_data),
        checksum.name: sha256(checksum_data),
        SCRIPT_NAME: sha256(script),
    }
    installer_record = None
    if runtime_installer is not None:
        installer_data = package_binary.bounded_read(
            runtime_installer, package_binary.MAX_FILE
        )
        installer_identity = authenticode_identity(runtime_installer.resolve())
        installer_name = "vc_redist.x64.exe"
        write_new(input_dir / installer_name, installer_data)
        immutable_inputs[installer_name] = sha256(installer_data)
        installer_record = {
            "name": installer_name,
            "sha256": sha256(installer_data),
            "signature_status": installer_identity["status"],
            "signer_subject": installer_identity["subject"],
            "file_version": installer_identity["file_version"],
            "source_url": "https://aka.ms/vc14/vc_redist.x64.exe",
        }
    request = {
        "schema_version": REQUEST_SCHEMA,
        "nonce": secrets.token_hex(32),
        "generated_utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "archive_name": archive.name,
        "checksum_name": checksum.name,
        "archive_sha256": verification["sha256"],
        "executable_sha256": None,
        "version": verification["version"],
        "target": verification["target"],
        "source_revision": verification["source_revision"],
        "immutable_inputs": immutable_inputs,
        "runtime_installer": installer_record,
        "controls": {
            "networking": "disabled",
            "clipboard": "disabled",
            "audio_input": "disabled",
            "video_input": "disabled",
            "printer_redirection": "disabled",
            "vgpu": "disabled",
            "protected_client": "enabled",
            "input_mapping": "read_only",
            "evidence_mapping": "dedicated_writable",
            "hardware_access": False,
        },
    }
    # The verified release manifest is the authority for the executable digest.
    with zipfile.ZipFile(archive) as package:
        folder = f"embedded-debugger-{verification['version']}-{verification['target']}"
        manifest = package_binary.parse_json(
            package.read(f"{folder}/{package_binary.MANIFEST_NAME}")
        )
    request["executable_sha256"] = next(
        item["sha256"]
        for item in manifest["files"]
        if item["path"] == "embedded-debugger.exe"
    )
    request_data = json_bytes(request)
    write_new(input_dir / REQUEST_NAME, request_data)
    config = sandbox_configuration(input_dir.resolve(), evidence_dir.resolve())
    validate_configuration(config, input_dir.resolve(), evidence_dir.resolve())
    launcher = output_dir / "Run-Clean-Windows-Acceptance.wsb"
    write_new(launcher, config)
    return {
        "directory": str(output_dir.resolve()),
        "launcher": str(launcher.resolve()),
        "request_sha256": sha256(request_data),
        "configuration_sha256": sha256(config),
        "archive_sha256": verification["sha256"],
        "executable_sha256": request["executable_sha256"],
        "nonce": request["nonce"],
        "sandbox_available_on_host": Path(
            Path.home().drive + r"\Windows\System32\WindowsSandbox.exe"
        ).is_file(),
        "hardware_access": False,
        "clean_environment_verified": False,
    }


def verify(root_dir: Path) -> dict:
    input_dir = root_dir / "input"
    evidence_dir = root_dir / "evidence"
    request_data = package_binary.bounded_read(input_dir / REQUEST_NAME, MAX_EVIDENCE)
    request = exact_fields(
        parse_json(request_data),
        {
            "schema_version",
            "nonce",
            "generated_utc",
            "archive_name",
            "checksum_name",
            "archive_sha256",
            "executable_sha256",
            "version",
            "target",
            "source_revision",
            "immutable_inputs",
            "runtime_installer",
            "controls",
        },
        "sandbox request",
    )
    if (
        request["schema_version"] != REQUEST_SCHEMA
        or not re.fullmatch(r"[0-9a-f]{64}", request["nonce"])
        or not HASH.fullmatch(request["archive_sha256"])
        or not HASH.fullmatch(request["executable_sha256"])
        or not isinstance(request["generated_utc"], str)
        or not isinstance(request["archive_name"], str)
        or Path(request["archive_name"]).name != request["archive_name"]
        or not isinstance(request["checksum_name"], str)
        or Path(request["checksum_name"]).name != request["checksum_name"]
    ):
        raise ValueError("invalid Windows Sandbox request identity")
    expected_controls = {
        "networking": "disabled",
        "clipboard": "disabled",
        "audio_input": "disabled",
        "video_input": "disabled",
        "printer_redirection": "disabled",
        "vgpu": "disabled",
        "protected_client": "enabled",
        "input_mapping": "read_only",
        "evidence_mapping": "dedicated_writable",
        "hardware_access": False,
    }
    if request["controls"] != expected_controls:
        raise ValueError("Windows Sandbox request controls differ")
    expected_inputs = {request["archive_name"], request["checksum_name"], SCRIPT_NAME}
    installer = request["runtime_installer"]
    if installer is not None:
        exact_fields(
            installer,
            {
                "name",
                "sha256",
                "signature_status",
                "signer_subject",
                "file_version",
                "source_url",
            },
            "runtime installer",
        )
        if (
            installer["name"] != "vc_redist.x64.exe"
            or not HASH.fullmatch(installer["sha256"])
            or installer["signature_status"] != "Valid"
            or installer["signer_subject"]
            != "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", installer["file_version"])
            or installer["source_url"] != "https://aka.ms/vc14/vc_redist.x64.exe"
        ):
            raise ValueError("invalid pinned runtime installer")
        expected_inputs.add(installer["name"])
    if (
        not isinstance(request["immutable_inputs"], dict)
        or set(request["immutable_inputs"]) != expected_inputs
    ):
        raise ValueError("unexpected immutable input inventory")
    for name, expected in request["immutable_inputs"].items():
        if not isinstance(expected, str) or not HASH.fullmatch(expected):
            raise ValueError("invalid immutable input digest")
        if (
            sha256(
                package_binary.bounded_read(
                    input_dir / name, package_binary.MAX_ARCHIVE
                )
            )
            != expected
        ):
            raise ValueError(f"immutable sandbox input changed: {name}")
    candidate = package_binary.verify(
        input_dir / request["archive_name"], input_dir / request["checksum_name"]
    )
    if any(
        candidate[key] != request[value]
        for key, value in (
            ("sha256", "archive_sha256"),
            ("version", "version"),
            ("target", "target"),
            ("source_revision", "source_revision"),
        )
    ):
        raise ValueError("sandbox request differs from verified candidate")
    config_data = package_binary.bounded_read(
        root_dir / "Run-Clean-Windows-Acceptance.wsb", MAX_EVIDENCE
    )
    validate_configuration(config_data, input_dir.resolve(), evidence_dir.resolve())
    result = exact_fields(
        parse_json(
            package_binary.bounded_read(evidence_dir / RESULT_NAME, MAX_EVIDENCE)
        ),
        {
            "schema_version",
            "ok",
            "nonce",
            "request_sha256",
            "archive_sha256",
            "executable_sha256",
            "input_mapping_read_only_observed",
            "network_interfaces_up_non_loopback",
            "hardware_access",
            "environment",
            "smoke_report_sha256",
            "runtime_installation",
            "error",
        },
        "sandbox result",
    )
    smoke_data = package_binary.bounded_read(evidence_dir / SMOKE_NAME, MAX_EVIDENCE)
    smoke = exact_fields(
        parse_json(smoke_data),
        {
            "schema_version",
            "ok",
            "environment_label",
            "clean_environment_verified",
            "hardware_access",
            "executable_started",
            "executable",
            "expected_sha256",
            "expected_version",
            "timestamp_utc",
            "os_version",
            "is_64_bit_os",
            "checks",
            "error",
            "actual_sha256",
            "system_vcruntime140",
        },
        "sandbox smoke report",
    )
    environment = exact_fields(
        result["environment"],
        {
            "os_version",
            "is_64_bit_os",
            "user_name",
            "computer_name",
            "manufacturer",
            "model",
            "system_vcruntime140_before_execution",
        },
        "sandbox environment",
    )
    installation = result["runtime_installation"]
    installation_ok = installer is None and installation is None
    if installer is not None:
        exact_fields(
            installation,
            {
                "attempted",
                "installer_sha256",
                "signature_status",
                "signer_subject",
                "file_version",
                "exit_code",
                "restart_required",
                "vcruntime140_after_installation",
                "log_sha256",
            },
            "runtime installation",
        )
        log_data = package_binary.bounded_read(
            evidence_dir / INSTALL_LOG_NAME, MAX_EVIDENCE
        )
        installation_ok = (
            installation["attempted"] is True
            and installation["installer_sha256"] == installer["sha256"]
            and installation["signature_status"] == installer["signature_status"]
            and installation["signer_subject"] == installer["signer_subject"]
            and installation["file_version"] == installer["file_version"]
            and installation["exit_code"] in {0, 1638, 3010}
            and installation["restart_required"] is (installation["exit_code"] == 3010)
            and isinstance(installation["vcruntime140_after_installation"], str)
            and installation["log_sha256"] == sha256(log_data)
        )
    checks = smoke["checks"]
    if not isinstance(checks, list) or len(checks) != 2:
        raise ValueError("Windows Sandbox smoke checks differ")
    for check in checks:
        exact_fields(
            check, {"arguments", "exit_code", "stdout", "stderr"}, "smoke check"
        )
    version_check, help_check = checks
    smoke_checks_ok = (
        version_check["arguments"] == "--version"
        and version_check["exit_code"] == 0
        and version_check["stdout"].strip() == f"embedded-debugger {request['version']}"
        and not version_check["stderr"].strip()
        and help_check["arguments"] == "runtime --help"
        and help_check["exit_code"] == 0
        and "inspect" in help_check["stdout"]
        and not help_check["stderr"].strip()
    )
    if (
        result["schema_version"] != RESULT_SCHEMA
        or result["ok"] is not True
        or result["nonce"] != request["nonce"]
        or result["request_sha256"] != sha256(request_data)
        or result["archive_sha256"] != request["archive_sha256"]
        or result["executable_sha256"] != request["executable_sha256"]
        or result["input_mapping_read_only_observed"] is not True
        or result["network_interfaces_up_non_loopback"] != 0
        or result["hardware_access"] is not False
        or result["error"] is not None
        or not installation_ok
        or environment["user_name"] != "WDAGUtilityAccount"
        or environment["is_64_bit_os"] is not True
        or result["smoke_report_sha256"] != sha256(smoke_data)
        or smoke["schema_version"] != "embedded-debugger.windows-host-smoke.v1"
        or smoke["ok"] is not True
        or smoke["hardware_access"] is not False
        or smoke["clean_environment_verified"] is not False
        or smoke["executable_started"] is not True
        or smoke["error"] is not None
        or smoke["actual_sha256"] != request["executable_sha256"]
        or smoke["expected_sha256"] != request["executable_sha256"]
        or smoke["expected_version"] != request["version"]
        or smoke["os_version"] != environment["os_version"]
        or smoke["is_64_bit_os"] != environment["is_64_bit_os"]
        or smoke["system_vcruntime140"]
        != environment["system_vcruntime140_before_execution"]
        or not smoke_checks_ok
    ):
        raise ValueError("Windows Sandbox evidence does not meet acceptance policy")
    return {
        "schema_version": SCHEMA,
        "ok": True,
        "archive_sha256": request["archive_sha256"],
        "executable_sha256": request["executable_sha256"],
        "source_revision": request["source_revision"],
        "request_sha256": sha256(request_data),
        "configuration_sha256": sha256(config_data),
        "smoke_report_sha256": sha256(smoke_data),
        "runtime_installation": installation,
        "environment": environment,
        "clean_environment_verified": True,
        "hardware_access": False,
        "publisher_authenticity_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("archive", type=Path)
    prepare_parser.add_argument("--checksum", type=Path, required=True)
    prepare_parser.add_argument("--output-dir", type=Path, required=True)
    prepare_parser.add_argument("--runtime-installer", type=Path)
    prepare_parser.add_argument("--json", action="store_true")
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("directory", type=Path)
    verify_parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parent.parent
        result = (
            prepare(
                root,
                args.archive,
                args.checksum,
                args.output_dir,
                args.runtime_installer,
            )
            if args.operation == "prepare"
            else verify(args.directory)
        )
        report = {
            "schema_version": SCHEMA,
            "ok": True,
            "operation": args.operation,
            "data": result,
        }
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        StopIteration,
        ET.ParseError,
        package_binary.ReleaseError,
    ) as error:
        report = {
            "schema_version": SCHEMA,
            "ok": False,
            "operation": args.operation,
            "error": str(error),
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
