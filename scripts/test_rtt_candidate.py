#!/usr/bin/env python3
"""Check a hash-bound release executable's RTT interface without hardware access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def check(executable: Path, expected_hash: str, fixture: Path, output: Path) -> dict:
    executable = executable.resolve()
    require(executable.is_file(), "executable is not a regular file")
    require(digest(executable.read_bytes()) == expected_hash, "executable hash differs")
    fixture_data = fixture.read_bytes()
    require(len(fixture_data) < 1024 * 1024, "fixture is too large")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": "embedded-debugger.rtt-candidate-smoke.v1",
        "ok": False,
        "scope": "host_only_replay_and_planning",
        "hardware_access": False,
        "hardware_acceptance_verified": False,
        "executable": str(executable),
        "executable_sha256": expected_hash,
        "fixture_sha256": digest(fixture_data),
        "checks": [],
        "error": None,
    }
    try:
        copied_fixture = (output / "fixture.json").resolve()
        with copied_fixture.open("xb") as stream:
            stream.write(fixture_data)
        environment = os.environ.copy()
        if os.name == "nt":
            system_root = os.environ["SystemRoot"]
            environment["PATH"] = os.pathsep.join(
                [str(Path(system_root) / "System32"), system_root]
            )

        def run(name: str, arguments: list[str], exit_code: int = 0) -> dict:
            result = subprocess.run(
                [str(executable), *arguments],
                cwd=output,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            for suffix, content in (("stdout", result.stdout), ("stderr", result.stderr)):
                with (output / f"{name}.{suffix}").open("xb") as stream:
                    stream.write(content)
            report["checks"].append(
                {"name": name, "arguments": arguments, "exit_code": result.returncode}
            )
            require(result.returncode == exit_code, f"{name}: unexpected exit code")
            require(not result.stderr.strip(), f"{name}: unexpected stderr")
            return json.loads(result.stdout)

        native = run("native-plan", [
            "--json", "--backend", "probe-rs", "rtt", "plan", "--probe",
            "1366:1061:not-a-connected-serial", "--target", "nRF52840_xxAA",
            "--control-block", "0x20000100",
        ])
        require(native["ok"] is True, "native plan failed")
        native_data = native["data"]
        require(native_data["hardware_access"] is False, "native plan accessed hardware")
        require(native_data["memory_scope"]["start"] == "0x20000000", "wrong RAM scope")
        require(native_data["effects"]["target_rtt_read_cursor_write"] is True, "missing cursor effect")
        require(all(native_data["effects"][key] is False for key in (
            "reset_requested", "halt_requested", "resume_requested", "down_channel_write",
        )), "unexpected native plan effect")

        expected_payload = (
            b"EAT_RTT_READY v1\n"
            b"EAT_RTT_HEARTBEAT 0001\n"
            b"EAT_RTT_HEARTBEAT 0002\n"
        )
        prefix = ["--json", "--backend", "replay", "--fixture", str(copied_fixture)]
        selection = [
            "--probe", "replay:stlink-v3:0039002A3432510433343034",
            "--target", "STM32G431CBTx", "--control-block", "0x20000100",
            "--duration-ms", "1000", "--poll-interval-ms", "1",
            "--max-bytes", str(len(expected_payload)),
        ]
        plan = run("replay-plan", prefix + ["rtt", "plan"] + selection)
        require(plan["ok"] is True and plan["data"]["hardware_access"] is False, "replay plan failed")
        rejected_file = (output / "must-not-exist.jsonl").resolve()
        rejected = run("bad-confirmation", prefix + ["rtt", "capture"] + selection + [
            "--confirm", "wrong", "--evidence", str(rejected_file),
        ], 2)
        require(rejected["error"]["code"] == "CONFIRMATION_MISMATCH", "wrong confirmation error")
        require(not rejected_file.exists(), "rejected capture created evidence")

        evidence_file = (output / "rtt.jsonl").resolve()
        captured = run("replay-capture", prefix + ["rtt", "capture"] + selection + [
            "--confirm", plan["data"]["confirm_digest"], "--evidence", str(evidence_file),
        ])
        data = captured["data"]
        require(captured["ok"] is True, "replay capture failed")
        require(all(data[key] is True for key in (
            "complete", "channel_stopped", "disconnected",
        )), "capture cleanup is incomplete")
        require(data["hardware_access"] is False, "replay accessed hardware")
        require(data["stop_reason"] == "byte_limit", "wrong capture boundary")
        evidence = evidence_file.read_bytes()
        require(data["evidence"]["sha256"] == digest(evidence), "evidence hash differs")
        events = [json.loads(line) for line in evidence.splitlines()]
        chunks = [event for event in events if event["event"] == "rtt.chunk"]
        payload = b"".join(bytes.fromhex(event["data"]) for event in chunks)
        require(payload == expected_payload, "lossless RTT payload differs")
        require(data["bytes_captured"] == len(payload), "byte count differs")
        require(data["chunk_count"] == len(chunks), "chunk count differs")
        require(data["payload_sha256"] == digest(payload), "payload hash differs")
        report.update(bytes_captured=len(payload), payload_sha256=digest(payload),
                      evidence_sha256=digest(evidence))

        unsupported = run("unsupported-openocd", [
            "--json", "--backend", "openocd", "rtt", "plan",
        ] + selection, 6)
        require(unsupported["error"]["code"] == "CAPABILITY_UNAVAILABLE", "wrong capability error")
        require(digest(executable.read_bytes()) == expected_hash, "executable changed")
        require(fixture.read_bytes() == fixture_data, "source fixture changed")
        report["ok"] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    write_json(output / "report.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(re.fullmatch(r"[0-9a-fA-F]{64}", args.sha256) is not None, "invalid SHA-256")
        report = check(args.executable, args.sha256.lower(), args.fixture, args.output_dir.resolve())
    except (OSError, ValueError) as error:
        report = {"ok": False, "hardware_access": False, "error": str(error)}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
