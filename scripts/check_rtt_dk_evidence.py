#!/usr/bin/env python3
"""Evaluate existing native DK RTT evidence offline; never runs an executable."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
PROBE = "1366:1061:001050275757"
SCHEMA = "embedded-debugger.rtt-evidence.v1"
READY = "EAT_NRF52840_DK_RTT_READY v1"
BUILD = "EAT_NRF52840_DK_RTT_BUILD_ID v1 "


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def evaluate(manifest: dict, plan: dict, report: dict, evidence: bytes) -> dict:
    require(manifest["schema_version"] == "embedded-debugger.nrf52840-rtt-firmware.v1", "wrong firmware manifest schema")
    require(plan["ok"] is True and report["ok"] is True, "native command failed")
    require(plan["operation"] == "rtt.plan" and report["operation"] == "rtt.capture", "wrong native operation")
    expected = plan["data"]
    result = report["data"]
    require(result["schema_version"] == "embedded-debugger.rtt-capture.v1", "wrong capture schema")
    require(result["plan"] == expected and expected["backend"] == "probe-rs", "capture plan/backend mismatch")
    require(expected["probe_id"] == PROBE and expected["target"]["name"] == "nRF52840_xxAA", "wrong planned board")
    require(result["session"]["probe"]["id"] == PROBE and result["session"]["target"]["name"] == "nRF52840_xxAA", "wrong attached board")
    require(expected["tool_version"] == "0.2.4", "wrong RTT candidate version")
    require(expected["selection"] == {"core": 0, "channel": 0, "control_block": manifest["rtt"]["control_block"]}, "wrong selected symbol/core/channel")
    require(expected["limits"] == {"duration_ms": 10000, "maximum_bytes": 65536, "poll_interval_ms": 50}, "wrong capture limits")
    require(all(result[key] is True for key in ("complete", "channel_stopped", "disconnected", "hardware_access")), "incomplete native capture/cleanup")
    require(result["stop_reason"] == "duration_limit", "unexpected capture stop reason")
    require(result["evidence"]["sha256"] == sha(evidence) and result["evidence"]["size"] == len(evidence), "evidence hash/size mismatch")
    channel = result["channel"]
    require(channel["selection"] == expected["selection"], "wrong channel selection")
    require(channel["buffer_start"] == manifest["rtt"]["buffer"] and channel["buffer_size"] == 1024, "wrong ring")
    require(channel["read_cursor_address"] == manifest["rtt"]["read_cursor"] and channel["flags"] == 0 and channel["control_block_bytes"] == 48, "wrong descriptor")
    records = [json.loads(line) for line in evidence.splitlines()]
    require(len(records) >= 4, "missing evidence records")
    require(records[0]["event"] == "capture.started" and records[0]["plan"] == expected, "wrong start record")
    require(records[1]["event"] == "rtt.channel" and records[1]["channel"] == channel, "wrong channel record")
    require(records[-1]["event"] == "capture.finished" and records[-1]["ok"] is True, "missing successful finish")
    payload = bytearray()
    sequence = 0
    previous_ms = -1
    for record in records:
        require(record["schema_version"] == SCHEMA and record["capture_id"] == result["capture_id"], "wrong evidence identity")
        instant = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
        require(instant.utcoffset() is not None, "timestamp lacks timezone")
        require(record["elapsed_ms"] >= previous_ms, "non-monotonic elapsed time")
        # UTC is recorded for correlation; wall-clock adjustment is not a failure.
        previous_ms = record["elapsed_ms"]
    for record in records[2:-1]:
        require(record["event"] == "rtt.chunk" and record["encoding"] == "hex", "unexpected evidence record")
        chunk = bytes.fromhex(record["data"])
        require(0 < len(chunk) <= 4096 and len(chunk) == record["length"], "bad chunk length")
        require(record["sequence"] == sequence and record["cursor"] == len(payload), "chunk sequence/cursor gap")
        payload.extend(chunk)
        require(record["next_cursor"] == len(payload), "bad next cursor")
        sequence += 1
    require(sequence <= 4096, "too many chunks")
    finish = records[-1]
    for key, value in (("bytes_captured", len(payload)), ("chunk_count", sequence), ("next_cursor", len(payload)), ("payload_sha256", sha(payload)), ("stop_reason", "duration_limit")):
        require(result[key] == value and finish[key] == value, f"capture/finish mismatch: {key}")
    require(finish["cleanup"]["channel_stopped"] is True and finish["cleanup"]["disconnected"] is True, "finish cleanup failed")
    require(finish["cleanup"]["stop_error"] is None and finish["cleanup"]["disconnect_error"] is None, "finish cleanup contains errors")
    require(len(payload) > 3 * 1024, "insufficient payload to exercise repeated ring reuse")
    text = payload.decode("ascii")
    banner = READY + "\r\n" + BUILD + manifest["build_id"] + "\r\n"
    require(text.startswith(banner), "missing initial ready/build banner")
    index = len(banner)
    heartbeat_count = 0
    while index < len(text):
        number = heartbeat_count + 1
        frame = banner + f"EAT_NRF52840_DK_RTT_HEARTBEAT {number:08X} SKIPPED=00000000\r\n"
        remaining = text[index:]
        if len(remaining) < len(frame):
            require(frame.startswith(remaining), "invalid partial frame/build/sequence/skipped count")
            break
        require(remaining.startswith(frame), "unexpected frame/build/sequence/skipped count")
        index += len(frame)
        heartbeat_count += 1
    require(heartbeat_count >= 3, "less than three complete heartbeats")
    tail = text.rsplit("\r\n", 1)[-1]
    return {"schema_version": "embedded-debugger.nrf52840-rtt-acceptance.v1", "ok": True,
            "scope": "host_only_evidence_evaluation", "hardware_access": False, "executables_started": False,
            "build_id": manifest["build_id"], "identity_count": text.count(banner), "heartbeat_count": heartbeat_count,
            "first_heartbeat": 1, "last_heartbeat": heartbeat_count, "bytes_captured": len(payload),
            "payload_sha256": sha(payload), "evidence_sha256": sha(evidence), "chunk_count": sequence,
            "partial_tail_bytes": len(tail), "runtime_source_identity_observed": True,
            "runtime_identity_is_artifact_attestation": False, "post_disconnect_core_state_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("manifest", "plan", "report", "evidence"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest, plan, report = (json.loads(getattr(args, name).read_text(encoding="utf-8-sig")) for name in ("manifest", "plan", "report"))
        for artifact in manifest["artifacts"].values():
            data = Path(artifact["path"]).read_bytes()
            require(sha(data) == artifact["sha256"] and len(data) == artifact["size"], "firmware artifact changed")
        require(Path(report["data"]["evidence"]["path"]).resolve() == args.evidence.resolve(), "wrong evidence path")
        result = evaluate(manifest, plan, report, args.evidence.read_bytes())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
        print(json.dumps({"ok": False, "hardware_access": False, "executables_started": False, "error": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
