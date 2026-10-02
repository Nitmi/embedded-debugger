"""Offline tests: all native-looking evidence below is explicitly synthetic."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import unittest

from scripts import check_rtt_dk_evidence as checker

ROOT = Path(__file__).resolve().parents[1]
builder = runpy.run_path(str(ROOT / "examples/nrf52840-dk-rtt/build.py"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def record(kind, data=b"", offset=0):
    raw = bytes([len(data)]) + offset.to_bytes(2, "big") + bytes([kind]) + data
    return ":" + (raw + bytes([-sum(raw) & 255])).hex().upper()


class HexInspectionTests(unittest.TestCase):
    def image(self, start_record=3):
        vector = bytearray(256)
        vector[:8] = bytes.fromhex("0000042001010000")
        records = [record(0, bytes(vector[index:index + 16]), index) for index in range(0, 256, 16)]
        records += [record(0, b"\xFE\xE7", 256), record(start_record, b"\x00\x00\x01\x01"), record(1)]
        return "\n".join(records)

    def test_code_image_and_both_entry_record_types(self):
        for kind in (3, 5):
            ranges, data = builder["inspect_hex"](self.image(kind))
            self.assertEqual(ranges, [{"start": 0, "length": 258}])
            self.assertEqual(len(data), 258)

    def test_uicr_duplicate_and_invalid_checksum_fail(self):
        image = self.image().splitlines()
        for extra in ([record(4, b"\x10\x00"), record(0, b"\x5A", 0x1208)], [image[0]], [image[0][:-2] + "01"]):
            with self.assertRaises(ValueError):
                builder["inspect_hex"]("\n".join(image[:-1] + extra + [image[-1]]))


class RttEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "schema_version": "embedded-debugger.nrf52840-rtt-firmware.v1",
            "build_id": "a" * 64,
            "rtt": {"control_block": "0x20000000", "buffer": "0x20000030", "read_cursor": "0x20000028"},
        }
        selection = {"core": 0, "channel": 0, "control_block": "0x20000000"}
        self.plan = {"ok": True, "operation": "rtt.plan", "data": {
            "backend": "probe-rs", "probe_id": checker.PROBE, "target": {"name": "nRF52840_xxAA"},
            "tool_version": "0.2.4", "selection": selection,
            "limits": {"duration_ms": 10000, "maximum_bytes": 65536, "poll_interval_ms": 50},
        }}
        self.channel = {"selection": selection, "buffer_start": "0x20000030", "buffer_size": 1024,
                        "read_cursor_address": "0x20000028", "flags": 0, "control_block_bytes": 48}
        self.banner = checker.READY + "\r\n" + checker.BUILD + "a" * 64 + "\r\n"
        self.payload = (self.banner + "".join(self.frame(number) for number in range(1, 21))).encode()

    def frame(self, number):
        return self.banner + f"EAT_NRF52840_DK_RTT_HEARTBEAT {number:08X} SKIPPED=00000000\r\n"

    def evidence(self, payload=None):
        payload = self.payload if payload is None else payload
        common = {"schema_version": checker.SCHEMA, "capture_id": "synthetic-only",
                  "timestamp": "2026-10-02T00:00:00.000Z", "elapsed_ms": 0}
        records = [dict(common, event="capture.started", plan=self.plan["data"]),
                   dict(common, event="rtt.channel", channel=self.channel)]
        for sequence, index in enumerate(range(0, len(payload), 13)):
            chunk = payload[index:index + 13]
            records.append(dict(common, event="rtt.chunk", encoding="hex", data=chunk.hex(), length=len(chunk),
                                sequence=sequence, cursor=index, next_cursor=index + len(chunk)))
        values = {"stop_reason": "duration_limit", "bytes_captured": len(payload), "chunk_count": len(records) - 2,
                  "next_cursor": len(payload), "payload_sha256": sha(payload)}
        records.append(dict(common, event="capture.finished", ok=True, **values,
                            cleanup={"channel_stopped": True, "disconnected": True, "stop_error": None, "disconnect_error": None}))
        data = ("\n".join(json.dumps(item) for item in records) + "\n").encode()
        report = {"ok": True, "operation": "rtt.capture", "data": dict(
            schema_version="embedded-debugger.rtt-capture.v1", plan=self.plan["data"], channel=self.channel,
            session={"probe": {"id": checker.PROBE}, "target": {"name": "nRF52840_xxAA"}},
            capture_id="synthetic-only", complete=True, channel_stopped=True, disconnected=True, hardware_access=True,
            evidence={"size": len(data), "sha256": sha(data)}, **values)}
        return report, data

    def evaluate(self, payload=None):
        report, data = self.evidence(payload)
        return checker.evaluate(self.manifest, self.plan, report, data)

    def test_split_chunks_reconstruct_exact_telemetry(self):
        result = self.evaluate()
        self.assertEqual(result["heartbeat_count"], 20)
        self.assertEqual(result["payload_sha256"], sha(self.payload))
        self.assertFalse(result["hardware_access"])
        self.assertFalse(result["executables_started"])

    def test_every_valid_partial_frame_is_excluded_from_heartbeat_count(self):
        for end in range(1, len(self.frame(21))):
            result = self.evaluate(self.payload + self.frame(21)[:end].encode())
            self.assertEqual(result["heartbeat_count"], 20)

    def test_old_build_sequence_gap_skip_and_arbitrary_tail_fail(self):
        corruptions = (
            self.payload.replace(b"a" * 64, b"b" * 64, 1),
            self.payload.replace(b"00000002 SKIPPED", b"00000003 SKIPPED", 1),
            self.payload.replace(b"SKIPPED=00000000", b"SKIPPED=00000001", 1),
            self.payload + b"OLD_HEARTBEAT",
        )
        for data in corruptions:
            with self.assertRaises(ValueError):
                self.evaluate(data)

    def test_hash_cleanup_and_plan_mismatch_fail(self):
        report, data = self.evidence()
        for key, value in (("disconnected", False), ("plan", {}), ("payload_sha256", "b" * 64)):
            changed = copy.deepcopy(report)
            changed["data"][key] = value
            with self.assertRaises(ValueError):
                checker.evaluate(self.manifest, self.plan, changed, data)
        with self.assertRaises(ValueError):
            checker.evaluate(self.manifest, self.plan, report, data + b" ")


if __name__ == "__main__":
    unittest.main()
