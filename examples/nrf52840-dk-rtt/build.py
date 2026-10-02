#!/usr/bin/env python3
"""Build and inspect a code-Flash-only RTT fixture. Never accesses hardware."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
TARGET = "thumbv7em-none-eabihf"
SOURCES = (
    ".cargo/config.toml", "Cargo.lock", "Cargo.toml", "build.py", "build.rs",
    "memory.x", "src/main.rs", "src/ring.rs",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_hex(data: str) -> tuple[list[dict], bytes]:
    image: dict[int, int] = {}
    base = 0
    eof = False
    for line in data.splitlines():
        if not line.startswith(":") or eof:
            raise ValueError("invalid HEX framing or data after EOF")
        record = bytes.fromhex(line[1:])
        if len(record) < 5 or len(record) != record[0] + 5 or sum(record) & 255:
            raise ValueError("invalid HEX checksum/length")
        size, offset, kind = record[0], int.from_bytes(record[1:3], "big"), record[3]
        payload = record[4:-1]
        if kind == 0:
            for index, byte in enumerate(payload):
                address = base + offset + index
                if address >= 0x100000 or address in image:
                    raise ValueError("HEX contains non-code-Flash or duplicate bytes")
                image[address] = byte
        elif kind == 1 and size == 0 and offset == 0:
            eof = True
        elif kind in (2, 4) and size == 2 and offset == 0:
            base = int.from_bytes(payload, "big") << (4 if kind == 2 else 16)
        elif kind in (3, 5) and size == 4 and offset == 0:
            pass
        else:
            raise ValueError("unsupported HEX record")
    if not eof or not image or any(index not in image for index in range(256)):
        raise ValueError("missing EOF/image/vector table")
    stack, reset = struct.unpack("<II", bytes(image[index] for index in range(8)))
    if stack != 0x20040000 or reset & 1 != 1 or (reset & ~1) not in image:
        raise ValueError("invalid Cortex-M stack/reset vector")
    addresses = sorted(image)
    ranges = []
    start = previous = addresses[0]
    for address in addresses[1:]:
        if address != previous + 1:
            ranges.append({"start": start, "length": previous + 1 - start})
            start = address
        previous = address
    ranges.append({"start": start, "length": previous + 1 - start})
    return ranges, bytes(image[address] for address in addresses)


def run(argv: list[str], output: Path, env: dict | None = None) -> str:
    result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    output.write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"{argv[0]} exited {result.returncode}; see {output}")
    return result.stdout.strip()


def build(output: Path) -> dict:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inputs = []
    for name in SOURCES:
        normalized = ROOT.joinpath(name).read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
        inputs.append({"path": name, "normalized_text_sha256": sha(normalized.encode())})
    identity = sha("\n".join(f"{item['path']}={item['normalized_text_sha256']}" for item in inputs).encode())
    env = dict(os.environ, NRF_RTT_BUILD_ID=identity)
    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    if not cargo or not rustc:
        raise RuntimeError("cargo and rustc are required")
    compiler = run([rustc, "-vV"], output / "rustc-version.txt")
    sysroot = Path(run([rustc, "--print", "sysroot"], output / "rustc-sysroot.txt"))
    host = next(line[6:] for line in compiler.splitlines() if line.startswith("host: "))
    llvm = sysroot / "lib" / "rustlib" / host / "bin"
    suffix = ".exe" if os.name == "nt" else ""
    objcopy = llvm / f"llvm-objcopy{suffix}"
    nm = llvm / f"llvm-nm{suffix}"
    readobj = llvm / f"llvm-readobj{suffix}"
    if not all(path.is_file() for path in (objcopy, nm, readobj)):
        raise RuntimeError("installed llvm-tools-preview is required")
    run([cargo, "build", "--release", "--locked", "--offline", "--target", TARGET,
         "--target-dir", str(output / "cargo-target")], output / "cargo-build.log", env)
    elf = output / "nrf52840-dk-rtt.elf"
    firmware = output / "nrf52840-dk-rtt.hex"
    shutil.copyfile(output / "cargo-target" / TARGET / "release" / "nrf52840-dk-rtt", elf)
    run([str(objcopy), "-O", "ihex", str(elf), str(firmware)], output / "objcopy.log")
    symbols = run([str(nm), "--defined-only", "--print-size", str(elf)], output / "symbols.txt")
    run([str(readobj), "--file-headers", "--program-headers", "--sections", str(elf)], output / "elf-layout.txt")
    selected = {}
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[3] in ("_SEGGER_RTT", "EAT_RTT_BUFFER"):
            selected[fields[3]] = {"address": int(fields[0], 16), "size": int(fields[1], 16), "kind": fields[2]}
    for name, expected_size in (("_SEGGER_RTT", 48), ("EAT_RTT_BUFFER", 1024)):
        symbol = selected.get(name, {})
        if symbol.get("size") != expected_size or symbol.get("kind", "").lower() != "b":
            raise ValueError(f"invalid {name} symbol/layout")
        if symbol["address"] % 4 or not 0x20000000 <= symbol["address"] <= 0x20040000 - expected_size:
            raise ValueError(f"{name} is outside aligned RAM")
    cb = selected["_SEGGER_RTT"]["address"]
    ring = selected["EAT_RTT_BUFFER"]["address"]
    if cb < ring + 1024 and ring < cb + 48:
        raise ValueError("RTT metadata and ring overlap")
    ranges, payload = inspect_hex(firmware.read_text(encoding="ascii"))
    if identity.encode() not in elf.read_bytes():
        raise ValueError("build identity absent from ELF")
    manifest = {
        "schema_version": "embedded-debugger.nrf52840-rtt-firmware.v1",
        "board": "Nordic nRF52840 DK onboard target", "target": "nRF52840_xxAA",
        "build_id": identity, "source_files": inputs, "input_normalization": "utf8-lf",
        "build_identity_is_artifact_attestation": False, "compiler": compiler,
        "target_triple": TARGET, "flash_write_ranges": ranges,
        "flash_payload_bytes": len(payload), "flash_payload_sha256": sha(payload),
        "uicr_in_image": False, "hardware_access": False,
        "runtime_effects": {"approtect_software_disable": True, "gpio": False, "uart": False, "ble": False},
        "rtt": {"control_block": f"0x{cb:08X}", "control_block_bytes": 48,
                "buffer": f"0x{ring:08X}", "buffer_bytes": 1024,
                "read_cursor": f"0x{cb + 40:08X}", "up_channels": 1, "down_channels": 0,
                "flags": 0, "heartbeat_nominal_ms": 250, "starts_after_first_consumption": True},
        "symbols": selected,
        "artifacts": {path.suffix[1:]: {"path": str(path), "size": path.stat().st_size, "sha256": sha(path.read_bytes())}
                      for path in (elf, firmware)},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new, non-existing artifact directory")
    args = parser.parse_args()
    try:
        manifest = build(args.output)
    except (OSError, ValueError, RuntimeError, StopIteration) as error:
        print(json.dumps({"ok": False, "hardware_access": False, "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, "hardware_access": False, "manifest": str(args.output.resolve() / "manifest.json"),
                      "build_id": manifest["build_id"], "rtt": manifest["rtt"], "artifacts": manifest["artifacts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
