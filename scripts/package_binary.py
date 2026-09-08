#!/usr/bin/env python3
"""Build or verify an unsigned Windows CLI candidate; never access hardware."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

if __package__:
    from . import license_materials
else:
    import license_materials

NAME = "embedded-debugger"
TARGET = "x86_64-pc-windows-msvc"
SCHEMA = "embedded-debugger.binary-release.v3"
LICENSE_SCHEMA = "embedded-debugger.binary-release.v2"
LEGACY_SCHEMA = "embedded-debugger.binary-release.v1"
LEGACY_PAYLOAD_NAMES = (
    "Cargo.lock",
    "DEPENDENCIES.json",
    "LICENSE",
    "README.md",
    "embedded-debugger.exe",
)
PAYLOAD_NAMES = (
    *LEGACY_PAYLOAD_NAMES,
    "THIRD_PARTY_LICENSES.json",
    "THIRD_PARTY_NOTICES.txt",
    "THIRD_PARTY_SOURCES.zip",
    "Test-WindowsCandidate.ps1",
    "WINDOWS_RUNTIME.md",
)
MANIFEST_NAME = "release-manifest.json"
MAX_FILE = 128 * 1024 * 1024
MAX_METADATA = 4 * 1024 * 1024
MAX_ARCHIVE = MAX_FILE + 8 * MAX_METADATA
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
HASH = re.compile(r"[0-9a-f]{64}")
CRT_CONFIG = b'[target.x86_64-pc-windows-msvc]\nrustflags = ["-C", "target-feature=+crt-static"]\n'
FORBIDDEN_CRT_IMPORTS = (
    "vcruntime",
    "msvcp",
    "ucrtbase.dll",
    "api-ms-win-crt-",
)


class ReleaseError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes) -> object:
    def reject_constant(value: str) -> None:
        raise ReleaseError(f"non-JSON numeric constant: {value}")

    return json.loads(
        data, object_pairs_hook=unique_object, parse_constant=reject_constant
    )


def bounded_read(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"expected a regular non-symlink file: {path}")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ReleaseError(f"file exceeds {limit} bytes: {path}")
    return data


def run(root: Path, args: list[str], timeout: int | None = 60) -> bytes:
    result = subprocess.run(
        args, cwd=root, capture_output=True, timeout=timeout, check=False
    )
    if result.stderr:
        sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
    if result.returncode:
        raise ReleaseError(f"{args[0]} failed with exit code {result.returncode}")
    return result.stdout


def clean_revision(root: Path) -> str:
    if run(root, ["git", "status", "--porcelain", "--untracked-files=normal"]).strip():
        raise ReleaseError("build requires a clean committed worktree")
    revision = run(root, ["git", "rev-parse", "HEAD"]).decode("ascii").strip()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ReleaseError("invalid source revision")
    return revision


def git_file(root: Path, revision: str, name: str) -> bytes:
    data = run(root, ["git", "show", f"{revision}:{name}"])
    if len(data) > MAX_METADATA:
        raise ReleaseError(f"source document too large: {name}")
    return data


def dependency_inventory(metadata: dict, lockfile: bytes) -> bytes:
    lock = tomllib.loads(lockfile.decode("utf-8"))
    locked = {
        (item["name"], item["version"], item.get("source")): item.get("checksum")
        for item in lock["package"]
    }
    packages = []
    for package in metadata["packages"]:
        source = package.get("source")
        key = (package["name"], package["version"], source)
        if key not in locked:
            raise ReleaseError("Cargo metadata does not match the pinned lockfile")
        packages.append(
            {
                "name": package["name"],
                "version": package["version"],
                "license_expression": package.get("license"),
                "has_license_file": bool(package.get("license_file")),
                "source_kind": source.split("+", 1)[0] if source else "local",
                "registry_checksum": locked[key],
            }
        )
    packages.sort(
        key=lambda item: (
            item["name"],
            item["version"],
            item["source_kind"],
            item["registry_checksum"] or "",
        )
    )
    return json_bytes(
        {
            "schema_version": "embedded-debugger.dependencies.v1",
            "scope": "target_filtered_cargo_metadata_including_build_and_dev_dependencies",
            "target": TARGET,
            "runtime_sbom": False,
            "license_compliance_verified": False,
            "cargo_lock_sha256": sha256(lockfile),
            "packages": packages,
        }
    )


def pe_imports(data: bytes) -> list[str]:
    """Return direct PE32+ imports without loading or executing the image."""

    def unpack(offset: int, pattern: str) -> tuple:
        size = struct.calcsize(pattern)
        if offset < 0 or offset + size > len(data):
            raise ReleaseError("truncated PE executable")
        return struct.unpack_from(pattern, data, offset)

    if len(data) < 64 or data[:2] != b"MZ":
        raise ReleaseError("executable is not a PE image")
    pe_offset = unpack(0x3C, "<I")[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ReleaseError("invalid PE signature")
    section_count = unpack(pe_offset + 6, "<H")[0]
    optional_size = unpack(pe_offset + 20, "<H")[0]
    optional = pe_offset + 24
    if optional_size < 128 or optional + optional_size > len(data):
        raise ReleaseError("invalid PE optional header")
    if unpack(optional, "<H")[0] != 0x20B:
        raise ReleaseError("expected a PE32+ executable")
    directory_count = unpack(optional + 108, "<I")[0]
    if directory_count < 2:
        raise ReleaseError("PE image has no import directory")
    import_rva, import_size = unpack(optional + 120, "<II")
    if not import_rva or import_size < 20:
        raise ReleaseError("PE image has an empty import directory")

    sections = []
    section_table = optional + optional_size
    for index in range(section_count):
        offset = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = unpack(
            offset + 8, "<IIII"
        )
        sections.append(
            (virtual_address, max(virtual_size, raw_size), raw_offset, raw_size)
        )

    def rva_offset(rva: int) -> int:
        for virtual_address, span, raw_offset, raw_size in sections:
            relative = rva - virtual_address
            if 0 <= relative < span and relative < raw_size:
                offset = raw_offset + relative
                if offset < len(data):
                    return offset
        raise ReleaseError("PE import RVA is outside file-backed sections")

    imports = []
    descriptor = rva_offset(import_rva)
    descriptor_limit = min(len(data), descriptor + import_size)
    while descriptor + 20 <= descriptor_limit:
        fields = unpack(descriptor, "<IIIII")
        if fields == (0, 0, 0, 0, 0):
            if not imports:
                raise ReleaseError("PE image has no imported libraries")
            return imports
        name_offset = rva_offset(fields[3])
        end = data.find(b"\0", name_offset, min(len(data), name_offset + 260))
        if end < 0:
            raise ReleaseError("unterminated PE import name")
        try:
            name = data[name_offset:end].decode("ascii").lower()
        except UnicodeDecodeError as error:
            raise ReleaseError("non-ASCII PE import name") from error
        if not name or name in imports:
            raise ReleaseError("empty or duplicate PE import name")
        imports.append(name)
        descriptor += 20
    raise ReleaseError("unterminated PE import directory")


def enforce_static_windows_crt(data: bytes) -> list[str]:
    imports = pe_imports(data)
    forbidden = [
        name
        for name in imports
        if any(token in name for token in FORBIDDEN_CRT_IMPORTS)
    ]
    if forbidden:
        raise ReleaseError(
            "dynamic Windows CRT imports are forbidden: " + ", ".join(forbidden)
        )
    return imports


def archive_bytes(payload: dict[str, bytes], build: dict) -> bytes:
    if set(payload) != set(PAYLOAD_NAMES):
        raise ReleaseError("unexpected payload inventory")
    manifest = {
        **build,
        "schema_version": SCHEMA,
        "product": NAME,
        "publication": "unsigned_local_candidate",
        "files": [],
    }
    for name, data in sorted(payload.items()):
        limit = MAX_FILE if name.endswith(".exe") else MAX_METADATA
        if not data or len(data) > limit:
            raise ReleaseError(f"empty or oversized payload: {name}")
        manifest["files"].append(
            {"path": name, "size": len(data), "sha256": sha256(data)}
        )
    members = {**payload, MANIFEST_NAME: json_bytes(manifest)}
    folder = f"{NAME}-{build['version']}-{build['target']}"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(members.items()):
            entry = zipfile.ZipInfo(f"{folder}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, data)
    return output.getvalue()


def inspect_archive(data: bytes) -> dict:
    if len(data) > MAX_ARCHIVE:
        raise ReleaseError("archive exceeds the size limit")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) not in {len(PAYLOAD_NAMES) + 1, len(LEGACY_PAYLOAD_NAMES) + 1}:
            raise ReleaseError("unexpected archive member count")
        names = [entry.filename for entry in entries]
        manifest_entries = [
            name for name in names if name.endswith("/" + MANIFEST_NAME)
        ]
        if len(manifest_entries) != 1 or len(names) != len(set(names)):
            raise ReleaseError("missing or duplicate archive members")
        manifest_entry = archive.getinfo(manifest_entries[0])
        if manifest_entry.file_size > MAX_METADATA:
            raise ReleaseError("oversized release manifest")
        for entry in entries:
            if (
                entry.orig_filename != entry.filename
                or entry.compress_type != zipfile.ZIP_STORED
                or entry.flag_bits & 1
                or stat.S_IFMT(entry.external_attr >> 16) != stat.S_IFREG
                or entry.is_dir()
                or entry.file_size > MAX_FILE
            ):
                raise ReleaseError("unsupported archive entry")
        manifest = parse_json(archive.read(manifest_entry))
        if not isinstance(manifest, dict):
            raise ReleaseError("release manifest must be an object")
        schema = manifest.get("schema_version")
        payload_names = (
            LEGACY_PAYLOAD_NAMES if schema == LEGACY_SCHEMA else PAYLOAD_NAMES
        )
        expected_fields = {
            "schema_version",
            "product",
            "publication",
            "files",
            "version",
            "target",
            "source_revision",
            "rustc",
            "cargo",
            "build_profile",
        }
        if schema == SCHEMA:
            expected_fields.add("windows_crt_linkage")
        if set(manifest) != expected_fields:
            raise ReleaseError("unexpected release manifest fields")
        if manifest["build_profile"] != "release" or any(
            not isinstance(manifest[key], str) or not 0 < len(manifest[key]) <= 4096
            for key in ("rustc", "cargo")
        ):
            raise ReleaseError("invalid build metadata")
        version = manifest.get("version")
        if (
            not isinstance(schema, str)
            or schema not in {SCHEMA, LICENSE_SCHEMA, LEGACY_SCHEMA}
            or manifest.get("product") != NAME
            or manifest.get("target") != TARGET
            or manifest.get("publication") != "unsigned_local_candidate"
            or not isinstance(version, str)
            or not VERSION.fullmatch(version)
            or not isinstance(manifest.get("source_revision"), str)
            or not re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})", manifest["source_revision"]
            )
        ):
            raise ReleaseError("unsupported release identity")
        if schema == SCHEMA and manifest["windows_crt_linkage"] != "static":
            raise ReleaseError("unsupported Windows CRT linkage")
        folder = f"{NAME}-{version}-{TARGET}"
        expected = {f"{folder}/{name}" for name in (*payload_names, MANIFEST_NAME)}
        if set(names) != expected:
            raise ReleaseError("archive paths do not match the fixed release layout")
        files = manifest.get("files")
        if not isinstance(files, list) or len(files) != len(payload_names):
            raise ReleaseError("invalid manifest inventory")
        seen = set()
        for item in files:
            if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
                raise ReleaseError("invalid manifest file record")
            name = item["path"]
            if not isinstance(name, str) or name not in payload_names or name in seen:
                raise ReleaseError("unknown or duplicate payload path")
            seen.add(name)
            entry = archive.getinfo(f"{folder}/{name}")
            limit = MAX_FILE if name.endswith(".exe") else MAX_METADATA
            if (
                type(item["size"]) is not int
                or not 0 < item["size"] <= limit
                or item["size"] != entry.file_size
                or not isinstance(item["sha256"], str)
                or not HASH.fullmatch(item["sha256"])
                or sha256(archive.read(entry)) != item["sha256"]
            ):
                raise ReleaseError(f"payload integrity failure: {name}")
        return manifest


def verify(archive: Path, checksum: Path) -> dict:
    data = bounded_read(archive, MAX_ARCHIVE)
    expected = f"{sha256(data)}  {archive.name}\n".encode("ascii")
    if bounded_read(checksum, 1024) != expected:
        raise ReleaseError("archive checksum or checksum filename binding differs")
    manifest = inspect_archive(data)
    return {
        "version": manifest["version"],
        "target": manifest["target"],
        "source_revision": manifest["source_revision"],
        "sha256": sha256(data),
        "file_count": len(manifest["files"]) + 1,
        "integrity_verified": True,
        "publisher_authenticity_verified": False,
        "executable_started": False,
        "archive_schema_version": manifest["schema_version"],
        "license_materials_present": manifest["schema_version"] != LEGACY_SCHEMA,
        "windows_crt_linkage": manifest.get("windows_crt_linkage", "unspecified"),
    }


def build(root: Path, output_dir: Path, offline: bool, cargo_about: Path) -> dict:
    revision = clean_revision(root)
    if git_file(root, revision, ".cargo/config.toml") != CRT_CONFIG:
        raise ReleaseError("committed Windows static CRT configuration differs")
    package = tomllib.loads(git_file(root, revision, "Cargo.toml").decode("utf-8"))[
        "package"
    ]
    version = package["version"]
    if package["name"] != NAME or not VERSION.fullmatch(version):
        raise ReleaseError("expected an embedded-debugger X.Y.Z release")
    rustc = run(root, ["rustc", "-vV"]).decode("utf-8").strip()
    if f"host: {TARGET}" not in rustc.splitlines():
        raise ReleaseError(f"native packaging currently requires {TARGET}")
    cargo_version = run(root, ["cargo", "--version"]).decode("utf-8").strip()
    flags = ["--locked", *(["--offline"] if offline else [])]
    metadata = parse_json(
        run(
            root,
            [
                "cargo",
                "metadata",
                *flags,
                "--filter-platform",
                TARGET,
                "--format-version",
                "1",
            ],
        )
    )
    root_id = metadata["resolve"]["root"]
    root_package = next(item for item in metadata["packages"] if item["id"] == root_id)
    if root_package["name"] != NAME or root_package["version"] != version:
        raise ReleaseError("Cargo root package differs from the committed manifest")
    folder = f"{NAME}-{version}-{TARGET}"
    output = output_dir / f"{folder}.zip"
    checksum = output.with_suffix(".zip.sha256")
    if (
        output.exists()
        or output.is_symlink()
        or checksum.exists()
        or checksum.is_symlink()
    ):
        raise ReleaseError(
            "release output already exists; choose a new output directory"
        )
    about_executable = cargo_about.resolve()
    about_binary = bounded_read(about_executable, MAX_FILE)
    about_version = (
        run(root, [str(about_executable), "--version"]).decode("utf-8").strip()
    )
    if about_version != license_materials.ABOUT_VERSION:
        raise ReleaseError(
            f"license collection requires {license_materials.ABOUT_VERSION}"
        )
    about_config = git_file(root, revision, "about.toml")
    # cargo-about rejects redirected stdout on Windows; use its output-file API.
    with tempfile.TemporaryDirectory(prefix="embedded-debugger-licenses-") as temporary:
        about_output = Path(temporary) / "licenses.json"
        run(
            root,
            [
                str(about_executable),
                "generate",
                "--frozen",
                "--fail",
                "--format",
                "json",
                "--config",
                str(root / "about.toml"),
                "--output-file",
                str(about_output),
            ],
            timeout=300,
        )
        about_report = license_materials.parse_about_report(
            bounded_read(about_output, MAX_FILE)
        )
    if bounded_read(about_executable, MAX_FILE) != about_binary:
        raise ReleaseError("cargo-about executable changed during collection")
    build_output = run(
        root,
        [
            "cargo",
            "build",
            *flags,
            "--release",
            "--bin",
            NAME,
            "--target",
            TARGET,
            "--message-format=json",
        ],
        timeout=None,
    )
    artifacts = [parse_json(line) for line in build_output.splitlines() if line.strip()]
    binaries = [
        Path(item["executable"])
        for item in artifacts
        if item.get("reason") == "compiler-artifact"
        and item.get("package_id") == root_id
        and item.get("target", {}).get("kind") == ["bin"]
        and item.get("target", {}).get("name") == NAME
        and item.get("executable")
    ]
    if len(binaries) != 1:
        raise ReleaseError("Cargo did not report one exact executable artifact")
    binary = binaries[0]
    binary_data = bounded_read(binary, MAX_FILE)
    enforce_static_windows_crt(binary_data)
    if (
        run(root, [str(binary), "--version"]).decode("utf-8").strip()
        != f"{NAME} {version}"
    ):
        raise ReleaseError("built executable version differs from the source")
    if bounded_read(binary, MAX_FILE) != binary_data:
        raise ReleaseError("source or executable changed during packaging")
    lockfile = git_file(root, revision, "Cargo.lock")
    payload = {
        "embedded-debugger.exe": binary_data,
        "LICENSE": git_file(root, revision, "LICENSE"),
        "README.md": git_file(root, revision, "docs/binary-release.md"),
        "Cargo.lock": lockfile,
        "DEPENDENCIES.json": dependency_inventory(metadata, lockfile),
        "Test-WindowsCandidate.ps1": git_file(
            root, revision, "scripts/test_windows_candidate.ps1"
        ),
        "WINDOWS_RUNTIME.md": git_file(root, revision, "docs/windows-runtime.md"),
    }
    payload.update(
        license_materials.collect(
            metadata,
            lockfile,
            about_report,
            {
                item["package_id"]
                for item in artifacts
                if item.get("reason") == "compiler-artifact"
            },
            {
                "version": about_version,
                "executable_sha256": sha256(about_binary),
                "network_access": False,
            },
            about_config,
            git_file(root, revision, "licenses/upstream-supplements.json"),
        )
    )
    if (
        clean_revision(root) != revision
        or bounded_read(binary, MAX_FILE) != binary_data
    ):
        raise ReleaseError("source or executable changed during packaging")
    data = archive_bytes(
        payload,
        {
            "version": version,
            "target": TARGET,
            "source_revision": revision,
            "rustc": rustc,
            "cargo": cargo_version,
            "build_profile": "release",
            "windows_crt_linkage": "static",
        },
    )
    inspect_archive(data)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Exclusive writes never replace a previously generated candidate.
    with output.open("xb") as stream:
        stream.write(data)
    with checksum.open("xb") as stream:
        stream.write(f"{sha256(data)}  {output.name}\n".encode("ascii"))
    return {
        "archive": str(output.resolve()),
        "checksum": str(checksum.resolve()),
        "sha256": sha256(data),
        "binary_sha256": sha256(binary_data),
        "source_revision": revision,
        "version": version,
        "target": TARGET,
        "size": len(data),
        "file_count": len(payload) + 1,
        "windows_crt_linkage": "static",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    builder = commands.add_parser("build")
    builder.add_argument("--output-dir", type=Path, default=Path("target/binary-dist"))
    builder.add_argument("--offline", action="store_true")
    builder.add_argument(
        "--cargo-about",
        type=Path,
        required=True,
        help="exact trusted cargo-about 0.9.2 executable (never installed automatically)",
    )
    builder.add_argument("--json", action="store_true")
    verifier = commands.add_parser("verify")
    verifier.add_argument("archive", type=Path)
    verifier.add_argument("--checksum", type=Path, required=True)
    verifier.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        if args.operation == "build":
            result = build(
                Path(__file__).resolve().parent.parent,
                args.output_dir,
                args.offline,
                args.cargo_about,
            )
        else:
            result = verify(args.archive, args.checksum)
        report = {
            "schema_version": SCHEMA,
            "ok": True,
            "operation": args.operation,
            "hardware_access": False,
            "data": result,
        }
    except (
        ReleaseError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        StopIteration,
        subprocess.SubprocessError,
        zipfile.BadZipFile,
        tarfile.TarError,
        UnicodeError,
    ) as error:
        report = {
            "schema_version": SCHEMA,
            "ok": False,
            "operation": args.operation,
            "hardware_access": False,
            "error": str(error),
        }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif report["ok"]:
        print(json.dumps(report["data"], indent=2, sort_keys=True))
    else:
        print(report["error"], file=sys.stderr)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
