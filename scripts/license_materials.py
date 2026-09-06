"""Collect candidate notices from cargo-about and locked local crate archives."""

from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ABOUT_VERSION = "cargo-about 0.9.2"
MAX_CRATE = 32 * 1024 * 1024
MAX_EXPANDED_CRATE = 128 * 1024 * 1024
MAX_DOCUMENT = 1024 * 1024
MAX_MATERIALS = 4 * 1024 * 1024
DOCUMENT_NAME = re.compile(
    r"^(licen[cs]e|copying|notice|copyright|authors)(?:[._-].*)?$", re.IGNORECASE
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def read_file(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular license input: {path}")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError(f"empty or oversized license input: {path}")
    return data


def crate_materials(package: dict, checksum: str) -> tuple[bytes, list[dict]]:
    """Read registry archives without extracting or trusting mutable source copies."""
    if package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
        raise ValueError("license collection currently requires crates.io dependencies")
    name = package["name"]
    version = package["version"]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(
        r"[0-9A-Za-z.+-]+", version
    ):
        raise ValueError("invalid registry package identity")
    crate_root = Path(package["manifest_path"]).parent
    folder = f"{name}-{version}"
    if crate_root.name != folder or crate_root.parent.parent.name != "src":
        raise ValueError("unsupported Cargo registry cache layout")
    archive_path = (
        crate_root.parent.parent.parent
        / "cache"
        / crate_root.parent.name
        / f"{folder}.crate"
    )
    data = read_file(archive_path, MAX_CRATE)
    if digest(data) != checksum:
        raise ValueError(f"locked crate checksum mismatch: {folder}")
    license_file = package.get("license_file")
    if license_file and Path(license_file).is_absolute():
        license_file = Path(license_file).relative_to(crate_root).as_posix()
    documents = []
    seen = set()
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for count, member in enumerate(archive, 1):
            path = PurePosixPath(member.name)
            if (
                count > 20000
                or "\\" in member.name
                or ":" in member.name
                or "\x00" in member.name
                or path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] != folder
                or member.name in seen
            ):
                raise ValueError(f"invalid registry archive layout: {folder}")
            seen.add(member.name)
            expanded += member.size
            if expanded > MAX_EXPANDED_CRATE:
                raise ValueError(f"oversized expanded crate: {folder}")
            if member.isdir():
                continue
            relative = str(PurePosixPath(*path.parts[1:]))
            if not (
                DOCUMENT_NAME.fullmatch(path.name)
                or any(
                    part.lower() in {"licenses", "licences"}
                    for part in path.parts[1:-1]
                )
                or relative == license_file
            ):
                continue
            if not member.isfile() or not 0 < member.size <= MAX_DOCUMENT:
                raise ValueError(f"invalid license document: {folder}/{relative}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("unreadable license archive member")
            with stream:
                content = stream.read(MAX_DOCUMENT + 1)
            if len(content) != member.size:
                raise ValueError("license archive member size mismatch")
            documents.append(
                {
                    "path": relative,
                    "sha256": digest(content),
                    "text": content.decode("utf-8"),
                }
            )
    return data, sorted(documents, key=lambda item: item["path"])


def sources_zip(sources: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(sources.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, content)
    return output.getvalue()


def collect(
    metadata: dict,
    lockfile: bytes,
    about: dict,
    artifact_ids: set[str],
    tool: dict,
    config: bytes,
) -> dict[str, bytes]:
    packages = {item["id"]: item for item in metadata["packages"]}
    root_id = metadata["resolve"]["root"]
    locked = {
        (item["name"], item["version"], item.get("source")): item.get("checksum")
        for item in tomllib.loads(lockfile.decode("utf-8"))["package"]
    }
    selected: dict[str, set[str]] = {}
    declarations = {}
    defaults: set[str] = set()
    licenses = []
    for license in about["licenses"]:
        used_by = []
        license_id = license["id"]
        text = license["text"]
        if (
            not isinstance(license_id, str)
            or not re.fullmatch(r"[A-Za-z0-9.+-]+", license_id)
            or not isinstance(text, str)
            or not text.strip()
        ):
            raise ValueError("invalid cargo-about license record")
        for usage in license["used_by"]:
            crate = usage["crate"]
            package_id = crate["id"]
            if package_id not in packages or any(
                crate[key] != packages[package_id][key]
                for key in ("name", "version", "source")
            ):
                raise ValueError("cargo-about package differs from Cargo metadata")
            # cargo-about normalizes legacy Cargo expressions such as MIT/Apache-2.0.
            declaration = crate["license"]
            if not isinstance(declaration, str) or not declaration.strip():
                raise ValueError("missing cargo-about license declaration")
            if package_id in declarations and declarations[package_id] != declaration:
                raise ValueError("inconsistent cargo-about license declarations")
            declarations[package_id] = declaration
            selected.setdefault(package_id, set()).add(license_id)
            if package_id == root_id:
                continue
            if not license.get("source_path"):
                defaults.add(package_id)
            used_by.append(f"{crate['name']}@{crate['version']}")
        if used_by:
            licenses.append(
                {
                    "id": license_id,
                    "text": text,
                    "sha256": digest(text.encode("utf-8")),
                    "text_origin": "cargo_about_local_file"
                    if license.get("source_path")
                    else "cargo_about_default_text",
                    "used_by": sorted(set(used_by)),
                }
            )
    if not artifact_ids or not artifact_ids <= selected.keys():
        raise ValueError("compiled dependency missing from cargo-about license report")
    records = []
    sources = {}
    for package_id, package in sorted(
        packages.items(), key=lambda item: (item[1]["name"], item[1]["version"])
    ):
        if package_id == root_id:
            continue
        key = (package["name"], package["version"], package.get("source"))
        checksum = locked.get(key)
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("third-party package missing from pinned Cargo.lock")
        archive, documents = crate_materials(package, checksum)
        chosen = sorted(selected.get(package_id, set()))
        source_archive = None
        if "MPL-2.0" in chosen:
            source_archive = f"{package['name']}-{package['version']}.crate"
            sources[source_archive] = archive
        review = []
        if package_id in defaults:
            review.append("cargo_about_used_default_text")
        if not documents:
            review.append("no_conventional_license_documents_in_crate")
        if not chosen:
            review.append("metadata_only_not_in_cargo_about_graph")
        if source_archive:
            review.append("mpl_source_delivery_and_modifications_review")
        records.append(
            {
                "name": package["name"],
                "version": package["version"],
                "declared_license": package.get("license"),
                "cargo_about_license": declarations.get(package_id),
                "selected_licenses": chosen,
                "compiled_artifact_observed": package_id in artifact_ids,
                "registry_checksum": checksum,
                "registry_archive_checksum_verified": True,
                "source_url": f"https://crates.io/api/v1/crates/{package['name']}/{package['version']}/download",
                "bundled_source_archive": source_archive,
                "documents": documents,
                "review_items": review,
            }
        )
    licenses.sort(key=lambda item: (item["id"], item["sha256"], item["used_by"]))
    report = {
        "schema_version": "embedded-debugger.license-materials.v1",
        "scope": "windows_target_metadata_superset_including_build_and_dev_dependencies",
        "cargo_lock_sha256": digest(lockfile),
        "about_config_sha256": digest(config),
        "generator": tool,
        "license_compliance_verified": False,
        "runtime_sbom": False,
        "compiled_dependency_coverage_verified": True,
        "compiled_third_party_count": len(artifact_ids - {root_id}),
        "packages": records,
        "licenses": licenses,
        "review_required": [
            "Review default license text and packages without original license documents.",
            "Review vendored code, native libraries, Rust toolchain runtime and other non-Cargo materials.",
            "Before distribution verify MPL source delivery, modifications and recipient notices.",
            "This is a source-material collection, not legal approval or publisher authentication.",
        ],
    }
    notices = [
        "Third-party license materials (unsigned local candidate)",
        "======================================================",
        "Generated selections and original source notices follow. Manual review remains required.",
        "Scope includes build/dev dependencies; this is not a precise runtime SBOM.",
        "For versions, checksums, source URLs and review gaps see THIRD_PARTY_LICENSES.json.",
        "MPL-2.0 source copies are provided in THIRD_PARTY_SOURCES.zip as original .crate archives.",
        "Those source files remain available under MPL-2.0; review any local modifications before publishing.",
    ]
    for license in licenses:
        notices.extend(
            [
                "",
                f"License: {license['id']}",
                f"Used by: {', '.join(license['used_by'])}",
                f"Origin: {license['text_origin']}",
                "",
                license["text"],
            ]
        )
    for record in records:
        for document in record["documents"]:
            notices.extend(
                [
                    "",
                    f"Original document: {record['name']} {record['version']} / {document['path']}",
                    f"SHA-256: {document['sha256']}",
                    "",
                    document["text"],
                ]
            )
    result = {
        "THIRD_PARTY_LICENSES.json": encode_json(report),
        "THIRD_PARTY_NOTICES.txt": ("\n".join(notices) + "\n").encode("utf-8"),
        "THIRD_PARTY_SOURCES.zip": sources_zip(sources),
    }
    if any(len(data) > MAX_MATERIALS for data in result.values()):
        raise ValueError("license materials exceed the candidate payload limit")
    return result
