"""Validate committed upstream notices against checksum-verified crate archives.

No network calls or extraction: upstream retrieval is a separate reviewed step.
Hashes bind the recorded evidence; they do not authenticate upstream authors.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
import tomllib
from pathlib import PurePosixPath

SCHEMA = "embedded-debugger.license-supplements.v1"
MAX_CATALOG = 4 * 1024 * 1024
MAX_DOCUMENT = 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_json(data: bytes) -> object:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate supplement JSON key: {key}")
            result[key] = value
        return result

    def reject(value):
        raise ValueError(f"non-JSON numeric constant: {value}")

    return json.loads(data, object_pairs_hook=unique, parse_constant=reject)


def fields(value: object, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("unexpected license supplement fields")


def safe_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(c in value for c in "\\:\x00?#%")
        and not PurePosixPath(value).is_absolute()
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def hex_digest(value: object, size: int) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(f"[0-9a-f]{{{size}}}", value))


def load_catalog(data: bytes) -> tuple[dict, dict]:
    if not 0 < len(data) <= MAX_CATALOG:
        raise ValueError("empty or oversized license supplement catalog")
    catalog = parse_json(data)
    fields(catalog, {"schema_version", "documents", "packages"})
    if catalog["schema_version"] != SCHEMA:
        raise ValueError("unsupported license supplement schema")
    documents = catalog["documents"]
    if not isinstance(documents, dict) or not isinstance(catalog["packages"], list):
        raise TypeError("invalid license supplement catalog")
    for identity, document in documents.items():
        fields(
            document,
            {"repository", "revision", "path", "url", "sha256", "text", "kind"},
        )
        if (
            not safe_path(identity)
            or not safe_path(document["path"])
            or not hex_digest(document["revision"], 40)
            or not hex_digest(document["sha256"], 64)
            or document["kind"]
            not in {"upstream_license_text", "crate_license_declaration"}
            or not isinstance(document["text"], str)
        ):
            raise ValueError("invalid supplemental document")
        content = document["text"].encode("utf-8")
        if (
            not 0 < len(content) <= MAX_DOCUMENT
            or sha256(content) != document["sha256"]
        ):
            raise ValueError("supplemental document hash or size mismatch")
        repository = document["repository"]
        if not isinstance(repository, str) or not re.fullmatch(
            r"https://(?:github\.com|gitlab\.com)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
            repository,
        ):
            raise ValueError("unsupported supplemental repository")
        revision, path = document["revision"], document["path"]
        if repository.startswith("https://github.com/"):
            expected = (
                repository.replace("github.com", "raw.githubusercontent.com")
                + f"/{revision}/{path}"
            )
        else:
            expected = repository + f"/-/raw/{revision}/{path}"
        if document["url"] != expected:
            raise ValueError(
                "supplement URL differs from pinned repository/revision/path"
            )
    packages = {}
    used = set()
    for package in catalog["packages"]:
        fields(
            package,
            {
                "name",
                "version",
                "registry_checksum",
                "repository",
                "binding",
                "documents",
                "review_note",
            },
        )
        if (
            not isinstance(package["name"], str)
            or not isinstance(package["version"], str)
            or not hex_digest(package["registry_checksum"], 64)
            or not isinstance(package["documents"], list)
            or not package["documents"]
            or any(not isinstance(item, str) for item in package["documents"])
            or len(set(package["documents"])) != len(package["documents"])
            or not (
                package["review_note"] is None
                or isinstance(package["review_note"], str)
            )
        ):
            raise ValueError("invalid license supplement package")
        key = (package["name"], package["version"])
        if key in packages:
            raise ValueError("duplicate license supplement package")
        binding = package["binding"]
        if not isinstance(binding, dict) or not hex_digest(binding.get("revision"), 40):
            raise ValueError("invalid supplement source binding")
        method = binding.get("method")
        if method == "cargo_vcs_info":
            fields(binding, {"method", "revision", "path_in_vcs"})
            if binding["path_in_vcs"] != "" and not safe_path(binding["path_in_vcs"]):
                raise ValueError("invalid VCS package path")
        elif method == "published_package_files_match":
            fields(binding, {"method", "revision", "files"})
            if not isinstance(binding["files"], dict) or not binding["files"]:
                raise ValueError("missing package file evidence")
            for path, evidence in binding["files"].items():
                fields(evidence, {"crate_path", "sha256"})
                if (
                    not safe_path(path)
                    or not safe_path(evidence["crate_path"])
                    or evidence["crate_path"]
                    != ("Cargo.toml.orig" if path == "Cargo.toml" else path)
                    or not hex_digest(evidence["sha256"], 64)
                ):
                    raise ValueError("invalid package file evidence")
        else:
            raise ValueError("unsupported supplement source binding")
        for identity in package["documents"]:
            if identity not in documents or any(
                documents[identity][field] != value
                for field, value in (
                    ("repository", package["repository"]),
                    ("revision", binding["revision"]),
                )
            ):
                raise ValueError("supplement document/source binding mismatch")
            used.add(identity)
        packages[key] = package
    if used != documents.keys():
        raise ValueError("unreferenced supplemental document")
    return packages, documents


def verify_package(
    package: dict, checksum: str, archive_bytes: bytes, entry: dict, documents: dict
) -> dict:
    if (
        (package["name"], package["version"]) != (entry["name"], entry["version"])
        or checksum != entry["registry_checksum"]
        or sha256(archive_bytes) != checksum
    ):
        raise ValueError("license supplement differs from locked package")
    folder = f"{package['name']}-{package['version']}/"
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        # The caller has already validated archive paths, duplicates and expansion.
        def read(path):
            member = archive.getmember(folder + path)
            if not member.isfile() or not 0 < member.size <= MAX_DOCUMENT:
                raise ValueError("invalid supplemental binding archive member")
            with archive.extractfile(member) as stream:
                content = stream.read(MAX_DOCUMENT + 1)
            if len(content) != member.size:
                raise ValueError("supplemental binding member size mismatch")
            return content

        manifest = tomllib.loads(read("Cargo.toml").decode("utf-8"))["package"]
        if any(manifest.get(k) != entry[k] for k in ("name", "version", "repository")):
            raise ValueError(
                "supplement repository differs from published Cargo manifest"
            )
        binding = entry["binding"]
        if binding["method"] == "cargo_vcs_info":
            vcs = parse_json(read(".cargo_vcs_info.json"))
            if (
                vcs.get("git", {}).get("sha1") != binding["revision"]
                or vcs.get("git", {}).get("dirty", False) is not False
                or vcs.get("path_in_vcs", "") != binding["path_in_vcs"]
            ):
                raise ValueError("supplement differs from published Cargo VCS record")
        else:
            actual = {m.name[len(folder) :] for m in archive if not m.isdir()}
            expected = {item["crate_path"] for item in binding["files"].values()}
            if actual != expected | {"Cargo.toml"} or "Cargo.toml.orig" not in expected:
                raise ValueError(
                    "supplement evidence does not cover all non-generated package files"
                )
            for item in binding["files"].values():
                if sha256(read(item["crate_path"])) != item["sha256"]:
                    raise ValueError("supplement package file evidence hash mismatch")
        selected = [documents[key] for key in sorted(entry["documents"])]
        for document in selected:
            if document["kind"] == "crate_license_declaration":
                relative = PurePosixPath(document["path"]).relative_to(
                    binding.get("path_in_vcs") or "."
                )
                if read(str(relative)) != document["text"].encode("utf-8"):
                    raise ValueError(
                        "supplemental declaration differs from locked crate"
                    )
    return {
        "binding": binding,
        "binding_verified_against_locked_crate": True,
        "package_authors": manifest.get("authors", []),
        "review_note": entry["review_note"],
        "documents": selected,
    }
