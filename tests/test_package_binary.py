import copy
import io
import json
import stat
import tempfile
import unittest
import zipfile
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from scripts import package_binary as release


class BinaryPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = {
            name: f"test {name}\n".encode() for name in release.PAYLOAD_NAMES
        }
        self.build = {
            "version": "0.2.0",
            "target": release.TARGET,
            "source_revision": "a" * 40,
            "rustc": f"rustc test\nhost: {release.TARGET}",
            "cargo": "cargo test",
            "build_profile": "release",
        }
        self.data = release.archive_bytes(self.payload, self.build)

    def rewrite(self, callback):
        output = io.BytesIO()
        with (
            zipfile.ZipFile(io.BytesIO(self.data)) as source,
            zipfile.ZipFile(output, "w") as destination,
        ):
            for original in source.infolist():
                info = copy.copy(original)
                info, data = callback(info, source.read(original))
                destination.writestr(info, data)
        return output.getvalue()

    def change_manifest(self, callback):
        def change(info, data):
            if info.filename.endswith(release.MANIFEST_NAME):
                manifest = json.loads(data)
                callback(manifest)
                data = release.json_bytes(manifest)
            return info, data

        return self.rewrite(change)

    def write_candidate(self, data=None):
        archive = self.root / "candidate.zip"
        content = self.data if data is None else data
        archive.write_bytes(content)
        checksum = self.root / "candidate.zip.sha256"
        checksum.write_text(
            f"{release.sha256(content)}  {archive.name}\n",
            encoding="ascii",
            newline="\n",
        )
        return archive, checksum

    def test_deterministic_archive(self):
        self.assertEqual(
            self.data,
            release.archive_bytes(
                dict(reversed(list(self.payload.items()))), self.build
            ),
        )
        manifest = release.inspect_archive(self.data)
        self.assertEqual(manifest["version"], "0.2.0")
        with zipfile.ZipFile(io.BytesIO(self.data)) as archive:
            self.assertEqual(len(archive.infolist()), 11)
            for entry in archive.infolist():
                self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(entry.compress_type, zipfile.ZIP_STORED)

    def test_verify_does_not_execute_a_tool_or_binary(self):
        archive, checksum = self.write_candidate()
        with patch.object(
            release.subprocess, "run", side_effect=AssertionError("must not execute")
        ):
            report = release.verify(archive, checksum)
        self.assertTrue(report["integrity_verified"])
        self.assertFalse(report["publisher_authenticity_verified"])
        self.assertFalse(report["executable_started"])

    def test_checksum_is_required_and_bound_to_filename(self):
        archive, checksum = self.write_candidate()
        for text in (
            "0" * 64 + "  candidate.zip\n",
            release.sha256(self.data) + "  other.zip\n",
        ):
            with self.subTest(text=text):
                checksum.write_text(text, encoding="ascii")
                with self.assertRaises(release.ReleaseError):
                    release.verify(archive, checksum)

    def test_changed_member_is_rejected_even_with_recomputed_archive_checksum(self):
        data = self.rewrite(
            lambda info, data: (
                info,
                data + b"tamper" if info.filename.endswith(".exe") else data,
            )
        )
        with self.assertRaisesRegex(release.ReleaseError, "integrity"):
            release.verify(*self.write_candidate(data))

    def test_traversal_and_absolute_paths_are_rejected(self):
        for path in (
            "../LICENSE",
            "/LICENSE",
            "C:/LICENSE",
            "folder\\LICENSE",
            "folder/CON",
            "folder/LICENSE:stream",
        ):
            with self.subTest(path=path):

                def change(info, data, path=path):
                    if info.filename.endswith("/LICENSE"):
                        info.filename = path
                    return info, data

                with self.assertRaises(release.ReleaseError):
                    release.inspect_archive(self.rewrite(change))

    def test_links_and_compressed_members_are_rejected(self):
        for kind in ("symlink", "compressed"):
            with self.subTest(kind=kind):

                def change(info, data, kind=kind):
                    if kind == "symlink":
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    else:
                        info.compress_type = zipfile.ZIP_DEFLATED
                    return info, data

                with self.assertRaises(release.ReleaseError):
                    release.inspect_archive(self.rewrite(change))

    def test_extra_duplicate_and_missing_members_are_rejected(self):
        for kind in ("extra", "duplicate", "missing"):
            with self.subTest(kind=kind):
                output = io.BytesIO()
                with (
                    zipfile.ZipFile(io.BytesIO(self.data)) as source,
                    zipfile.ZipFile(output, "w") as destination,
                ):
                    items = source.infolist()
                    for item in items[1:] if kind == "missing" else items:
                        destination.writestr(item, source.read(item))
                    if kind != "missing":
                        name = "extra" if kind == "extra" else items[0].filename
                        with (
                            self.assertWarns(UserWarning)
                            if kind == "duplicate"
                            else nullcontext()
                        ):
                            destination.writestr(name, b"extra")
                with self.assertRaises(release.ReleaseError):
                    release.inspect_archive(output.getvalue())

    def test_invalid_release_identity(self):
        for key, value in (
            ("version", "../../bad"),
            ("target", "aarch64-unknown-linux-gnu"),
            ("source_revision", "not-a-commit"),
            ("schema_version", "future"),
            ("schema_version", []),
            ("schema_version", {}),
            ("publication", "signed"),
            ("product", "another-tool"),
            ("build_profile", "debug"),
            ("rustc", None),
            ("unknown", "field"),
        ):
            with self.subTest(key=key):
                data = self.change_manifest(
                    lambda manifest, key=key, value=value: manifest.update({key: value})
                )
                with self.assertRaises(release.ReleaseError):
                    release.inspect_archive(data)

    def test_invalid_file_records(self):
        for field, value in (
            ("size", True),
            ("size", 0),
            ("size", release.MAX_FILE + 1),
            ("sha256", "x" * 64),
            ("path", "../payload"),
        ):
            with self.subTest(field=field):
                data = self.change_manifest(
                    lambda manifest, field=field, value=value: manifest["files"][
                        0
                    ].update({field: value})
                )
                with self.assertRaises(release.ReleaseError):
                    release.inspect_archive(data)

    def test_duplicate_manifest_paths(self):
        data = self.change_manifest(
            lambda manifest: manifest["files"].__setitem__(1, manifest["files"][0])
        )
        with self.assertRaises(release.ReleaseError):
            release.inspect_archive(data)

    def test_duplicate_json_keys(self):
        def change(info, data):
            if info.filename.endswith(release.MANIFEST_NAME):
                data = data.replace(
                    b'"version": "0.2.0"', b'"version": "0.2.0", "version": "0.2.0"'
                )
            return info, data

        with self.assertRaisesRegex(release.ReleaseError, "duplicate JSON"):
            release.inspect_archive(self.rewrite(change))

    def test_non_json_constants_and_cli_errors(self):
        with self.assertRaises(release.ReleaseError):
            release.parse_json(b'{"value": NaN}')
        output = io.StringIO()
        with (
            patch.object(
                release.sys,
                "argv",
                [
                    "package_binary.py",
                    "verify",
                    str(self.root / "missing.zip"),
                    "--checksum",
                    str(self.root / "missing.sha256"),
                    "--json",
                ],
            ),
            patch.object(release.sys, "stdout", output),
        ):
            self.assertEqual(release.main(), 1)
        report = json.loads(output.getvalue())
        self.assertFalse(report["ok"])
        self.assertFalse(report["hardware_access"])
        self.assertEqual(report["operation"], "verify")

    def test_archive_and_file_limits(self):
        with (
            patch.object(release, "MAX_ARCHIVE", 10),
            self.assertRaises(release.ReleaseError),
        ):
            release.inspect_archive(self.data)
        archive, _ = self.write_candidate()
        with self.assertRaises(release.ReleaseError):
            release.bounded_read(archive, 10)
        with self.assertRaises(release.ReleaseError):
            release.bounded_read(self.root, 10)

    def test_inventory_is_not_mislabeled_as_runtime_sbom(self):
        lockfile = b'[[package]]\nname="example"\nversion="1.0.0"\nsource="registry+https://example.test/index"\nchecksum="abc"\n'
        metadata = {
            "packages": [
                {
                    "name": "example",
                    "version": "1.0.0",
                    "source": "registry+https://example.test/index",
                    "license": "MIT",
                    "license_file": "/private/home/LICENSE",
                }
            ]
        }
        result = json.loads(release.dependency_inventory(metadata, lockfile))
        self.assertFalse(result["runtime_sbom"])
        self.assertFalse(result["license_compliance_verified"])
        self.assertEqual(result["target"], release.TARGET)
        self.assertEqual(result["packages"][0]["registry_checksum"], "abc")
        self.assertNotIn("/private/home", json.dumps(result))
        metadata["packages"][0]["version"] = "2.0.0"
        with self.assertRaises(release.ReleaseError):
            release.dependency_inventory(metadata, lockfile)

    def test_dirty_source_stops_before_build(self):
        with (
            patch.object(release, "run", return_value=b" M src/main.rs\n") as runner,
            self.assertRaisesRegex(release.ReleaseError, "clean"),
        ):
            release.build(
                self.root, self.root / "dist", True, self.root / "cargo-about.exe"
            )
        self.assertEqual(runner.call_count, 1)

    def build_with_fake_cargo(
        self,
        output,
        revisions=None,
        mutate_binary=False,
        version="0.2.0",
        host=release.TARGET,
        about_version="0.9.2",
        mutate_about=False,
    ):
        binary = self.root / "artifact.exe"
        binary.write_bytes(b"not executable; controlled fixture")
        about = self.root / "cargo-about.exe"
        about.write_bytes(b"fixture cargo-about")
        root_id = "fixture-root"
        package = {
            "name": release.NAME,
            "version": "0.2.0",
            "id": root_id,
            "source": None,
            "license": "MIT",
        }
        metadata = {"resolve": {"root": root_id}, "packages": [package]}
        sources = {
            "Cargo.toml": b'[package]\nname="embedded-debugger"\nversion="0.2.0"\n',
            "Cargo.lock": b'[[package]]\nname="embedded-debugger"\nversion="0.2.0"\n',
            "LICENSE": b"license\n",
            "docs/binary-release.md": b"instructions\n",
            "about.toml": b'accepted = ["MIT"]\n',
            "licenses/upstream-supplements.json": b"committed supplement fixture\n",
            "scripts/test_windows_candidate.ps1": b"smoke script\n",
            "docs/windows-runtime.md": b"runtime guide\n",
        }

        def fake_run(root, args, timeout=60):
            if args == [str(about), "--version"]:
                return f"cargo-about {about_version}\n".encode()
            if args[:2] == [str(about), "generate"]:
                self.assertIn("--frozen", args)
                self.assertIn("--fail", args)
                if mutate_about:
                    about.write_bytes(b"changed license generator")
                Path(args[args.index("--output-file") + 1]).write_bytes(
                    b'{"licenses": []}'
                )
                return b""
            if args == ["rustc", "-vV"]:
                return f"rustc fixture\nhost: {host}\n".encode()
            if args == ["cargo", "--version"]:
                return b"cargo fixture\n"
            if args[:2] == ["cargo", "metadata"]:
                self.assertIn("--offline", args)
                self.assertEqual(
                    args[args.index("--filter-platform") + 1], release.TARGET
                )
                return release.json_bytes(metadata)
            if args[:2] == ["cargo", "build"]:
                self.assertIn("--locked", args)
                self.assertIn("--offline", args)
                self.assertEqual(args[args.index("--target") + 1], release.TARGET)
                return (
                    json.dumps(
                        {
                            "reason": "compiler-artifact",
                            "package_id": root_id,
                            "target": {"kind": ["bin"], "name": release.NAME},
                            "executable": str(binary),
                        }
                    ).encode("utf-8")
                    + b"\n"
                )
            if args == [str(binary), "--version"]:
                if mutate_binary:
                    binary.write_bytes(b"changed during version smoke")
                return f"embedded-debugger {version}\n".encode()
            raise AssertionError(args)

        with (
            patch.object(
                release, "clean_revision", side_effect=revisions or ["a" * 40, "a" * 40]
            ),
            patch.object(
                release,
                "git_file",
                side_effect=lambda root, revision, name: sources[name],
            ),
            patch.object(release, "run", side_effect=fake_run),
            patch.object(
                release.license_materials,
                "collect",
                return_value={
                    name: b"fixture license materials\n"
                    for name in release.PAYLOAD_NAMES
                    if name.startswith("THIRD_PARTY_")
                },
            ),
        ):
            return release.build(self.root, output, True, about)

    def test_legacy_archive_verification_is_preserved(self):
        with (
            patch.object(release, "SCHEMA", release.LEGACY_SCHEMA),
            patch.object(release, "PAYLOAD_NAMES", release.LEGACY_PAYLOAD_NAMES),
        ):
            data = release.archive_bytes(
                {name: self.payload[name] for name in release.LEGACY_PAYLOAD_NAMES},
                self.build,
            )
        result = release.verify(*self.write_candidate(data))
        self.assertTrue(result["integrity_verified"])
        self.assertFalse(result["license_materials_present"])
        self.assertEqual(result["archive_schema_version"], release.LEGACY_SCHEMA)

    def test_schema_and_license_payload_layout_must_agree(self):
        with self.assertRaises(release.ReleaseError):
            release.inspect_archive(
                self.change_manifest(
                    lambda manifest: manifest.update(
                        schema_version=release.LEGACY_SCHEMA
                    )
                )
            )

    def test_wrong_or_changed_license_generator_publishes_nothing(self):
        output = self.root / "dist"
        for options in ({"about_version": "0.9.1"}, {"mutate_about": True}):
            with self.subTest(options=options), self.assertRaises(release.ReleaseError):
                self.build_with_fake_cargo(output, **options)
            self.assertFalse(output.exists())

    def test_build_binds_the_cargo_artifact_and_preserves_existing_outputs(self):
        output = self.root / "dist"
        result = self.build_with_fake_cargo(output)
        archive = Path(result["archive"])
        checksum = Path(result["checksum"])
        before = archive.read_bytes()
        self.assertTrue(release.verify(archive, checksum)["integrity_verified"])
        with self.assertRaisesRegex(release.ReleaseError, "already exists"):
            self.build_with_fake_cargo(output)
        self.assertEqual(archive.read_bytes(), before)

    def test_source_change_during_build_publishes_nothing(self):
        output = self.root / "dist"
        with self.assertRaisesRegex(release.ReleaseError, "changed"):
            self.build_with_fake_cargo(output, ["a" * 40, "b" * 40])
        self.assertFalse(output.exists())

    def test_binary_change_or_version_mismatch_publishes_nothing(self):
        output = self.root / "dist"
        for options in ({"mutate_binary": True}, {"version": "0.1.0"}):
            with self.subTest(options=options), self.assertRaises(release.ReleaseError):
                self.build_with_fake_cargo(output, **options)
        self.assertFalse(output.exists())

    def test_unsupported_host_stops_before_cargo_build(self):
        output = self.root / "dist"
        with self.assertRaisesRegex(release.ReleaseError, "currently requires"):
            self.build_with_fake_cargo(output, host="x86_64-unknown-linux-gnu")
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
