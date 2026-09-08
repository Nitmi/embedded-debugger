import copy
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts import license_materials as materials


class LicenseMaterialsTests(unittest.TestCase):
    def test_pinned_about_repeated_target_doctest_is_normalized(self):
        data = b'{"crates":[{"package":{"targets":[{"doctest":true,"doctest":true}]}}],"licenses":[{"used_by":[{"crate":{"targets":[{"doctest":false,"doctest":false}]}}]}]}'
        result = materials.parse_about_report(data)
        self.assertIs(result["crates"][0]["package"]["targets"][0]["doctest"], True)
        self.assertIs(
            result["licenses"][0]["used_by"][0]["crate"]["targets"][0]["doctest"], False
        )

    def test_about_conflicting_repeated_and_nonboolean_doctest_rejected(self):
        for fields in (
            b'"doctest":true,"doctest":false',
            b'"doctest":true,"doctest":1',
            b'"doctest":1,"doctest":true',
            b'"doctest":null,"doctest":null',
            b'"doctest":true,"doctest":true,"doctest":true',
            b'"name":"example","name":"example"',
        ):
            with (
                self.subTest(fields=fields),
                self.assertRaisesRegex(ValueError, "duplicate"),
            ):
                materials.parse_about_report(
                    b'{"crates":[{"package":{"targets":[{' + fields + b"}]}}]}"
                )

    def test_about_license_records_and_unknown_paths_remain_strict(self):
        for data in (
            b'{"doctest":true,"doctest":true}',
            b'{"licenses":[{"text":"a","text":"a"}]}',
            b'{"licenses":[{"doctest":true,"doctest":true}]}',
            b'{"crates":[{"package":{"metadata":{"targets":[{"doctest":true,"doctest":true}]}}}]}',
            b'{"crates":[],"crates":[]}',
        ):
            with (
                self.subTest(data=data),
                self.assertRaisesRegex(ValueError, "duplicate"),
            ):
                materials.parse_about_report(data)

    def test_about_requires_json_object_and_finite_numbers(self):
        for data in (b"[]", b"null", b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(data=data), self.assertRaises((TypeError, ValueError)):
                materials.parse_about_report(data)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.crate_root = self.root / "registry/src/test-index/example-1.0.0"
        self.archive = self.root / "registry/cache/test-index/example-1.0.0.crate"
        self.archive.parent.mkdir(parents=True)
        self.package = {
            "id": "registry-example",
            "name": "example",
            "version": "1.0.0",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "license": "MPL-2.0",
            "manifest_path": str(self.crate_root / "Cargo.toml"),
        }
        self.local = {
            "id": "local-root",
            "name": "embedded-debugger",
            "version": "0.2.0",
            "source": None,
            "license": "MIT",
        }
        self.metadata = {
            "packages": [self.local, self.package],
            "resolve": {"root": "local-root"},
        }
        self.about = {
            "licenses": [
                {
                    "id": "MPL-2.0",
                    "text": "Example MPL text\n",
                    "source_path": None,
                    "used_by": [{"crate": self.package}],
                },
                {
                    "id": "MIT",
                    "text": "Root MIT text\n",
                    "source_path": str(self.root / "LICENSE"),
                    "used_by": [{"crate": self.local}],
                },
            ]
        }
        self.make_archive(
            {
                "LICENSE.txt": b"Original copyright and license\r\n",
                "vendor/NOTICE": b"Vendor attribution\n",
                "src/lib.rs": b"// code\n",
            }
        )

    def make_archive(self, files, special=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo("example-1.0.0/" + name)
                info.size = len(data)
                if special:
                    special(info)
                archive.addfile(info, io.BytesIO(data))
        self.archive.write_bytes(output.getvalue())
        self.checksum = materials.digest(output.getvalue())
        self.lockfile = f'[[package]]\nname="example"\nversion="1.0.0"\nsource="{self.package["source"]}"\nchecksum="{self.checksum}"\n'.encode()

    def collect(self, about=None, artifacts=None):
        return materials.collect(
            self.metadata,
            self.lockfile,
            about or self.about,
            {"local-root", "registry-example"} if artifacts is None else artifacts,
            {"version": materials.ABOUT_VERSION},
            b"configuration",
        )

    def test_preserves_original_documents_and_mpl_archive(self):
        result = self.collect()
        report = json.loads(result["THIRD_PARTY_LICENSES.json"])
        self.assertFalse(report["license_compliance_verified"])
        self.assertFalse(report["runtime_sbom"])
        self.assertTrue(report["compiled_dependency_coverage_verified"])
        package = report["packages"][0]
        self.assertEqual(
            package["documents"][0]["text"], "Original copyright and license\r\n"
        )
        self.assertEqual(package["documents"][1]["path"], "vendor/NOTICE")
        self.assertIn("cargo_about_used_default_text", package["review_items"])
        self.assertIn(
            "mpl_source_delivery_and_modifications_review", package["review_items"]
        )
        self.assertNotIn(str(self.root), result["THIRD_PARTY_LICENSES.json"].decode())
        with zipfile.ZipFile(io.BytesIO(result["THIRD_PARTY_SOURCES.zip"])) as archive:
            self.assertEqual(archive.namelist(), ["example-1.0.0.crate"])
            self.assertEqual(
                archive.read("example-1.0.0.crate"), self.archive.read_bytes()
            )

    def test_missing_compiled_dependency_is_fatal(self):
        about = copy.deepcopy(self.about)
        about["licenses"] = about["licenses"][1:]
        with self.assertRaisesRegex(ValueError, "compiled dependency missing"):
            self.collect(about)
        with self.assertRaises(ValueError):
            self.collect(artifacts=set())

    def test_metadata_only_dependency_is_reported_not_claimed_compiled(self):
        about = copy.deepcopy(self.about)
        about["licenses"] = about["licenses"][1:]
        report = json.loads(
            self.collect(about, {"local-root"})["THIRD_PARTY_LICENSES.json"]
        )
        self.assertFalse(report["packages"][0]["compiled_artifact_observed"])
        self.assertIn(
            "metadata_only_not_in_cargo_about_graph",
            report["packages"][0]["review_items"],
        )

    def test_mismatched_package_identity_is_rejected(self):
        for key, value in (
            ("version", "2.0.0"),
            ("source", "another registry"),
            ("id", "unknown"),
        ):
            with self.subTest(key=key):
                about = copy.deepcopy(self.about)
                about["licenses"][0]["used_by"][0]["crate"][key] = value
                with self.assertRaisesRegex(ValueError, "differs"):
                    self.collect(about)

    def test_cargo_about_normalized_declaration_is_preserved(self):
        self.package["license"] = "MIT/Apache-2.0"
        about = copy.deepcopy(self.about)
        about["licenses"][0]["id"] = "MIT"
        about["licenses"][0]["used_by"][0]["crate"]["license"] = "MIT OR Apache-2.0"
        report = json.loads(self.collect(about)["THIRD_PARTY_LICENSES.json"])
        self.assertEqual(report["packages"][0]["declared_license"], "MIT/Apache-2.0")
        self.assertEqual(
            report["packages"][0]["cargo_about_license"], "MIT OR Apache-2.0"
        )

    def test_altered_or_missing_registry_archive_is_rejected(self):
        self.archive.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.collect()
        self.archive.unlink()
        with self.assertRaises(ValueError):
            self.collect()

    def test_registry_sources_require_pinned_checksums(self):
        self.lockfile = self.lockfile.replace(self.checksum.encode(), b"invalid")
        with self.assertRaisesRegex(ValueError, "Cargo.lock"):
            self.collect()

    def test_deterministic_and_no_tool_execution(self):
        with patch("subprocess.run", side_effect=AssertionError("must not execute")):
            first = self.collect()
            self.metadata["packages"].reverse()
            self.about["licenses"].reverse()
            self.assertEqual(first, self.collect())

    def test_archive_paths_links_and_duplicate_members_are_rejected(self):
        for name in ("../LICENSE", "C:/LICENSE", "a\\LICENSE"):
            with self.subTest(name=name):
                self.make_archive({name: b"test"})
                with self.assertRaisesRegex(ValueError, "layout"):
                    self.collect()
        self.make_archive(
            {"LICENSE": b"test"}, lambda info: setattr(info, "type", tarfile.SYMTYPE)
        )
        with self.assertRaisesRegex(ValueError, "document"):
            self.collect()
        self.make_archive(
            {"LICENSE": b"one", "COPYING": b"two"},
            lambda info: setattr(info, "name", "example-1.0.0/LICENSE"),
        )
        with self.assertRaisesRegex(ValueError, "layout"):
            self.collect()

    def test_license_file_and_nested_licenses_are_collected(self):
        self.package["license_file"] = "custom/legal.txt"
        self.make_archive(
            {
                "custom/legal.txt": b"custom terms",
                "LICENSES/exception.txt": b"exception terms",
            }
        )
        report = json.loads(self.collect()["THIRD_PARTY_LICENSES.json"])
        self.assertEqual(len(report["packages"][0]["documents"]), 2)

    def test_missing_original_document_is_explicit_review_gap(self):
        self.make_archive({"src/lib.rs": b"// code"})
        report = json.loads(self.collect()["THIRD_PARTY_LICENSES.json"])
        self.assertIn(
            "no_conventional_license_documents_in_crate",
            report["packages"][0]["review_items"],
        )

    def test_size_limits(self):
        for name in (
            "MAX_CRATE",
            "MAX_EXPANDED_CRATE",
            "MAX_DOCUMENT",
            "MAX_MATERIALS",
        ):
            with (
                self.subTest(name=name),
                patch.object(materials, name, 1),
                self.assertRaises(ValueError),
            ):
                self.collect()

    def test_unsupported_dependency_source_is_not_silently_skipped(self):
        self.package["source"] = "git+https://example.test/repo"
        with self.assertRaises(ValueError):
            materials.crate_materials(self.package, self.checksum)


if __name__ == "__main__":
    unittest.main()
