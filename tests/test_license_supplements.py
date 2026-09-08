import copy
import io
import json
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import license_materials as materials
from scripts import license_supplements as supplements


class LicenseSupplementTests(unittest.TestCase):
    def setUp(self):
        self.package = {"name": "example", "version": "1.0.0"}
        self.revision = "a" * 40
        self.manifest = b'[package]\nname="example"\nversion="1.0.0"\nrepository="https://github.com/example/example"\nauthors=["Published author"]\n'
        self.files = {
            "Cargo.toml": self.manifest,
            "src/lib.rs": b"// source\n",
            "README.md": b"Original declaration\r\n",
            ".cargo_vcs_info.json": json.dumps(
                {"git": {"sha1": self.revision}, "path_in_vcs": "member"}
            ).encode(),
        }
        self.document = {
            "repository": "https://github.com/example/example",
            "revision": self.revision,
            "path": "LICENSE",
            "url": f"https://raw.githubusercontent.com/example/example/{self.revision}/LICENSE",
            "kind": "upstream_license_text",
            "text": "Original license\r\nCopyright Example",  # No terminal newline.
            "sha256": supplements.sha256(b"Original license\r\nCopyright Example"),
        }
        self.entry = {
            **self.package,
            "registry_checksum": "0" * 64,
            "repository": self.document["repository"],
            "binding": {
                "method": "cargo_vcs_info",
                "revision": self.revision,
                "path_in_vcs": "member",
            },
            "documents": ["example/LICENSE"],
            "review_note": "Preserve original author attribution.",
        }
        self.catalog = {
            "schema_version": supplements.SCHEMA,
            "documents": {"example/LICENSE": self.document},
            "packages": [self.entry],
        }
        self.archive()

    def archive(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for path, content in self.files.items():
                member = tarfile.TarInfo("example-1.0.0/" + path)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        self.data = output.getvalue()
        self.checksum = supplements.sha256(self.data)
        self.entry["registry_checksum"] = self.checksum

    def load(self):
        return supplements.load_catalog(materials.encode_json(self.catalog))

    def verify(self):
        entries, documents = self.load()
        return supplements.verify_package(
            self.package,
            self.checksum,
            self.data,
            entries[("example", "1.0.0")],
            documents,
        )

    def declaration(self):
        self.document.update(
            kind="crate_license_declaration",
            path="member/README.md",
            url=f"https://raw.githubusercontent.com/example/example/{self.revision}/member/README.md",
            text=self.files["README.md"].decode(),
            sha256=supplements.sha256(self.files["README.md"]),
        )

    def manual_binding(self):
        self.files.pop(".cargo_vcs_info.json")
        self.files["Cargo.toml.orig"] = self.manifest
        self.entry["binding"] = {
            "method": "published_package_files_match",
            "revision": self.revision,
            "files": {
                ("Cargo.toml" if path == "Cargo.toml.orig" else path): {
                    "crate_path": path,
                    "sha256": supplements.sha256(content),
                }
                for path, content in self.files.items()
                if path != "Cargo.toml"
            },
        }
        self.archive()

    def test_vcs_binding_preserves_exact_license_bytes_and_authors_without_network(
        self,
    ):
        with patch("socket.socket", side_effect=AssertionError("must remain offline")):
            result = self.verify()
        self.assertTrue(result["binding_verified_against_locked_crate"])
        self.assertEqual(result["documents"][0]["text"], self.document["text"])
        self.assertEqual(result["package_authors"], ["Published author"])

    def test_crate_declaration_is_distinct_from_full_license(self):
        self.declaration()
        result = self.verify()
        self.assertEqual(result["documents"][0]["kind"], "crate_license_declaration")
        self.document["text"] = "Changed declaration"
        self.document["sha256"] = supplements.sha256(b"Changed declaration")
        with self.assertRaisesRegex(ValueError, "differs from locked crate"):
            self.verify()

    def test_document_tampering_and_oversize_are_rejected(self):
        self.document["text"] += "x"
        with self.assertRaisesRegex(ValueError, "hash or size"):
            self.load()
        self.document["text"] = self.document["text"][:-1]
        with (
            patch.object(supplements, "MAX_DOCUMENT", 1),
            self.assertRaises(ValueError),
        ):
            self.load()
        with patch.object(supplements, "MAX_CATALOG", 1), self.assertRaises(ValueError):
            self.load()

    def test_lock_and_archive_changes_are_rejected(self):
        self.entry["registry_checksum"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "locked package"):
            self.verify()
        self.entry["registry_checksum"] = self.checksum
        self.data += b"changed"
        with self.assertRaisesRegex(ValueError, "locked package"):
            self.verify()

    def test_wrong_revision_subdirectory_dirty_or_repository_are_rejected(self):
        cases = [
            {"git": {"sha1": "b" * 40}, "path_in_vcs": "member"},
            {"git": {"sha1": self.revision}, "path_in_vcs": "other"},
            {"git": {"sha1": self.revision, "dirty": True}, "path_in_vcs": "member"},
        ]
        for vcs in cases:
            with self.subTest(vcs=vcs):
                self.files[".cargo_vcs_info.json"] = json.dumps(vcs).encode()
                self.archive()
                with self.assertRaisesRegex(ValueError, "VCS record"):
                    self.verify()
        self.files["Cargo.toml"] = self.manifest.replace(
            b"github.com/example/example", b"github.com/other/other"
        )
        self.archive()
        with self.assertRaisesRegex(ValueError, "repository"):
            self.verify()

    def test_manual_binding_matches_complete_package_without_claiming_release_commit(
        self,
    ):
        self.manual_binding()
        result = self.verify()
        self.assertEqual(result["binding"]["method"], "published_package_files_match")
        self.files["src/lib.rs"] += b"// changed\n"
        self.archive()
        with self.assertRaisesRegex(ValueError, "evidence hash mismatch"):
            self.verify()

    def test_manual_binding_rejects_uncovered_files_or_hidden_vcs_evidence(self):
        self.manual_binding()
        for path in ("extra.rs", ".cargo_vcs_info.json"):
            with self.subTest(path=path):
                self.files[path] = b"extra"
                self.archive()
                with self.assertRaisesRegex(ValueError, "all non-generated"):
                    self.verify()
                self.files.pop(path)

    def test_pinned_url_and_document_revision_must_match(self):
        original = copy.deepcopy(self.document)
        for key, value in (
            ("url", "https://example.test/LICENSE"),
            ("revision", "b" * 40),
            ("path", "../LICENSE"),
        ):
            with self.subTest(key=key):
                self.document.update(original)
                self.document[key] = value
                with self.assertRaises(ValueError):
                    self.load()

    def test_duplicate_json_packages_and_unused_documents_are_rejected(self):
        for raw in (b'{"a":1,"a":1}', b'{"x":NaN}', b"[]", b""):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                supplements.load_catalog(raw)
        self.catalog["packages"].append(copy.deepcopy(self.entry))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.load()
        self.catalog["packages"].pop()
        self.catalog["documents"]["unused/LICENSE"] = copy.deepcopy(self.document)
        with self.assertRaisesRegex(ValueError, "unreferenced"):
            self.load()

    def test_committed_catalog_has_valid_hashes_and_exact_locked_versions(self):
        import tomllib

        root = Path(__file__).resolve().parent.parent
        entries, documents = supplements.load_catalog(
            (root / "licenses/upstream-supplements.json").read_bytes()
        )
        lock = {
            (p["name"], p["version"]): p.get("checksum")
            for p in tomllib.loads((root / "Cargo.lock").read_text())["package"]
        }
        for key, entry in entries.items():
            self.assertEqual(entry["registry_checksum"], lock[key])
        self.assertEqual(len(entries), 8)
        self.assertEqual(len(documents), 10)
        self.assertEqual(
            sum(d["kind"] == "crate_license_declaration" for d in documents.values()), 1
        )


if __name__ == "__main__":
    unittest.main()
