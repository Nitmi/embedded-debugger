import argparse
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import upload_release_asset as uploader


TAG = "v0.2.5"
SOURCE = "a" * 40
SHA = "b" * 64
NAME = "embedded-debugger-0.2.5-x86_64-pc-windows-msvc.zip"


def run_record():
    return {
        "id": 123,
        "head_sha": SOURCE,
        "head_branch": TAG,
        "event": "push",
        "path": uploader.WORKFLOW,
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "repository": {"full_name": uploader.REPOSITORY},
    }


def draft_record():
    return {
        "id": 456,
        "draft": True,
        "prerelease": False,
        "tag_name": TAG,
        "target_commitish": SOURCE,
        "assets": [],
    }


def attestation():
    uri = (
        f"https://github.com/{uploader.REPOSITORY}/{uploader.WORKFLOW}@refs/tags/{TAG}"
    )
    return [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "subjectAlternativeName": uri,
                        "buildConfigURI": uri,
                        "sourceRepositoryURI": f"https://github.com/{uploader.REPOSITORY}",
                        "sourceRepositoryRef": f"refs/tags/{TAG}",
                        "sourceRepositoryDigest": SOURCE,
                        "buildSignerDigest": SOURCE,
                        "buildConfigDigest": SOURCE,
                        "buildTrigger": "push",
                        "runnerEnvironment": "github-hosted",
                        "sourceRepositoryVisibilityAtSigning": "public",
                        "runInvocationURI": f"https://github.com/{uploader.REPOSITORY}/actions/runs/123/attempts/1",
                    }
                },
                "verifiedTimestamps": [{"timestamp": "fixture"}],
                "statement": {
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "subject": [{"name": NAME, "digest": {"sha256": SHA}}],
                },
            }
        }
    ]


class UploadReleaseAssetTests(unittest.TestCase):
    def test_run_rejects_wrong_source_ref_workflow_event_attempt_or_result(self):
        uploader.validate_run(run_record(), TAG, SOURCE, 123)
        for field, value in [
            ("head_sha", "c" * 40),
            ("head_branch", "main"),
            ("path", ".github/workflows/ci.yml"),
            ("event", "pull_request"),
            ("run_attempt", 2),
            ("conclusion", "failure"),
            ("id", 999),
        ]:
            with self.subTest(field=field):
                changed = run_record()
                changed[field] = value
                with self.assertRaises(ValueError):
                    uploader.validate_run(changed, TAG, SOURCE, 123)

    def test_certificate_rejects_other_signer_run_runner_or_private_source(self):
        uploader.validate_attestation(attestation(), TAG, SOURCE, 123, NAME, SHA)
        for field, value in [
            ("buildSignerDigest", "c" * 40),
            ("sourceRepositoryRef", "main"),
            ("runInvocationURI", "https://example.com/other"),
            ("runnerEnvironment", "self-hosted"),
            ("sourceRepositoryVisibilityAtSigning", "private"),
        ]:
            changed = attestation()
            changed[0]["verificationResult"]["signature"]["certificate"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                uploader.validate_attestation(changed, TAG, SOURCE, 123, NAME, SHA)

    def test_signed_subject_must_match_name_and_digest(self):
        for name, sha in [("other.zip", SHA), (NAME, "c" * 64)]:
            with self.assertRaises(ValueError):
                uploader.validate_attestation(
                    attestation(), TAG, SOURCE, 123, name, sha
                )

    def test_published_or_wrong_draft_is_rejected(self):
        for field, value in [
            ("draft", False),
            ("prerelease", True),
            ("tag_name", "v0.2.4"),
            ("target_commitish", "main"),
        ]:
            changed = draft_record()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                uploader.validate_draft(changed, TAG, SOURCE)

    def test_existing_asset_is_idempotent_only_for_exact_uploaded_content(self):
        draft = draft_record()
        self.assertIsNone(uploader.existing_asset(draft, TAG, SOURCE, NAME, SHA, 100))
        asset = {
            "id": 789,
            "name": NAME,
            "state": "uploaded",
            "size": 100,
            "digest": "sha256:" + SHA,
        }
        draft["assets"] = [asset]
        self.assertEqual(
            uploader.existing_asset(draft, TAG, SOURCE, NAME, SHA, 100), asset
        )
        for field, value in [
            ("state", "starter"),
            ("size", 99),
            ("digest", "sha256:" + "c" * 64),
        ]:
            changed = copy.deepcopy(draft)
            changed["assets"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                uploader.existing_asset(changed, TAG, SOURCE, NAME, SHA, 100)
        draft["assets"].append(asset.copy())
        with self.assertRaises(ValueError):
            uploader.existing_asset(draft, TAG, SOURCE, NAME, SHA, 100)

    def test_invalid_arguments_never_start_git_or_gh(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(
                tag="v0.2.5; bad",
                source=SOURCE,
                sha256=SHA,
                run_id=123,
                release_id=456,
                output_dir=Path(temporary) / "new",
            )
            with (
                patch.object(uploader, "execute") as execute,
                self.assertRaises(ValueError),
            ):
                uploader.upload(args)
            execute.assert_not_called()
            self.assertFalse(args.output_dir.exists())

    def test_invalid_attestation_never_reaches_upload(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(
                tag=TAG,
                source=SOURCE,
                sha256=SHA,
                run_id=123,
                release_id=456,
                output_dir=Path(temporary) / "new",
            )
            changed = attestation()
            changed[0]["verificationResult"]["signature"]["certificate"][
                "runnerEnvironment"
            ] = "self-hosted"
            responses = [
                SOURCE.encode(),
                json.dumps(run_record()).encode(),
                json.dumps(draft_record()).encode(),
                b"",
                json.dumps(changed).encode(),
            ]
            with patch.object(uploader, "execute", side_effect=responses) as execute:
                with (
                    patch.object(
                        uploader.package_binary,
                        "verify",
                        return_value={
                            "source_revision": SOURCE,
                            "version": TAG[1:],
                            "sha256": SHA,
                        },
                    ),
                    self.assertRaises(ValueError),
                ):
                    uploader.upload(args)
            self.assertFalse(
                any(
                    call.args[0][:3] == ["gh", "release", "upload"]
                    for call in execute.call_args_list
                )
            )


if __name__ == "__main__":
    unittest.main()
