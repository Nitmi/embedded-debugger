"""Upload one verified CI ZIP to an existing draft, without executing the CLI."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

if __package__:
    from . import package_binary
else:
    import package_binary

REPOSITORY = "Nitmi/embedded-debugger"
WORKFLOW = ".github/workflows/binary-release.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_run(run: dict, tag: str, source: str, run_id: int) -> None:
    require(
        (
            run["id"],
            run["head_sha"],
            run["head_branch"],
            run["event"],
            run["path"],
            run["status"],
            run["conclusion"],
            run["run_attempt"],
            run["repository"]["full_name"],
        )
        == (
            run_id,
            source,
            tag,
            "push",
            WORKFLOW,
            "completed",
            "success",
            1,
            REPOSITORY,
        ),
        "CI run does not match the successful tag provenance run",
    )


def validate_attestation(
    items: list, tag: str, source: str, run_id: int, name: str, sha: str
) -> None:
    require(bool(items), "No verified attestation")
    uri = f"https://github.com/{REPOSITORY}/{WORKFLOW}@refs/tags/{tag}"
    for item in items:
        result = item["verificationResult"]
        certificate = result["signature"]["certificate"]
        for field, expected in {
            "subjectAlternativeName": uri,
            "buildConfigURI": uri,
            "sourceRepositoryURI": f"https://github.com/{REPOSITORY}",
            "sourceRepositoryRef": f"refs/tags/{tag}",
            "sourceRepositoryDigest": source,
            "buildSignerDigest": source,
            "buildConfigDigest": source,
            "buildTrigger": "push",
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryVisibilityAtSigning": "public",
            "runInvocationURI": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/1",
        }.items():
            require(
                certificate.get(field) == expected,
                f"Attestation certificate mismatch: {field}",
            )
        statement = result["statement"]
        require(
            statement["predicateType"] == "https://slsa.dev/provenance/v1",
            "Wrong predicate",
        )
        require(
            statement["subject"] == [{"name": name, "digest": {"sha256": sha}}],
            "Wrong subject",
        )
        require(bool(result["verifiedTimestamps"]), "Missing verified timestamp")


def validate_draft(release: dict, tag: str, source: str) -> None:
    require(
        release["draft"] is True and release["prerelease"] is False,
        "Release is not a draft",
    )
    require(
        release["tag_name"] == tag and release["target_commitish"] == source,
        "Draft target mismatch",
    )


def existing_asset(
    release: dict, tag: str, source: str, name: str, sha: str, size: int
) -> dict | None:
    validate_draft(release, tag, source)
    matches = [asset for asset in release["assets"] if asset["name"] == name]
    require(len(matches) <= 1, "Duplicate asset names")
    if not matches:
        return None
    asset = matches[0]
    require(
        asset["state"] == "uploaded"
        and asset["size"] == size
        and asset["digest"] == "sha256:" + sha,
        "Existing asset differs; it will not be replaced",
    )
    return asset


def execute(arguments: list[str]) -> bytes:
    result = subprocess.run(arguments, check=True, capture_output=True, timeout=180)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
    return result.stdout


def write_json(path: Path, data: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(data, indent=2) + "\n")


def upload(args: argparse.Namespace) -> dict:
    require(
        re.fullmatch(
            r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", args.tag
        )
        is not None,
        "Tag must be vX.Y.Z",
    )
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.source) is not None, "Invalid source digest"
    )
    require(
        re.fullmatch(r"[0-9a-f]{64}", args.sha256) is not None, "Invalid archive digest"
    )
    require(args.run_id > 0 and args.release_id > 0, "IDs must be positive")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    resolved = execute(
        ["git", "rev-parse", "--verify", f"refs/tags/{args.tag}^{{commit}}"]
    )
    require(resolved.decode().strip() == args.source, "Tag commit mismatch")

    def api(endpoint: str, record: str) -> dict:
        value = json.loads(execute(["gh", "api", f"repos/{REPOSITORY}/{endpoint}"]))
        write_json(args.output_dir / record, value)
        return value

    run = api(f"actions/runs/{args.run_id}", "run.json")
    validate_run(run, args.tag, args.source, args.run_id)
    draft = api(f"releases/{args.release_id}", "draft-before.json")
    # Reject a wrong/published destination before downloading or uploading assets.
    validate_draft(draft, args.tag, args.source)
    artifacts = args.output_dir / "candidate"
    execute(
        [
            "gh",
            "run",
            "download",
            str(args.run_id),
            "--repo",
            REPOSITORY,
            "--name",
            "embedded-debugger-windows-x86_64",
            "--dir",
            str(artifacts),
        ]
    )
    name = f"embedded-debugger-{args.tag[1:]}-x86_64-pc-windows-msvc.zip"
    archive = artifacts / name
    integrity = package_binary.verify(archive, archive.with_suffix(".zip.sha256"))
    write_json(args.output_dir / "integrity.json", integrity)
    require(
        integrity["source_revision"] == args.source
        and integrity["version"] == args.tag[1:]
        and integrity["sha256"] == args.sha256,
        "Archive identity mismatch",
    )
    attestation = json.loads(
        execute(
            [
                "gh",
                "attestation",
                "verify",
                str(archive),
                "--repo",
                REPOSITORY,
                "--source-ref",
                f"refs/tags/{args.tag}",
                "--source-digest",
                args.source,
                "--signer-digest",
                args.source,
                "--deny-self-hosted-runners",
                "--cert-identity",
                f"https://github.com/{REPOSITORY}/{WORKFLOW}@refs/tags/{args.tag}",
                "--predicate-type",
                "https://slsa.dev/provenance/v1",
                "--format",
                "json",
            ]
        )
    )
    write_json(args.output_dir / "attestation.json", attestation)
    validate_attestation(
        attestation, args.tag, args.source, args.run_id, name, args.sha256
    )
    asset = existing_asset(
        draft, args.tag, args.source, name, args.sha256, archive.stat().st_size
    )
    if asset is None:
        execute(
            ["gh", "release", "upload", args.tag, str(archive), "--repo", REPOSITORY]
        )
    final = api(f"releases/{args.release_id}", "draft-after.json")
    verified = existing_asset(
        final, args.tag, args.source, name, args.sha256, archive.stat().st_size
    )
    require(verified is not None, "Uploaded asset is missing")
    return {
        "ok": True,
        "status": "already_uploaded" if asset else "uploaded",
        "source_revision": args.source,
        "tag": args.tag,
        "sha256": args.sha256,
        "release_id": args.release_id,
        "asset_id": verified["id"],
        "hardware_access": False,
        "native_executables_started": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("tag", "source", "sha256"):
        parser.add_argument("--" + field, required=True)
    for field in ("run-id", "release-id"):
        parser.add_argument("--" + field, required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = upload(args)
        write_json(args.output_dir / "result.json", report)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"ok": False, "error": str(error), "hardware_access": False}))
        return 1
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
