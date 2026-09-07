#!/usr/bin/env python3
"""Audit the HTTP/2 fork's upstream baseline; never update the fork itself.

Go may populate its module cache. Repository files are read-only unless the
maintainer explicitly requests --write-baseline or supplies a --report path.
Hashes describe original upstream files, not the intentionally modified fork.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile

MODULE = "golang.org/x/net"
SOURCE_DIRS = ("http2", "internal/httpcommon", "internal/httpsfv")
EXCLUDED = {"http2/transport_wrap.go", "http2/server_wrap.go"}
BASELINE_PATH = Path("internal/h2/upstream.json")


class AuditError(Exception):
    pass


def pinned_version(repo):
    text = (repo / "go.mod").read_text(encoding="utf-8")
    versions = re.findall(r"^\s*(?:require\s+)?golang\.org/x/net\s+(v\S+?)(?:\s*//.*)?\s*$", text, re.MULTILINE)
    if len(versions) != 1:
        raise AuditError("go.mod must require exactly one golang.org/x/net version")
    return versions[0]


def local_path(source):
    path = PurePosixPath(source)
    if (str(path.parent) not in SOURCE_DIRS or not path.name.endswith(".go")
            or path.name.endswith("_test.go") or source in EXCLUDED
            or str(path) != source):
        raise AuditError("baseline contains an invalid upstream source path")
    return "internal/h2/" + (path.name if path.parent == PurePosixPath("http2") else source)


def source_hashes(directory):
    if not directory.is_dir():
        raise AuditError("downloaded upstream module directory is unavailable")
    files = {}
    for relative in SOURCE_DIRS:
        for path in sorted((directory / relative).glob("*.go")):
            name = path.relative_to(directory).as_posix()
            if path.name.endswith("_test.go") or name in EXCLUDED:
                continue
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(sorted(files.items()))


def compare_files(expected, observed):
    return {
        "added": sorted(observed.keys() - expected.keys()),
        "deleted": sorted(expected.keys() - observed.keys()),
        "changed": [
            {"file": name, "baseline_sha256": expected[name], "observed_sha256": observed[name]}
            for name in sorted(expected.keys() & observed.keys()) if expected[name] != observed[name]
        ],
    }


def run_go_json(repo, go, *arguments):
    try:
        # Resolve/download outside a module so Go cannot rewrite this checkout's
        # go.mod or go.sum, including when checking a newer candidate release.
        with tempfile.TemporaryDirectory(prefix="requests-utls-upstream-") as directory:
            result = subprocess.run(
                [go, *arguments], cwd=directory, check=False, capture_output=True,
                text=True, encoding="utf-8", timeout=120,
                env={**os.environ, "GOWORK": "off"},
            )
    except (OSError, subprocess.TimeoutExpired):
        raise AuditError("Go command could not run; check the configured toolchain and module access") from None
    if result.returncode:
        # Go stderr may contain environment-specific paths or proxy settings.
        raise AuditError(f"go {' '.join(arguments[:2])} failed with exit code {result.returncode}")
    try:
        value = json.loads(result.stdout)
    except ValueError:
        raise AuditError("Go command returned invalid JSON") from None
    if not isinstance(value, dict) or value.get("Error"):
        raise AuditError("Go command could not resolve the requested upstream module")
    return value


def download_source(repo, go, version):
    info = run_go_json(repo, go, "mod", "download", "-json", MODULE + "@" + version)
    if info.get("Path") != MODULE or info.get("Version") != version or not isinstance(info.get("Dir"), str):
        raise AuditError("downloaded module metadata does not match the requested upstream version")
    return source_hashes(Path(info["Dir"]))


def read_baseline(repo):
    baseline = json.loads((repo / BASELINE_PATH).read_text(encoding="utf-8"))
    if (not isinstance(baseline, dict) or baseline.get("schema_version") != 1
            or baseline.get("module") != MODULE or not isinstance(baseline.get("version"), str)
            or not isinstance(baseline.get("files"), dict) or not baseline["files"]):
        raise AuditError("upstream baseline has an invalid schema")
    for name, digest in baseline["files"].items():
        local_path(name)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AuditError("upstream baseline contains an invalid SHA256")
    return baseline


def audit(repo, go, *, latest=False, write_baseline=False):
    pinned = pinned_version(repo)
    latest_version = None
    if latest:
        info = run_go_json(repo, go, "list", "-m", "-json", MODULE + "@latest")
        latest_version = info.get("Version")
        if info.get("Path") != MODULE or not isinstance(latest_version, str):
            raise AuditError("latest upstream module metadata is invalid")

    if write_baseline:
        target = latest_version or pinned
        if target != pinned:
            raise AuditError("review the update and align go.mod before writing a newer baseline")
        files = download_source(repo, go, target)
        missing = [local_path(name) for name in files if not (repo / local_path(name)).is_file()]
        if not files or missing:
            raise AuditError("cannot write baseline: corresponding reviewed fork files are missing")
        baseline = {"schema_version": 1, "module": MODULE, "version": target, "files": files}
        (repo / BASELINE_PATH).write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    else:
        baseline = read_baseline(repo)
        files = download_source(repo, go, baseline["version"])

    changes = compare_files(baseline["files"], files)
    missing = sorted(local_path(name) for name in baseline["files"] if not (repo / local_path(name)).is_file())
    needs_review = pinned != baseline["version"] or bool(missing) or any(changes.values())
    report = {
        "schema_version": 1, "module": MODULE,
        "baseline_version": baseline["version"], "go_mod_version": pinned,
        "baseline_file_count": len(baseline["files"]),
        "baseline_written": write_baseline,
        "baseline_source_changes": changes, "missing_local_files": missing,
        "scope": "Upstream source hashes and local file presence; fork modifications require manual review.",
    }
    if latest:
        candidate = files if latest_version == baseline["version"] else download_source(repo, go, latest_version)
        latest_changes = compare_files(baseline["files"], candidate)
        report.update(latest_version=latest_version, latest_source_changes=latest_changes)
        needs_review = needs_review or latest_version != baseline["version"] or any(latest_changes.values())
    report["status"] = "review_required" if needs_review else "ok"
    return report


def main(argv=None, *, repo=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help="Go executable")
    parser.add_argument("--latest", action="store_true", help="also compare the latest upstream version")
    parser.add_argument("--write-baseline", action="store_true", help="explicitly record the reviewed version pinned in go.mod")
    parser.add_argument("--report", type=Path, help="write a JSON report; reports contain no machine-specific paths")
    args = parser.parse_args(argv)
    repo = Path(repo) if repo is not None else Path(__file__).resolve().parents[1]
    try:
        report = audit(repo, args.go, latest=args.latest, write_baseline=args.write_baseline)
        exit_code = 0 if report["status"] == "ok" else 1
    except AuditError as exc:
        report = {"schema_version": 1, "module": MODULE, "status": "error", "message": str(exc)}
        exit_code = 2
    except (OSError, ValueError):
        report = {"schema_version": 1, "module": MODULE, "status": "error", "message": "cannot read or parse upstream audit inputs"}
        exit_code = 2
    encoded = json.dumps(report, indent=2) + "\n"
    if args.report:
        # Prevent --report from bypassing the explicit baseline write gate.
        if args.report.resolve() == (repo / BASELINE_PATH).resolve():
            parser.error("--report must not overwrite the upstream baseline")
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
