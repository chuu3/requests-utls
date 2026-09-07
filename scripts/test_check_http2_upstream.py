"""No network or Go executable is required for upstream audit regressions."""

from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("check_http2_upstream", Path(__file__).with_name("check_http2_upstream.py"))
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class UpstreamAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "go.mod").write_text("module example.test/fork\n\nrequire (\n\tgolang.org/x/net v0.58.0\n)\n", encoding="utf-8")
        (self.repo / "go.sum").write_text("unchanged test sums\n", encoding="utf-8")
        self.upstream = self.root / "upstream"
        for name in ("http2/transport.go", "http2/server.go", "internal/httpcommon/request.go", "internal/httpsfv/httpsfv.go"):
            self.write_source(name, "package upstream\n")
            destination = self.repo / audit.local_path(name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("package modifiedfork\n", encoding="utf-8")
        self.files = audit.source_hashes(self.upstream)
        self.baseline = self.repo / audit.BASELINE_PATH
        self.baseline.write_text(json.dumps({"schema_version": 1, "module": audit.MODULE, "version": "v0.58.0", "files": self.files}) + "\n", encoding="utf-8")
        self.original_baseline = self.baseline.read_bytes()
        self.go_calls = []
        self.mock_go = patch.object(audit, "run_go_json", side_effect=self.go_json)
        self.mock_go.start()
        self.addCleanup(self.mock_go.stop)

    def write_source(self, name, text):
        path = self.upstream / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))

    def go_json(self, repo, go, *arguments):
        self.go_calls.append(arguments)
        if arguments == ("list", "-m", "-json", audit.MODULE + "@latest"):
            return {"Path": audit.MODULE, "Version": "v0.59.0"}
        version = arguments[-1].split("@", 1)[1]
        source = self.root / "latest" if version == "v0.59.0" else self.upstream
        return {"Path": audit.MODULE, "Version": version, "Dir": str(source)}

    def run_check(self, *arguments):
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = audit.main(list(arguments), repo=self.repo)
        return code, json.loads(stream.getvalue())

    def test_default_check_does_not_change_baseline_or_fork(self):
        before = {str(path.relative_to(self.repo)): path.read_bytes() for path in self.repo.rglob("*") if path.is_file()}
        code, report = self.run_check()
        after = {str(path.relative_to(self.repo)): path.read_bytes() for path in self.repo.rglob("*") if path.is_file()}
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(before, after)
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertFalse(report["baseline_written"])

    def test_missing_local_copied_file_requires_review(self):
        name = "internal/h2/internal/httpcommon/request.go"
        (self.repo / name).unlink()
        code, report = self.run_check()
        self.assertEqual(code, 1)
        self.assertEqual(report["missing_local_files"], [name])

    def test_baseline_added_deleted_and_changed_files_require_review(self):
        self.write_source("http2/new.go", "package new\n")
        (self.upstream / "http2/server.go").unlink()
        self.write_source("internal/httpsfv/httpsfv.go", "package changed\n")
        code, report = self.run_check()
        self.assertEqual(code, 1)
        changes = report["baseline_source_changes"]
        self.assertEqual(changes["added"], ["http2/new.go"])
        self.assertEqual(changes["deleted"], ["http2/server.go"])
        self.assertEqual(changes["changed"], [{"file": "internal/httpsfv/httpsfv.go", "baseline_sha256": self.files["internal/httpsfv/httpsfv.go"], "observed_sha256": hashlib.sha256(b"package changed\n").hexdigest()}])
        self.assertEqual(self.baseline.read_bytes(), self.original_baseline)

    def test_latest_compares_module_root_internal_directories(self):
        latest = self.root / "latest"
        for name in self.files:
            path = latest / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((self.upstream / name).read_bytes())
        (latest / "internal/httpcommon/request.go").unlink()
        (latest / "internal/httpcommon/new.go").write_text("package new\n", encoding="utf-8")
        (latest / "internal/httpsfv/httpsfv.go").write_text("package changed\n", encoding="utf-8")
        code, report = self.run_check("--latest")
        self.assertEqual(code, 1)
        self.assertEqual(report["latest_version"], "v0.59.0")
        self.assertEqual(report["latest_source_changes"]["added"], ["internal/httpcommon/new.go"])
        self.assertEqual(report["latest_source_changes"]["deleted"], ["internal/httpcommon/request.go"])
        self.assertEqual(report["latest_source_changes"]["changed"][0]["file"], "internal/httpsfv/httpsfv.go")
        self.assertEqual(self.baseline.read_bytes(), self.original_baseline)

    def test_go_mod_version_mismatch_requires_review(self):
        (self.repo / "go.mod").write_text("module example.test/fork\nrequire golang.org/x/net v0.59.0 // pinned\n", encoding="utf-8")
        code, report = self.run_check()
        self.assertEqual(code, 1)
        self.assertEqual(report["go_mod_version"], "v0.59.0")
        self.assertEqual(report["baseline_version"], "v0.58.0")

    def test_source_selection_excludes_wrappers_tests_and_nested_packages(self):
        for name in ("http2/server_wrap.go", "http2/transport_wrap.go", "http2/transport_test.go", "http2/hpack/encode.go", "http2/internal/httpcommon/request.go", "internal/httpcommon/request_test.go"):
            self.write_source(name, "package excluded\n")
        self.assertEqual(audit.source_hashes(self.upstream), self.files)

    def test_explicit_write_updates_hash_after_review(self):
        self.write_source("http2/transport.go", "package updated\n")
        code, report = self.run_check("--write-baseline")
        self.assertEqual(code, 0)
        self.assertTrue(report["baseline_written"])
        self.assertEqual(json.loads(self.baseline.read_bytes())["files"], audit.source_hashes(self.upstream))

    def test_write_latest_requires_matching_go_mod_pin(self):
        code, report = self.run_check("--latest", "--write-baseline")
        self.assertEqual(code, 2)
        self.assertIn("align go.mod", report["message"])
        self.assertEqual(self.baseline.read_bytes(), self.original_baseline)

    def test_write_baseline_refuses_missing_local_files(self):
        self.write_source("http2/new.go", "package new\n")
        code, report = self.run_check("--write-baseline")
        self.assertEqual(code, 2)
        self.assertEqual(self.baseline.read_bytes(), self.original_baseline)

    def test_explicit_report_contains_no_machine_paths(self):
        report_path = self.root / "reports" / "review.json"
        code, report = self.run_check("--report", str(report_path))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(report_path.read_bytes()), report)
        self.assertNotIn(str(self.root), report_path.read_text(encoding="utf-8"))

    def test_report_cannot_overwrite_baseline(self):
        with redirect_stdout(io.StringIO()), patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            audit.main(["--report", str(self.baseline)], repo=self.repo)
        self.assertEqual(self.baseline.read_bytes(), self.original_baseline)


if __name__ == "__main__":
    unittest.main()
