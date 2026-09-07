"""Checks for artifact portability and preservation of redistribution notices."""

import argparse
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

import pack_native


class NativePackagingTests(unittest.TestCase):
    def test_go_json_is_utf8_even_when_windows_uses_an_ansi_locale(self):
        expected = '{"Doc": "header “cookie” and 请求"}\n'
        program = "import sys; sys.stdout.buffer.write(bytes.fromhex(" + repr(expected.encode().hex()) + "))"
        # Simulate Windows' cp1252 default. The curly closing quote contains
        # byte 0x9d in UTF-8, which that codec cannot decode at all.
        with patch("subprocess._text_encoding", return_value="cp1252"):
            self.assertEqual(pack_native.run(sys.executable, "-c", program), expected)

    def test_architecture_and_os_cannot_be_relabelled(self):
        with self.assertRaises(ValueError):
            pack_native.validate_platform("linux", "arm64", "linux_x86_64")
        with self.assertRaises(ValueError):
            pack_native.validate_platform("windows", "arm64", "win_amd64")
        with self.assertRaises(ValueError):
            pack_native.validate_platform("linux", "amd64", "manylinux_2_28_x86_64")

    def test_go_127_macos_floor_applies_to_both_architectures(self):
        for goarch, wheelarch in (("arm64", "arm64"), ("amd64", "x86_64")):
            with self.subTest(arch=goarch):
                with self.assertRaises(ValueError):
                    pack_native.validate_platform("darwin", goarch, f"macosx_12_0_{wheelarch}")
                self.assertEqual(pack_native.validate_platform(
                    "darwin", goarch, f"macosx_13_0_{wheelarch}"), "13.0")

    def test_output_cannot_replace_loaded_or_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifact"
            pack_native.fresh_directory(output)
            native = output / "librequests_utls.so"
            native.write_bytes(b"already in use")
            with self.assertRaises(ValueError):
                pack_native.fresh_directory(output)
            self.assertEqual(native.read_bytes(), b"already in use")

    def test_nested_notices_are_preserved_without_basename_collisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "module"
            (source / "nested").mkdir(parents=True)
            (source / "LICENSE").write_text("top-level license")
            (source / "nested/LICENSE").write_text("another license")
            (source / "nested/NOTICE.txt").write_text("attribution")
            (source / "source.go").write_text("not part of wheel payload")
            destination = Path(temporary) / "licenses"
            pack_native.copy_notices(source, destination)
            self.assertEqual((destination / "LICENSE").read_text(), "top-level license")
            self.assertEqual((destination / "nested/LICENSE").read_text(), "another license")
            self.assertTrue((destination / "nested/NOTICE.txt").is_file())
            self.assertFalse((destination / "source.go").exists())

    def test_distribution_collects_notices_for_library_and_peer_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, goroot = root / "source", root / "go"
            for relative in ("LICENSE", "internal/h2/LICENSE", "profiles/chrome_150.json", "profiles/chrome_152.json"):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"schema_version":1}' if relative.endswith(".json") else relative)
            (source / "profiles/builtin.json").write_text(json.dumps({"schema_version": 1, "profiles": ["chrome_150", "chrome_152"]}))
            (source / "profiles/profile.schema.json").write_text('{"not_a_profile":true}')
            (source / "profiles/README.md").write_text("profile documentation")
            goroot.mkdir()
            (goroot / "LICENSE").write_text("Go license")
            packages = {}
            for name, target in (("library", "./cmd/requests-utls-shared"),
                                 ("peer-only", "./cmd/requests-utls-testpeer")):
                directory = root / name
                (directory / "nested").mkdir(parents=True)
                (directory / "LICENSE").write_text(name + " license")
                (directory / "nested/NOTICE").write_text(name + " notice")
                packages[target] = {"Module": {
                    "Path": "example.invalid/" + name, "Version": "v1.0.0",
                    "Dir": str(directory), "Sum": "h1:test",
                }}

            def fake_run(*command, env=None):
                if command[:2] == ("go", "env"):
                    return json.dumps({"GOOS": "linux", "GOARCH": "amd64",
                                       "GOROOT": str(goroot), "GOVERSION": "go1.27.1"})
                if command[:2] == ("git", "rev-parse"):
                    return "1" * 40
                if command[:2] == ("git", "status"):
                    return ""
                if command[:2] == ("go", "build"):
                    output = Path(command[command.index("-o") + 1])
                    output.write_bytes(b"binary")
                    return ""
                if command[:2] == ("go", "list"):
                    return "\n".join(json.dumps(packages[target])
                                     for target in command if target in packages)
                self.fail(f"unexpected packaging command {command[:2]}")

            output, peer = root / "artifact", root / "testing/testpeer"
            args = argparse.Namespace(output=output, peer_output=peer, go="go",
                                      wheel_platform="linux_x86_64", glibc_baseline=None,
                                      engine_version="v0.2.1", require_clean=True)
            with patch.object(pack_native, "ROOT", source), \
                    patch.object(pack_native, "run", side_effect=fake_run), \
                    patch.object(pack_native, "inspect_binary", return_value={}):
                manifest = pack_native.build(args)

            self.assertTrue((output / "native/librequests_utls.so").is_file())
            self.assertTrue(peer.is_file())
            self.assertEqual(manifest["builtin_profiles"], ["chrome_150", "chrome_152"])
            self.assertEqual({path.name for path in (output / "profiles").iterdir()}, {"chrome_150.json", "chrome_152.json"})
            for name in manifest["builtin_profiles"]:
                relative = "profiles/" + name + ".json"
                self.assertEqual(manifest["files_sha256"][relative], pack_native.sha256(output / relative))
            self.assertEqual({d["module"] for d in manifest["dependencies"]},
                             {"example.invalid/library", "example.invalid/peer-only"})
            for name in ("library", "peer-only"):
                prefix = f"licenses/modules/example.invalid/{name}@v1.0.0"
                self.assertEqual((output / prefix / "nested/NOTICE").read_text(), name + " notice")
                self.assertIn(prefix + "/LICENSE", manifest["files_sha256"])
                self.assertIn(prefix + "/nested/NOTICE", manifest["files_sha256"])
            for path in ("licenses/requests-utls/LICENSE", "licenses/requests-utls/internal/h2/LICENSE",
                         "licenses/go/LICENSE"):
                self.assertIn(path, manifest["files_sha256"])

    def test_profile_index_rejects_missing_files_and_invalid_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "profiles").mkdir()
            index = root / "profiles/builtin.json"
            for names in (["missing"], ["../escape"], ["one", "one"], [], "chrome_150"):
                with self.subTest(names=names):
                    index.write_text(json.dumps({"schema_version": 1, "profiles": names}), encoding="utf-8")
                    with patch.object(pack_native, "ROOT", root), self.assertRaises(ValueError):
                        pack_native.collect_profiles(root / "output")

    def test_macos_binary_cannot_require_newer_os_than_its_wheel(self):
        with patch.object(pack_native, "run", return_value="cmd LC_BUILD_VERSION\nminos 14.0\n"):
            with self.assertRaisesRegex(ValueError, "above wheel tag"):
                pack_native.inspect_binary(Path("library.dylib"), "darwin", "13.0", None)

    def test_macos_binary_cannot_depend_on_build_machine_homebrew(self):
        outputs = ["cmd LC_BUILD_VERSION\nminos 13.0\n",
                   "library.dylib:\n\tlibrary.dylib (compatibility version 0.0.0)\n"
                   "\t/opt/homebrew/lib/unbundled.dylib (compatibility version 1.0.0)\n"]
        with patch.object(pack_native, "run", side_effect=outputs):
            with self.assertRaisesRegex(ValueError, "non-system"):
                pack_native.inspect_binary(Path("library.dylib"), "darwin", "13.0", None)

    def test_manylinux_baseline_rejects_newer_required_glibc(self):
        with patch.object(pack_native, "run", return_value="GLIBC_2.2.5 GLIBC_2.34"):
            with self.assertRaisesRegex(ValueError, "above requested 2.28"):
                pack_native.inspect_binary(Path("library.so"), "linux", None, "2.28")

    def test_glibc_version_comparison_is_numeric(self):
        outputs = ["GLIBC_2.2.5 GLIBC_2.9 GLIBC_2.28", "(NEEDED) Shared library: [libc.so.6]"]
        with patch.object(pack_native, "run", side_effect=outputs):
            result = pack_native.inspect_binary(Path("library.so"), "linux", None, "2.28")
            self.assertEqual(result["libc"]["maximum_required_symbol"], "2.28")
            self.assertEqual(result["dynamic_dependencies"], ["libc.so.6"])

    def test_manylinux_baseline_cannot_be_assumed_for_musl(self):
        with patch.object(pack_native, "run", return_value="No version information found"):
            with self.assertRaisesRegex(ValueError, "without GLIBC symbol versions"):
                pack_native.inspect_binary(Path("library.so"), "linux", None, "2.28")


if __name__ == "__main__":
    unittest.main()
