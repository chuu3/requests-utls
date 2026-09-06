"""Checks for artifact portability and preservation of redistribution notices."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pack_native


class NativePackagingTests(unittest.TestCase):
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
