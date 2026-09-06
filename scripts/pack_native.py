#!/usr/bin/env python3
"""Build the versioned native payload consumed by requests-utls Python wheels.

Requires Python 3.11+, Go, a C compiler, and the platform's binary inspection
tool (otool, readelf, or objdump). Never overwrites an existing native library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
EXTENSIONS = {"linux": ".so", "darwin": ".dylib", "windows": ".dll"}
LICENSE_NAME = re.compile(r"^(?:licen[sc]e|notice|copying|patents)(?:[._-].*)?$", re.I)


def run(*args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        args, cwd=ROOT, env=env, check=True, text=True, stdout=subprocess.PIPE
    ).stdout


def json_stream(value: str) -> list[dict]:
    decoder = json.JSONDecoder()
    values = []
    while value.strip():
        value = value.lstrip()
        item, end = decoder.raw_decode(value)
        values.append(item)
        value = value[end:]
    return values


def version_tuple(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        raise ValueError(f"invalid numeric version: {value!r}")
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * max(0, 3 - len(parts))


def validate_platform(goos: str, goarch: str, tag: str) -> str | None:
    expected = {
        ("linux", "amd64"): "linux_x86_64",
        ("linux", "arm64"): "linux_aarch64",
        ("windows", "amd64"): "win_amd64",
    }.get((goos, goarch))
    if expected:
        if tag != expected:
            raise ValueError(f"{goos}/{goarch} requires initial wheel tag {expected}")
        return None
    if goos == "darwin" and goarch in {"amd64", "arm64"}:
        arch_tag = "x86_64" if goarch == "amd64" else "arm64"
        match = re.fullmatch(rf"macosx_(\d+)_(\d+)_{arch_tag}", tag)
        if match:
            minimum = ".".join(match.groups())
            if version_tuple(minimum) >= (13, 0, 0):
                return minimum
        raise ValueError(f"{goos}/{goarch} requires macosx_13_0_{arch_tag} or later")
    raise ValueError(f"unsupported native wheel target: {goos}/{goarch}")


def fresh_directory(path: Path) -> None:
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError(f"output must be a new or empty directory: {path}")
    path.mkdir(parents=True, exist_ok=True)


def copy_file(source: Path, target: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"expected a regular payload source: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def copy_notices(source: Path, target: Path) -> list[str]:
    copied = []
    for path in sorted(source.rglob("*")):
        if path.is_file() and LICENSE_NAME.fullmatch(path.name):
            relative = path.relative_to(source)
            copy_file(path, target / relative)
            copied.append(relative.as_posix())
    if not copied:
        raise ValueError(f"no license or notice files found for {source.name}")
    return copied


def collect_licenses(output: Path, goenv: dict, packages: list[dict]) -> list[dict]:
    licenses = output / "licenses"
    copy_file(ROOT / "LICENSE", licenses / "requests-utls" / "LICENSE")
    copy_file(ROOT / "internal/h2/LICENSE", licenses / "requests-utls" / "internal/h2/LICENSE")
    goroot = Path(goenv["GOROOT"])
    copy_file(goroot / "LICENSE", licenses / "go" / "LICENSE")
    if (goroot / "PATENTS").is_file():
        copy_file(goroot / "PATENTS", licenses / "go" / "PATENTS")
    # The standard library includes independently licensed vendored packages.
    if (goroot / "src/vendor").is_dir():
        copy_notices(goroot / "src/vendor", licenses / "go" / "src/vendor")
    boring_license = goroot / "src/crypto/internal/boring/LICENSE"
    if boring_license.is_file():
        copy_file(boring_license, licenses / "go" / "src/crypto/internal/boring/LICENSE")

    modules = {}
    for package in packages:
        module = package.get("Module")
        if module and not module.get("Main"):
            modules[module["Path"]] = module
    dependencies = []
    for name, module in sorted(modules.items()):
        if "Replace" in module:
            raise ValueError(f"release builds require unreplaced, pinned modules: {name}")
        module_version = module["Version"]
        source = Path(module["Dir"])
        notices = copy_notices(source, licenses / "modules" / f"{name}@{module_version}")
        dependencies.append({
            "module": name, "version": module_version,
            "sum": module.get("Sum"), "notices": notices,
        })
    return dependencies


def inspect_binary(library: Path, goos: str, minimum_os: str | None,
                   glibc_baseline: str | None) -> dict:
    if goos == "darwin":
        commands = run("otool", "-l", str(library))
        versions = re.findall(r"\bminos\s+(\d+(?:\.\d+)*)", commands)
        versions += re.findall(
            r"cmd LC_VERSION_MIN_MACOSX\s+cmdsize \d+\s+version (\d+(?:\.\d+)*)", commands
        )
        if not versions:
            raise ValueError("cannot determine the Mach-O deployment target")
        actual = max(versions, key=version_tuple)
        if version_tuple(actual) > version_tuple(minimum_os or "0"):
            raise ValueError(f"Mach-O requires macOS {actual}, above wheel tag {minimum_os}")
        lines = run("otool", "-L", str(library)).splitlines()[2:]
        dependencies = [line.strip().split(" (", 1)[0] for line in lines]
        for dependency in dependencies:
            if not dependency.startswith(("/usr/lib/", "/System/Library/")):
                raise ValueError(f"unbundled non-system macOS library: {dependency}")
        return {"minimum_os": actual, "dynamic_dependencies": dependencies}
    if goos == "linux":
        versions = run("readelf", "--version-info", str(library))
        required = re.findall(r"\bGLIBC_(\d+(?:\.\d+)+)", versions)
        maximum = max(required, key=version_tuple) if required else None
        if glibc_baseline:
            if maximum is None:
                raise ValueError("cannot verify a glibc baseline without GLIBC symbol versions")
            if version_tuple(maximum) > version_tuple(glibc_baseline):
                raise ValueError(f"ELF requires glibc {maximum}, above requested {glibc_baseline}")
        needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", run("readelf", "-d", str(library)))
        return {"libc": {"family": "glibc", "maximum_required_symbol": maximum,
                         "build_baseline": glibc_baseline}, "dynamic_dependencies": needed}
    imports = run(os.environ.get("OBJDUMP", "objdump"), "-p", str(library))
    return {"minimum_os": "Windows 10", "dynamic_dependencies": sorted(set(
        re.findall(r"DLL Name:\s*(\S+)", imports)
    ))}


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build(args: argparse.Namespace) -> dict:
    output = args.output.resolve()
    env = dict(os.environ, CGO_ENABLED="1")
    goenv = json.loads(run(args.go, "env", "-json", "GOOS", "GOARCH", "GOROOT", "GOVERSION", env=env))
    goos, goarch = goenv["GOOS"], goenv["GOARCH"]
    minimum_os = validate_platform(goos, goarch, args.wheel_platform)
    if args.glibc_baseline:
        if goos != "linux":
            raise ValueError("--glibc-baseline only applies to Linux")
        version_tuple(args.glibc_baseline)
    if goos == "darwin":
        deployment = env.setdefault("MACOSX_DEPLOYMENT_TARGET", minimum_os or "13.0")
        if version_tuple(deployment) < (13, 0, 0):
            raise ValueError("Go 1.27 native artifacts require macOS 13.0 or later")
        if version_tuple(deployment) > version_tuple(minimum_os or "0"):
            raise ValueError("MACOSX_DEPLOYMENT_TARGET exceeds the wheel platform tag")
    # Baseline Go instruction sets also matter independently of the ELF ABI tag.
    env.setdefault("GOAMD64", "v1")
    env.setdefault("GOARM64", "v8.0")
    if goarch == "amd64" and env["GOAMD64"] != "v1":
        raise ValueError("portable amd64 wheels require GOAMD64=v1")
    if goarch == "arm64" and env["GOARM64"] != "v8.0":
        raise ValueError("portable arm64 wheels require GOARM64=v8.0")
    commit = run("git", "rev-parse", "HEAD").strip()
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("cannot identify the exact engine commit")
    dirty = bool(run("git", "status", "--porcelain", "--untracked-files=normal").strip())
    if args.require_clean and dirty:
        raise ValueError("--require-clean rejects modified or untracked source files")
    peer = (args.peer_output or output.with_name(output.name + "-testing") /
            ("requests-utls-testpeer.exe" if goos == "windows" else "requests-utls-testpeer")).resolve()
    if peer == output or output in peer.parents:
        raise ValueError("the test peer must be outside the wheel payload directory")
    if peer.exists():
        raise ValueError(f"refusing to overwrite existing test peer: {peer}")
    fresh_directory(output)
    peer.parent.mkdir(parents=True, exist_ok=True)
    library = output / "native" / ("librequests_utls" + EXTENSIONS[goos])
    library.parent.mkdir(parents=True)
    ldflags = "-s -w -buildid="
    if goos == "windows":
        ldflags += " -extldflags=-static-libgcc"
    common = ("build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=" + ldflags)
    run(args.go, *common, "-buildmode=c-shared", "-o", str(library), "./cmd/requests-utls-shared", env=env)
    # c-shared generates a header for C consumers, which is not a Python runtime file.
    library.with_suffix(".h").unlink(missing_ok=True)
    run(args.go, *common, "-o", str(peer), "./cmd/requests-utls-testpeer", env=env)
    packages = json_stream(run(args.go, "list", "-mod=readonly", "-deps", "-json",
                               "./cmd/requests-utls-shared", env=env))
    dependencies = collect_licenses(output, goenv, packages)
    copy_file(ROOT / "profiles/chrome_152.json", output / "profiles/chrome_152.json")
    manifest = {
        "schema_version": 1, "abi_version": 1,
        "engine_version": args.engine_version, "engine_commit": commit,
        "source_dirty": dirty, "go_version": goenv["GOVERSION"],
        "goos": goos, "goarch": goarch, "wheel_platform": args.wheel_platform,
        "library": library.relative_to(output).as_posix(), "sha256": sha256(library),
        "dependencies": dependencies,
        **inspect_binary(library, goos, minimum_os, args.glibc_baseline),
        "files_sha256": {path.relative_to(output).as_posix(): sha256(path)
                         for path in sorted(output.rglob("*")) if path.is_file()},
    }
    # Fixed key order and no timestamp or workstation path in the manifest.
    (output / "engine.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--go", default="go", help="Go executable (default: go on PATH)")
    parser.add_argument("--wheel-platform", required=True)
    parser.add_argument("--engine-version", "--version", default="v0.1.0")
    parser.add_argument("--peer-output", type=Path)
    parser.add_argument("--glibc-baseline", help="reject ELF symbols newer than this glibc version")
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()
    try:
        manifest = build(args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"native packaging failed: {error}\n")
    print(json.dumps({"engine_commit": manifest["engine_commit"],
                      "wheel_platform": manifest["wheel_platform"],
                      "library": manifest["library"], "sha256": manifest["sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
