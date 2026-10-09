# Native payloads for Python wheels

The Go repository produces a versioned directory of runtime files. The separate
Python repository consumes that directory when building a wheel; end users do
not need a Go compiler, GitHub access, or a separate engine download.

Build a local Apple Silicon payload with Go 1.27.2 and the Xcode command line tools:

```sh
MACOSX_DEPLOYMENT_TARGET=13.0 python3 scripts/pack_native.py \
  --go go \
  --output dist/native-macos-arm64 \
  --wheel-platform macosx_13_0_arm64 \
  --version v0.1.0 \
  --require-clean
```

The output directory must be new or empty. The script will not overwrite a
native library or a test peer that another process might be using.

```text
dist/native-macos-arm64/
  engine.json
  native/librequests_utls.dylib
  profiles/chrome_150.json
  profiles/chrome_152.json
  licenses/requests-utls/...
  licenses/go/...
  licenses/modules/...
dist/native-macos-arm64-testing/
  requests-utls-testpeer
```

`--peer-output PATH` changes the test executable destination. It must stay outside
the runtime payload; test infrastructure is excluded from wheels. Generated C
headers are also excluded; C clients use the Go repository's
[`include/requests_utls.h`](../include/requests_utls.h).

`profiles/builtin.json` is the source list for bundled profiles. The builder
copies only the declared files and records their names in the manifest's
`builtin_profiles` array. All profile bytes are included in `files_sha256`.
The source index and JSON schema are not installed as TLS profiles.

## Supported build targets

| Build environment | Initial wheel platform | Extra build configuration |
| --- | --- | --- |
| manylinux_2_28 x86_64 container | `linux_x86_64` | `--glibc-baseline 2.28` |
| manylinux_2_28 aarch64 container | `linux_aarch64` | `--glibc-baseline 2.28` |
| macOS Intel runner | `macosx_13_0_x86_64` | `MACOSX_DEPLOYMENT_TARGET=13.0` |
| macOS Apple Silicon runner | `macosx_13_0_arm64` | `MACOSX_DEPLOYMENT_TARGET=13.0` |
| Windows x64 runner with MinGW-w64 | `win_amd64` | Set `CC` and put `objdump` on `PATH` |

Linux artifacts are initially tagged `linux_*`. The Python release workflow runs
`auditwheel` on the assembled wheel before assigning its `manylinux_2_28_*` tag.
Merely naming an artifact manylinux-compatible is insufficient. The native
script checks the actual ELF glibc symbol requirements using `readelf`; the
release workflow checks the final wheel's external dependencies.
[Manylinux build images and compatibility rules](https://github.com/pypa/manylinux).

The macOS floor is 13.0 because that is the minimum supported by Go 1.27.
The script checks the dylib's Mach-O deployment target with `otool`, rejects a
wheel tag that promises an older OS, and rejects non-system dynamic libraries.
[Go 1.27 platform requirements](https://go.dev/doc/go1.27#darwin).

`GOOS`, `GOARCH`, `CC`, and normal cgo compiler flags are honored. The build turns
on cgo and requires baseline `GOAMD64=v1` / `GOARM64=v8.0` instruction sets. Build
each release artifact in its matching operating-system environment with a pinned
Go toolchain. On Windows, libgcc is linked statically; the final wheel workflow
must inspect and bundle any other non-system runtime dependencies.

## Artifact contract

`engine.json` contains schema version 1, ABI version 1, `engine_version`, the exact
`engine_commit`, `source_dirty`, `go_version`, `goos`, `goarch`, `wheel_platform`,
the relative `library` path, and that file's `sha256`. `files_sha256` covers every
runtime file except the manifest itself. License files retain their original
directory hierarchy, including nested third-party notices. The manifest lists
the versions and Go module checksums of dependencies linked into either the
library or its accompanying test peer. Wheels retain this complete set of
notices even though they exclude the peer executable. The manifest also records
the native library's platform requirements and dynamic
dependencies.

Go CI labels its downloadable payloads `v0.0.0-dev.<full-commit-sha>`. This is an
unpublished development snapshot label accepted by the Python artifact builder,
not a Go or Python release version. CI includes the runtime payload under
`dist/native-artifact/` and its peer under `dist/testing/`, with the complete
license set in the payload. The Python release workflow instead supplies
`v<python-package-version>` as the artifact's release label. In both cases,
`engine_commit` identifies the exact independent Go source revision; neither
label replaces that pin or the ABI check. Ordinary Go CI artifacts are not
audited manylinux release wheels.

There are no generation timestamps or local build paths in the manifest. Go
builds use `-trimpath`, disable automatic VCS metadata, and remove debug symbols
and the Go build ID. File checksums still identify the precise output of the
selected toolchain; this is not a promise that different C compilers or SDKs
produce identical binaries.

The Python builder validates this manifest against its engine lock before
assembling a wheel. If a platform repair tool changes or adds native files, the
Python release workflow refreshes the bundled file checksums after repair.

Run packaging guard tests with:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```
