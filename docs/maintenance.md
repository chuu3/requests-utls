# Maintaining the engine

## Dependencies and the HTTP/2 fork

Dependabot checks Go modules and GitHub Actions weekly. Dependency changes are
reviewed through the ordinary test workflow. The scheduled security workflow
also runs the Go vulnerability checker:

```sh
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

[govulncheck](https://go.dev/doc/security/vuln/) reports known vulnerabilities
using module, package and call information. The copied `internal/h2` code has
different import paths; review relevant upstream advisories against that code
even when the scanner reports no reachable vulnerable symbol.

`internal/h2/upstream.json` records the original source file hashes from the
pinned x/net version. It is distinct from the intentionally modified local
files. Check the baseline and compare the latest upstream release with:

```sh
python3 scripts/check_http2_upstream.py
python3 scripts/check_http2_upstream.py --latest --report dist/upstream-review.json
```

The first command checks the dependency pin and source baseline. The second
also checks upstream additions, removals and changed source files; relevant
changes fail the scheduled job for maintainer review. Neither command updates
the fork or accepts a new baseline. The tools download public Go modules when
they are absent from the module cache. `--go /absolute/path/to/go` selects the
toolchain.

For an update:

1. Read the upstream release notes and advisories and compare affected files.
2. Apply required upstream changes while preserving the local changes described
   in [UPSTREAM.md](../internal/h2/UPSTREAM.md). Updating `go.mod` alone does not
   change the copied transport.
3. Update the dependency pin, provenance notes and regression tests. After the
   source review, explicitly regenerate the baseline:
   `python3 scripts/check_http2_upstream.py --write-baseline`.
4. Run the baseline check, script tests and `make check`. For binding changes,
   run the Python native suite with the resulting shared library and test peer.

The baseline and tests record evidence; they do not replace review of protocol
semantics or establish full browser equivalence.

## Versions and artifacts

Go and Python versions may evolve independently. Git tags identify released
source revisions; `engine.lock.json` in Python identifies the exact bundled
engine commit, toolchain and ABI. Never move a published tag or replace a PyPI
file. Record unreleased changes in `CHANGELOG.md` and create a new version when
publishing fixes.

Native CI artifacts contain the library, independent test peer, public C header,
profile, provenance and license notices. Wheel artifacts are separately audited
for their advertised platform. Keep the peer out of the installed wheel.

Builds record their source and toolchain, but are not currently guaranteed to
produce byte-identical output across different compilers or runner images.
