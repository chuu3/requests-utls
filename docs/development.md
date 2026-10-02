# Development guide

This repository owns the Go transport, TLS profile compiler, C ABI and native
artifact builder. Python API changes belong in
[requests-utls-python](https://github.com/chuu3/requests-utls-python).

All shell commands run from the repository root unless stated otherwise.

## Build and test

Use a Go toolchain satisfying `go.mod`, Python 3.11+, and a C compiler for the
race detector and shared library. Release wheels currently use Go 1.27.1;
the Python project's `engine.lock.json` is the release source of truth.

```sh
git clone https://github.com/chuu3/requests-utls.git
cd requests-utls
make check
python3 -m unittest discover -s scripts -p 'test_*.py'
make shared testpeer
```

Set `GO=/absolute/path/to/go` for Make targets when needed. Shared libraries are
written under `dist/`; the independent test peer is under `bin/`. CI repeats
the race tests and native packaging checks on Linux, macOS and Windows. The
ordinary test suite uses local servers and needs no proxy or external account.

For a transport change, add a regression that observes the actual handshake,
headers, frames, cancellation or connection reuse. Keep caller inputs isolated
and preserve repeated header occurrences. Run the affected tests while editing,
then `make check` before submitting the final change. Do not replace wire checks
with assertions against the implementation's own intermediate structures.

## Profiles and reports

Describe the expected behavior, actual behavior, engine commit, Go version,
operating system and a minimal example. Include a sanitized profile only when
necessary. Remove authentication, cookies, personal addresses, connection
identifiers, captured keys and session tickets from reports. Ordinary test
fixtures should use loopback servers and synthetic credentials.

Profile support has several distinct levels; use the
[capability table](../docs/profile-capabilities.md) when describing results.
Importing a cipher or extension ID does not establish complete negotiation
support. New captures must have a documented source and permission to redistribute
their sanitized protocol configuration.

## Changes and compatibility

Keep Go and Python changes in their respective repositories and cross-link
related pull requests. A Python engine update pins an exact, reachable Go commit;
it does not copy the Go source into the Python project. Describe the trigger,
resulting behavior, tests and any wire-format or compatibility changes in the PR.

The projects are in the 0.x series. Patch releases should preserve public API and
profile semantics except for documented correctness and security fixes. Planned
breaking changes belong in a minor release with migration notes. Changes to the
C contract must update `include/requests_utls.h`, ABI documentation and both sides
of the binding; ABI 1 must not silently acquire incompatible semantics.

Retain copyright and license notices. Binary artifacts must include the notices
for the Go runtime, the local HTTP/2 fork and all linked modules. See
[maintenance](../docs/maintenance.md) for upstream reviews and
[SECURITY.md](../SECURITY.md) for confidential reports.
