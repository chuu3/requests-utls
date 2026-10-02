# Contributing

This repository owns the Go engine and native ABI. Python changes belong in
[requests-utls-python](https://github.com/chuu3/requests-utls-python).

Use Go satisfying `go.mod`, Python 3.11+, and a C compiler. From the repository root:

```sh
make check
python3 -m unittest discover -s scripts -p 'test_*.py'
make shared testpeer
```

Set `GO=/absolute/path/to/go` when needed. For transport changes, test actual wire
behavior, concurrency and resource cleanup using local peers and synthetic data.
Preserve request isolation, duplicate fields and ABI ownership. Describe changes,
validation and compatibility effects; remove credentials and private captures.

See the [development guide](docs/development.md) for compatibility, profile
provenance and CI requirements, and [maintenance](docs/maintenance.md) for upstream
updates. Retain copyright/license notices. Report vulnerabilities via
[SECURITY.md](SECURITY.md).
