# requests-utls

Go engine for profile-driven TLS, concurrent Sessions, and ordered HTTP/1.1 and
HTTP/2 headers, including repeated fields. The separate
[Python client](https://github.com/chuu3/requests-utls-python) bundles this engine
through CFFI; this repository owns the Go API and native ABI.

## Quick start

Requires Go 1.26+; native libraries and race tests also require a C compiler.
Run from the repository root:

```sh
make check
go run ./cmd/requests-utls validate -profile profiles/chrome_152.json
make shared
```

See the [Go API example](docs/usage.md#use-the-go-api) and
[native ABI](docs/abi.md) for embedding the engine.

## Behavior

- Immutable TLS profiles, request-level header order, and concurrent Sessions.
- HTTP/2 and HTTP/1.1 with ALPN fallback, connection reuse and TLS resumption.
- Authenticated HTTP CONNECT proxies and certificate verification by default.
- Bounded buffered responses with gzip, deflate, Brotli and Zstandard decoding.
- **No automatic redirects or Cookie state management.** Responses retain
  Location and Set-Cookie; callers decide subsequent requests and Cookie updates.
  Connection pooling, cancellation and cleanup remain engine responsibilities.

A matching fingerprint does not imply complete browser behavior. Some profile
extensions are advertisement-only; see [profile capabilities](docs/profile-capabilities.md).
Streaming, HTTP/3 and HTTPS/SOCKS proxy connections are not supported.

## Documentation

| Task | Guide |
| --- | --- |
| Why redirects and Cookie state are caller-owned | [Design rationale (中文)](docs/redirects-and-cookies.md) |
| Limit physical connection lifetime | [Parameters and interfaces (中文)](docs/connection-lifetime.md) |
| Go API, header order, profiles and CLI | [Usage](docs/usage.md) |
| Bind another language | [ABI](docs/abi.md), [native artifacts](docs/native-artifacts.md) |
| Understand validation evidence | [Verification](docs/verification.md) |
| Develop or maintain the engine | [Contributing](CONTRIBUTING.md), [maintenance](docs/maintenance.md) |
| Review changes or report a vulnerability | [Changelog](CHANGELOG.md), [security](SECURITY.md) |
