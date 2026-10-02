# Changelog

## Unreleased

- Add connection, proxy CONNECT, TLS, response-header and body phase timeouts
  with structured error stages; normalize socket deadline errors consistently.
- Batch ordinary Dependabot updates monthly and refresh compression/CI dependencies.

- Shorten root documentation; move detailed usage, development and release history to `docs/`.

- Sync the HTTP/2 fork and dependencies to x/net v0.59.0; require Go 1.26+.
- Clarify caller-owned redirects and Cookie state management.
- Retain protocol-aware ordered headers, Chrome 150/152 profiles and bounded decoding.

See the [full changelog](docs/changelog.md) for detailed development changes and
historical engine revisions.
