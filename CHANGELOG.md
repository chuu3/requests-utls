# Changelog

## Unreleased

- Update x/net and the local HTTP/2 fork to v0.60.0 security fixes; use Go
  1.27.2 for CI and native builds. Sanitize unsafe H2 response framing headers
  in both map and ordered output.

- Add opt-in physical connection age and per-connection jitter, including HTTP/2
  draining through response body completion and HTTP/1 pool retirement.
- Disabled by default; retains Session state and TLS resumption.

## 0.3.1 — 2026-10-02

- Preserve proxy CONNECT socket timeout classification when the socket deadline
  fires before the context timer, without exposing malformed proxy responses.
- Add deterministic regression coverage across Windows, macOS and Linux.
- Separate third-party notices from the project's MIT license text.
- No public API, TLS profile or native ABI changes; ABI remains version 1.

## 0.3.0 — 2026-10-02

- Add independent connect, proxy CONNECT, TLS handshake, response-header and
  response-body timeouts, plus structured error stages and elapsed time.
- Normalize socket deadline errors and preserve HTTP/2 stream isolation when
  header/body deadlines expire.
- Connection setup now has separate 10-second connect, proxy CONNECT and TLS
  budgets instead of one combined budget; the total request deadline still wins.
  Header/body phase limits are disabled by default. ABI remains version 1.
- Sync the HTTP/2 fork to x/net v0.59.0 (Go 1.26+), update compression libraries,
  and batch ordinary Dependabot updates monthly.
- Simplify documentation and clarify caller-owned redirects and Cookie state.

See the [full changelog](docs/changelog.md) for earlier releases.
