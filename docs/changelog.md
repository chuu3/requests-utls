# Full changelog

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

## 0.2.2 — 2026-09-07

- Normalize headers in the Go engine for the actual negotiated protocol: H2
  consumes Host as :authority and removes connection-specific fields and
  Connection-nominated fields before ordering; H1 always has Host and puts it
  first unless request-level HeadersOrder specifies its position. Preserve
  snapshots and connection reuse across automatic ALPN handoffs without new
  Python API or C ABI options.
- Bundle distinct Chrome 150 and 152 captures through a declared profile index,
  preserving each capture's ordering and advertised-only limitations.
- Combine Cookie occurrences only for actual HTTP/1.1 requests, after applying
  occurrence-level ordering; HTTP/2 keeps separate Cookie fields.
- Limit automatic response decoding to four non-identity encoding layers before
  reading body bytes or allocating decoders. Raw response mode remains available.
- Resolve ambiguous HTTP/1 header ordering after ALPN when the peer can select
  HTTP/2, preserving the established connection and HTTP/1 validation rules.
- Package Go CI binaries with the Go runtime, local fork and all linked module
  license notices, including dependencies used only by the test peer.
- Add upstream HTTP/2 baseline checks, scheduled dependency checks and contributor
  documentation.

## 0.2.1

Engine revision bundled with requests-utls Python 0.2.1:
`13ea2f55c4fed7505c2933cfe8dbd65ec64cdcb7`, ABI 1.

- Recalculate Content-Length from body bytes and include generated fields in
  request-local ordering for HTTP/1.1 and HTTP/2.
- Preserve supplied HTTP/1.1 field spelling and reject repeated Content-Length.
