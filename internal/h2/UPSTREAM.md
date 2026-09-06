# Upstream provenance and local changes

The non-test top-level Go files in this directory, except `ordered_headers.go`
and `wire_profile.go`, were copied from
[`golang.org/x/net/http2` v0.58.0](https://github.com/golang/net/tree/v0.58.0/http2).
`internal/httpcommon` and `internal/httpsfv` were copied from the same module version. The original BSD
license is retained in `LICENSE`, and original source copyright notices remain.
HPACK, IDNA, and HTTP grammar helpers remain imports from the pinned x/net module.

The server and scheduler files are retained as upstream supporting code so that
client/server shared types and configuration do not need a bespoke rewrite. The
requests-utls public engine uses only the client transport. This is an internal
fork, not a replacement public `golang.org/x/net/http2` package.

Local modifications are intentionally concentrated:

- `transport.go`: immutable per-connection `WireProfile` snapshots, exact initial
  SETTINGS and WINDOW_UPDATE, receive-state initialization matching explicit
  settings (including zero), ordered request encoding, optional HEADERS priority,
  raw final response-header capture, no automatic gzip in ordered mode.
- `ordered_headers.go`: copies an ordered regular field list into per-request
  context; validates every field and total peer limit before touching HPACK;
  preserves interleaved duplicates and HPACK Sensitive flags without cookie
  splitting or automatic headers. Pseudo-headers use upstream URL/authority/path
  validation and configured order. Request trailers are explicitly unsupported.
- `wire_profile.go`: validation and protocol defaults for omitted settings.
  ENABLE_PUSH=0 is mandatory because this upstream client does not support push.
  Unknown SETTINGS identifiers are emitted unchanged, as allowed by HTTP/2;
  this does not implement any future semantics attached to those identifiers.
- `frame.go`: explicit zero MAX_HEADER_LIST_SIZE support; ability to emit an
  all-zero priority tuple; avoid uint32 overflow while checking encoded header
  block size against a large decoded-header limit.
- `transport_common.go`: expose `WireProfile`; default to at most three ordered
  request retries, with an explicit `MaxUnprocessedRetries` bound (-1 disables,
  maximum 32), only after unprocessed-request evidence: an unusable connection
  before stream creation, REFUSED_STREAM, or graceful GOAWAY above LastStreamID.
  Body rewind is required after the body might have been consumed. Ambiguous
  EOF/reset and processed streams are never retried. `transport.go` limits the
  retryable GOAWAY sentinel to NO_ERROR for every affected stream.
- `client_conn_pool.go`: a request waiting for another request's shared dial can
  cancel immediately without canceling the leader's connection attempt.
- The Go 1.27 stdlib delegation wrappers (`transport_wrap.go`, `server_wrap.go`)
  are intentionally omitted, and conditional legacy-implementation build tags
  are removed. This fork must retain its own transport to apply wire control;
  silently delegating to the unmodified stdlib would lose those capabilities.
- `http2.go`: remove the upstream canonical import comment.
- Imports of upstream internal `httpcommon` and `httpsfv` point at local copies.

Limits: full browser HPACK policy, arbitrary initial PRIORITY frames, ordered
request/response trailers, server push, extended CONNECT in ordered mode, HTTP/1,
and HTTP/3 are not implemented by these additions. Advertised limits on response
headers are enforced; when no MAX_HEADER_LIST_SIZE is advertised, a local
response header resource limit still applies. Explicit zero stream windows are
faithfully applied and will prevent receiving response DATA until window credit
is granted; profiles intended for normal requests should grant positive credit.

For an upstream update, compare the pinned source against this directory, rebase
the small modifications listed above, run the local wire tests and the root
integration/race suite, and audit upstream protocol/security fixes. This initial
prototype is not a promise that v0.58.0 contains later upstream security fixes.
