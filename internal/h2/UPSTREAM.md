# Upstream provenance and local changes

The non-test top-level Go files in this directory, except `ordered_headers.go`
and `wire_profile.go`, were copied from
[`golang.org/x/net/http2` v0.59.0](https://github.com/golang/net/tree/v0.59.0/http2).
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
  raw final response-header capture, no automatic gzip in ordered mode. When an
  exact profile permits push, PUSH_PROMISE field blocks are fully HPACK-decoded
  and immediately declined with RST_STREAM CANCEL. Queued response HEADERS on
  canceled push streams still update the shared HPACK table; queued DATA is
  discarded while returning connection flow-control credit. A monotonic server
  stream high-water mark avoids retaining a per-push state map. Malformed stream
  identifiers and HPACK blocks retain their protocol/compression errors.
- `ordered_headers.go`: copies an ordered regular field list into per-request
  context; validates every field and total peer limit before touching HPACK;
  preserves interleaved duplicates and HPACK Sensitive flags without cookie
  splitting or automatic headers. Pseudo-headers use upstream URL/authority/path
  validation and configured order. Request trailers are explicitly unsupported.
- `wire_profile.go`: validation and protocol defaults for omitted settings.
  ENABLE_PUSH may be absent (the protocol default is 1), 0, or 1; the SETTINGS
  payload is never changed to disable push. The ordinary transport without a
  custom profile continues advertising 0. Receiving PUSH_PROMISE when push was
  explicitly disabled remains a connection protocol error.
  Unknown SETTINGS identifiers are emitted unchanged, as allowed by HTTP/2;
  this does not implement any future semantics attached to those identifiers.
- `frame.go`: explicit zero MAX_HEADER_LIST_SIZE support; ability to emit an
  all-zero priority tuple; avoid uint32 overflow while checking encoded header
  block size against a large decoded-header limit; enforce contiguous
  PUSH_PROMISE/CONTINUATION blocks on the associated request stream. Promise
  fields use the existing bounded metadata decoder, including header-list and
  string limits, before the promised stream is rejected.
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
request/response trailers, application-visible server push, extended CONNECT in
ordered mode, and HTTP/3 are not implemented by these additions. The root engine
implements HTTP/1 separately. Permitted pushes are declined according to
[RFC 9113 section 8.4.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.4.2);
their bodies, response headers, and cookies are never exposed or cached.
Advertised limits on response
headers are enforced; when no MAX_HEADER_LIST_SIZE is advertised, a local
response header resource limit still applies. Explicit zero stream windows are
faithfully applied and will prevent receiving response DATA until window credit
is granted; profiles intended for normal requests should grant positive credit.

For an upstream update, compare the pinned source against this directory, rebase
the small modifications listed above, run the local wire tests and the root
integration/race suite, and audit upstream protocol/security fixes. This initial
prototype is not a promise that v0.59.0 contains later upstream security fixes.

`upstream.json` records hashes for the 32 original source files, including the
module-root `internal/httpcommon` and `internal/httpsfv` helpers. Run
`python3 scripts/check_http2_upstream.py --latest` from the repository root to
check for upstream changes; the script does not overwrite local modifications.
See [the maintenance procedure](../../docs/maintenance.md) before explicitly
regenerating this baseline after an upstream review.

## v0.59.0 review

Reviewed all six changed baseline files against v0.58.0. Applied the ASCII
helper and IDNA Lookup conversion in `authorityAddr`, equivalent `max` buffer
allocation, upstream deprecation comments, and shared server request validation
for Host/:authority agreement, duplicate Host, and invalid authority values.
The retained H2 server already promotes a missing authority from Host before
calling the shared helper. Ordered client headers, wire settings, retry policy,
and local import/build-tag changes remain intact; stdlib delegation remains
excluded. The dependency now requires Go 1.26 or newer.

Upstream comparison: https://github.com/golang/net/compare/v0.58.0...v0.59.0

The local transport also exposes ResponseHeaderTimeout independently of the
stdlib adapter. It reuses the upstream per-stream final-header timer; timeout
aborts that stream rather than applying a deadline to the multiplexed socket.
