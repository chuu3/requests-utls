# requests-utls

A Go engine prototype for a separate Python requests-style client: immutable TLS profiles,
concurrent Sessions, and HTTP/2 and HTTP/1.1 header lists that retain interleaved duplicates.

This repository contains the **Go engine** and its versioned C ABI. The Python
client is maintained in the separate [requests-utls-python](https://github.com/chuu3/requests-utls-python) project and imports
as `requests_utls`; no Go source is copied into the Python repository.
The Go module path is `github.com/chuu3/requests-utls`.

For development, see [CONTRIBUTING.md](CONTRIBUTING.md), the
[profile capability table](docs/profile-capabilities.md), and
[maintenance guide](docs/maintenance.md). Confidential reports are covered by
[SECURITY.md](SECURITY.md); release changes are in [CHANGELOG.md](CHANGELOG.md).

The [verification report](docs/verification.md) records local race/wire tests and
authenticated HTTP CONNECT proxy tests against tls.peet.ws, including both the earlier
30-second timeout and the passing 60-second concurrent run.
The Python project's [bulk profile acceptance](https://github.com/chuu3/requests-utls-python/blob/main/docs/profile-acceptance.md)
checks each supplied cold-handshake capture and records historical Peet JA4
inconsistencies without treating them as exact fingerprint matches.

## What works

- Native versioned JSON profiles and an explicit `tls.peet.ws` capture importer.
- uTLS `HelloCustom` with **fresh extension objects for every connection**.
- HTTPS with negotiated HTTP/2 or HTTP/1.1, directly or through an explicit HTTP CONNECT
  proxy; certificate verification is enabled by default.
- Exact configured initial SETTINGS order, connection WINDOW_UPDATE, pseudo-header
  order, optional HEADERS priority, and ordered regular header occurrences.
- Repeated/interleaved request and response fields, including Cookie and Set-Cookie.
- Concurrent requests on one Session, HTTP/2 multiplexing, context cancellation,
  bounded request admission, bounded buffered responses, idempotent Session Close.
- Local TLS/HTTP2 wire tests that inspect what the server actually receives.
- HTTP/1.1 connection pooling with ordered field names and duplicates, including
  automatic ALPN fallback and explicit `ForceHTTP1`.
- Automatic gzip, deflate, Brotli and Zstandard response decoding with bounded
  encoded and decoded bodies; `DisableContentDecoding` returns original bytes.
  Automatic decoding accepts at most four non-identity encoding layers.
- Optional `RandomJA3` extension shuffling on each new connection without
  modifying shared profiles or requests already using an established connection.

## Build and verify

Use a Go toolchain that satisfies `go.mod` (the initial prototype is verified with
Go 1.27.1 on macOS arm64). The race detector also requires a C compiler.

```sh
go test -race ./...
go vet ./...
go build -o bin/requests-utls ./cmd/requests-utls
./bin/requests-utls validate -profile profiles/chrome_152.json
```

Equivalent: `make check`. Set `GO=/path/to/go` if Go is not on PATH.

To build a shared library for another language:

```sh
make shared
# macOS: dist/librequests_utls.dylib
# Linux: dist/librequests_utls.so
# Windows: dist/librequests_utls.dll
```

The public contract is [include/requests_utls.h](include/requests_utls.h), described
in [docs/abi.md](docs/abi.md). The consumer supplies the library path explicitly;
it does not need this repository at runtime. The generated shared library and
header are build artifacts under ignored `dist/`.

## Use the Go API

```go
p, err := profile.LoadFile("profiles/chrome_152.json")
if err != nil { return err }
s, err := requestsutls.NewSession(requestsutls.Options{
    Profile: p,
    MaxConcurrentRequests: 64,
    MaxPendingRequests: 256,
    MaxResponseBytes: 32 << 20,
})
if err != nil { return err }
defer s.Close()

ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
defer cancel()
response, err := s.Do(ctx, requestsutls.Request{
    Method: "GET",
    URL: "https://example.com/",
    Headers: []requestsutls.HeaderField{
        {Name: "x-a", Value: "1"},
        {Name: "x-b", Value: "2"},
        {Name: "x-a", Value: "3"},
    },
    HeadersOrder: []string{"x-a", "x-b", "x-a"},
})
```

Imports: `requestsutls "github.com/chuu3/requests-utls"`,
`"github.com/chuu3/requests-utls/profile"`, `"context"`, `"time"`.

`Session.Do` can be called from many goroutines. Profile and trust configuration
are fixed at Session creation. Each request owns its header list and body; the
Session snapshots them. The caller must not modify those slices concurrently
while `Do` is taking its snapshot. `Profile` itself exposes no mutable internals.

`Request.HeadersOrder` (`headers_order` in JSON) belongs to that request. It is
copied alongside headers before waiting for execution and does not modify the
Session, TLS profile, or any other request. Its rules are:

- Omitted/empty: preserve the input field order, except HTTP/1.1 Host is first;
  other generated fields follow the input fields.
- A name listed once moves all its values together, in their original order.
- A repeated name schedules individual occurrences. If present, its number of
  order entries must equal its number of supplied field occurrences.
- Generated fields participate in the order even when absent from the input.
  Other missing names are ignored, making reusable order templates possible.
- Unlisted fields follow in their original relative order.
- Names are matched case-insensitively; HTTP/1.1 preserves input spelling and
  HTTP/2 writes lowercase names. Pseudo-header order continues to belong to the
  connection's HTTP/2 profile.

For `x-a:1, x-b:2, x-a:3`, order `x-b,x-a` produces `x-b:2,x-a:1,x-a:3`;
order `x-a,x-b,x-a` retains the interleaving. Concurrent callers may choose either
order on the same Session. The Go caller must not mutate input slices during
the snapshot; the Python wrapper builds private input buffers before submission.

`Content-Length` is always calculated from the final request body bytes. A
single supplied field keeps its spelling and position but its value is replaced;
duplicate Content-Length fields are rejected. When missing, the engine adds it
for nonempty bodies and for POST/PUT/PATCH (including `0` for empty bodies), then
applies `HeadersOrder`. Empty GET/HEAD requests do not gain a Content-Length
unless explicitly supplied. HTTP/1.1 also generates a missing `Host` from the
URL. If `HeadersOrder` includes Host, that position is used; otherwise Host is
the first field, including when supplied explicitly. Supplied spelling and
value are preserved. HTTP/2 consumes an explicit Host as `:authority`, or uses
the URL authority when absent, without sending a regular Host field. The URL
still determines the connection destination, TLS SNI and certificate hostname.

HTTP/1.1 keeps connections reusable by default without generating a `Connection`
field. An explicit `Connection: keep-alive` or `Connection: close` keeps its input
spelling and participates in `HeadersOrder`; `close` retires the connection after
the response. HTTP/2 removes Connection, Keep-Alive, Proxy-Connection,
Transfer-Encoding, Upgrade, HTTP2-Settings and every regular field named by a
Connection option, before ordering. The auxiliary transport headers are filtered
as well, so a removed Connection: close cannot disable H2 connection reuse.
TE is retained only for a case-insensitive `trailers` value, emitted as
`trailers`, unless nominated for removal by Connection. Other TE values are
removed. If Connection names Content-Length, H2 omits that optional field
without regenerating it; DATA framing still carries the complete body.
These rules follow [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2).
Removed names in `HeadersOrder` are ignored; occurrence counts refer to surviving
H2 fields. Listing another absent field alone does not cause it to be generated.
Request trailers remain unsupported. Malformed field syntax, duplicate Host or
Content-Length, and origin Proxy-Authorization are rejected before filtering.

After ordering, an actual HTTP/1.1 request combines Cookie occurrences with
`; ` into one field, retaining the first occurrence's spelling and position.
Empty fragments are omitted; all-empty Cookie fields become one empty field.
Order entries refer to the original occurrences, before this combination.
HTTP/2 retains separate Cookie fields, and other permitted repeated fields retain
their order. The negotiated protocol determines this behavior, including when an
H2 profile falls back to H1 through a server or intercepting proxy.

All protocol selection, filtering, generation and ordering happens in this Go
engine. The C ABI and Python client forward the same request-level options;
neither needs a duplicate protocol implementation.

There is no `mount`, adapters registry, mutable Session default-header map, shared
header-order slice, or automatic cookie jar. Set `cookie` per request when needed.
Received Set-Cookie fields are returned, never silently sent by a later request.
Separate Sessions never share connections, profile state or cookies.

### Connection reuse and TLS session resumption

A Session reuses healthy HTTP/2 and HTTP/1.1 connections by default. Sequential requests on
that connection do not create another ClientHello. If the peer sends GOAWAY,
closes the connection, or the connection expires, the next request needs a new
connection.

TLS resumption is also enabled by default. Each Session has a bounded 64-entry
ticket cache separated by destination host and port. For a TLS 1.3 profile that
already offers `psk_key_exchange_modes=1`, a reconnect can use a real server
ticket to append `pre_shared_key` (41) as the last extension. uTLS computes fresh
identities and binders; captured PSK bytes are never replayed. With no usable
ticket, the first-handshake extension list stays unchanged. TLS 1.2 ticket
resumption requires the profile's `session_ticket` extension.

The server may decline resumption or never issue a usable ticket. A resumed
ClientHello has a different fingerprint from a cold handshake. Set
`Options.DisableSessionResumption: true` to keep every new connection cold;
this does not disable HTTP/2 connection reuse. Tickets are discarded on Close.
No 0-RTT HTTP requests are sent.

uTLS v1.8.2 cannot recalculate a custom PSK ClientHello after HelloRetryRequest.
For that exact error, before any HTTP request bytes are sent, the engine retries
one full TLS handshake on a new connection within the same remaining dial
deadline. Other handshake errors do not trigger this fallback.

Use `Options.ProxyURL` to choose an HTTP CONNECT proxy; it is fixed for the
Session, so changing proxies cannot reuse an old tunnel. Proxy environment
variables are intentionally not read implicitly. HTTPS proxies and SOCKS are not
implemented yet.

Proxy authentication accepts URL userinfo or a separate copied credential value:

```go
requestsutls.Options{
    Profile: p,
    ProxyURL: "http://proxy.example:8080",
    ProxyAuth: &requestsutls.ProxyAuth{
        Username: os.Getenv("PROXY_USERNAME"),
        Password: os.Getenv("PROXY_PASSWORD"),
    },
}
```

`Username` and `Password` are opaque credential strings. The engine applies
standard HTTP Basic authentication to `username:password`. Authentication is
fixed when the Session is created; create a new Session to change credentials.
Proxy credentials are sent only in CONNECT, never in the target request.

The running limit includes response-body consumption. `MaxConcurrentRequests=0`
means 64; `MaxPendingRequests=0` means **no waiting queue**. Once running and
pending capacity is exhausted, `Do` returns `ErrQueueFull`. Cancellation applies
while queued, dialing, handshaking, waiting for headers, and reading a body.
`Close` cancels admitted work and closes all this Session's connections.

## CLI

```sh
# Preserve this exact regular-header order, including the repeated x-a.
./bin/requests-utls request \
  -profile profiles/chrome_152.json \
  -url https://tls.peet.ws/api/all \
  -H 'x-a: 1' -H 'x-a: 3' -H 'x-b: 2' \
  -headers-order 'x-a,x-b,x-a'

# All workers share a single Session.
./bin/requests-utls request \
  -profile profiles/chrome_152.json \
  -url https://tls.peet.ws/api/all -n 16 -c 4 -timeout 20s

# Select an explicit HTTP CONNECT proxy.
./bin/requests-utls request \
  -profile profiles/chrome_152.json \
  -url https://tls.peet.ws/api/all -proxy http://proxy.example:8080

# Import fails on unsupported features unless explicitly allowed.
./bin/requests-utls import-peet -in capture.json -out profile.json
./bin/requests-utls import-peet -in capture.json -out profile.json -allow-opaque
```

The CLI writes one JSON result per request. `response.body` is base64 because it
is an arbitrary byte buffer, not necessarily text. Limitations go to stderr.
Pseudo-headers derive from the URL/method/profile and an optional Host override.
No User-Agent, Accept-Encoding or ordinary default headers are automatically added.
Content-Length is calculated from the final body bytes, including when supplied
explicitly, and cannot repeat. Generated fields participate in headers_order.
Other invalid fields are rejected.

For a credential-bearing proxy URL, `-proxy-env VARIABLE_NAME` reads it from an
explicit environment variable instead of putting it in command arguments. The
library accepts separate `ProxyAuth` so applications need not construct such URLs.

The opt-in live acceptance command compares the sanitized Chrome capture's
fingerprints and checks unique headers/cookies across a shared Session:

```sh
go run ./cmd/peetcheck -proxy-env REQUESTS_UTLS_TEST_PROXY -n 8 -c 4
```

It checks HTTP status, extension 51764's full payload, JA3, JA4, Peetprint,
HTTP/2 fingerprint, and the complete ordered regular-header list. It prints a
sanitized JSON report; ordinary `go test` uses only local servers. This checker
explicitly disables TLS resumption to compare every connection with the same
cold-handshake baseline. Resumption is verified separately.

The test endpoint was observed to send GOAWAY after a response. Under parallel
load this leaves other streams explicitly unprocessed. `peetcheck` therefore
sets `-unprocessed-retries 8`; normal Sessions default to 3. This changes only the
bounded retry count, never which failures are eligible for replay. Set
`Options.MaxUnprocessedRetries` to 1..32 to choose a bound, or -1 to disable.

## Built-in captures and fidelity

`profiles/builtin.json` declares the profiles included in native artifacts:

| Python builtin name | Go profile file |
| --- | --- |
| `chrome_150` | [chrome_150.json](profiles/chrome_150.json) |
| `chrome_152` | [chrome_152.json](profiles/chrome_152.json) |

Both are imported from distinct supplied captures. Chrome 150 has its own
extension ordering and does not advertise extension 51764. Each profile retains
its own declared limitations; adding a version is not a rename of another one.

`profiles/chrome_152.json` is derived from the existing local browser capture. It
contains protocol configuration, not the capture's IP address, TCP connection
details, session ID, random values or public key bytes. It represents **one
captured ClientHello extension order**, not every Chrome 152 installation or its
full randomized extension-order distribution. Headers are provided per request;
the profile does not automatically replay the capture's navigation headers.

The profile explicitly opts into these experimental advertisements:

- **51764 / 0xca34 (`trust_anchors`)**: the exact captured static payload is
  emitted at the configured position. A server can see the extension ID and its
  contents. Full trust-anchor negotiation, certificate-path selection and retry
  behavior are not implemented.
- Signature schemes **0x0904, 0x0905, 0x0906** are advertised as captured; pinned
  uTLS cannot verify signatures using these schemes if a server selects them.
- ECH is GREASE behavior with newly generated bytes, not working encrypted SNI.

The BoringSSL extension ID is defined in
[tls1.h](https://github.com/google/boringssl/blob/main/include/openssl/tls1.h);
the protocol is described in the
[TLS Trust Anchor Identifiers draft](https://datatracker.ietf.org/doc/html/draft-ietf-tls-trust-anchor-ids).
uTLS provides the raw extension mechanism in
[u_tls_extensions.go](https://github.com/refraction-networking/utls/blob/v1.8.2/u_tls_extensions.go).

These are capability limits, not missing extension IDs on the wire. A matching
JA3/JA4 alone is not proof of full browser equivalence. Key shares, TLS random
and GREASE/ECH material are generated per
connection. There is no promise of identical ciphertext, TCP/IP behavior, HPACK
bytes, all later frame scheduling, or full Chrome network-stack behavior.

## Deliberate prototype limits

- No HTTPS/SOCKS proxy, HTTP/3, WebSocket, user-issued CONNECT request,
  redirect following, or automatic shared cookie jar yet.
- Responses are buffered with a default 32 MiB cap; no public streaming API or
  upload streaming, request/response trailers, or informational-response API yet.
- The concurrency cap bounds admitted work, not a complete configurable
  per-origin connection-pool policy. HTTP/2 still respects peer stream limits.
- Retries are bounded and allowed only when the connection/HTTP2 error proves
  the request was not processed (unused connection, qualifying GOAWAY or
  REFUSED_STREAM). Ambiguous disconnects and possibly processed requests are
  returned as errors, including POST requests.
- The C ABI and separate Python client cover buffered synchronous/asynchronous
  requests. The Python package includes native platform wheels.
- The local tests validate these implementation paths; they do not certify every
  browser version, platform, server, or optional negotiated TLS extension.

## Repository layout

```text
session.go                 immutable Session / request admission / uTLS dialing
http1.go                   ordered HTTP/1.1 transport, connection pooling, ALPN fallback
content_decode.go          bounded gzip/deflate/Brotli/Zstandard response decoding
header_order.go            request-local ordering including repeated occurrences
native/                    bounded handles and completion queues for the C ABI
proxy.go                   HTTP CONNECT, Basic authentication, cancellation
profile/                   native profile compiler, capture importer and tests
profiles/                  sanitized native example profiles
internal/h2/               controlled upstream HTTP/2 fork, licenses and patch notes
internal/testserver/       local raw TLS + HTTP/2 capture fixture
session_test.go            wire and concurrency acceptance tests
cmd/requests-utls/         validate / import-peet / request CLI
cmd/peetcheck/              opt-in live fingerprint and isolation verification
cmd/requests-utls-shared/   C ABI shared-library build target
```

See `internal/h2/UPSTREAM.md` for the upstream revision and local changes. Preserve
the upstream licenses and review upstream transport fixes when updating the fork.
