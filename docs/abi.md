# Native ABI v1

The Go engine and Python client are separate projects. The engine exports the
stable C interface in [`include/requests_utls.h`](../include/requests_utls.h).
Python clients should check `ruts_abi_version() == 1` before creating a Session.
The ABI uses fixed-width integer handles and length-delimited UTF-8 JSON. Bodies
are separate raw bytes and never base64-encoded.

Build on the target operating system and architecture (a C compiler is needed):

```sh
go build -buildmode=c-shared -o dist/librequests_utls.dylib ./cmd/requests-utls-shared
```

Use `.so` on Linux and `.dll` on Windows. Clients need no Go compiler once the
matching shared library is installed. Distribute the public header from `include`
alongside the library, rather than the cgo-generated implementation header.

## Ownership

```c
typedef struct RUTS_Result {
    int32_t code;
    uint64_t handle;
    unsigned char *data;
    size_t length;
} RUTS_Result;
```

Every non-NULL `result.data` is a fresh C-allocated buffer, including errors and
repeat body reads. Copy it into the caller's runtime, then call
`ruts_buffer_free(result.data)` exactly once. The data is not NUL-terminated; use
`length`. An empty payload may use NULL with length zero. Returned buffers remain
valid after closing/releasing their handles. Freeing the buffer does not release
a request handle.

Inputs are borrowed only for the duration of the call. The ABI copies metadata
and bodies before submit returns; it never keeps a caller's pointer or exposes a
Go object pointer. The caller must not mutate input memory during a call. A NULL
pointer with nonzero length is invalid. JSON inputs are limited to 4 MiB and
request bodies to 64 MiB. All pointer addresses must refer to valid memory;
arbitrary invalid pointers and double frees are C caller errors.

## Session configuration

`ruts_session_create(json, length)` accepts an object with these fields. Unknown
fields, including unknown nested configuration fields, are rejected.

| Field | Meaning |
| --- | --- |
| `profile` | Required native schema-version-1 profile object |
| `proxy_url` | Optional explicit `http://` CONNECT proxy URL |
| `proxy_auth` | Optional `{ "username": "...", "password": "..." }`; cannot coexist with URL credentials |
| `ca_pem` | Optional PEM CA bundle used as the complete trust store; empty uses system trust |
| `insecure_skip_verify` | Default false |
| `disable_session_resumption` | Default false; true disables TLS ticket/PSK reuse, independently of HTTP/2 connection pooling |
| `random_ja3` | Default false; shuffle eligible extension positions separately for each new connection |
| `force_http1` | Default false; advertise only HTTP/1.1 and remove HTTP/2 ALPS when true |
| `disable_content_decoding` | Default false; true returns the original compressed body bytes |
| `max_concurrent_requests` | Default 64 when zero/omitted |
| `max_pending_requests` | Default 0; extra admitted requests allowed to wait |
| `max_response_bytes` | Default 32 MiB when zero/omitted; applies to encoded bytes and every decoding layer |
| `max_unprocessed_retries` | Default 3 when zero/omitted; -1 disables; maximum 32 |

Proxy authentication goes only to the CONNECT proxy. Session transport and
profile settings are immutable. There is no shared mutable default header list
or cookie jar in this layer; a higher-level client can supply request snapshots.

Tickets are held in a bounded cache per Session and separated by destination
host and port. A reconnect can offer a real ticket-derived PSK (extension 41);
the initial handshake keeps the supplied profile's extension sequence. Reusing
an existing HTTP/2 connection performs no additional handshake. This optional
configuration field requires an engine build that implements session resumption;
older ABI 1 engines reject the unknown field rather than silently ignore it.

Success returns `handle = session_id` and JSON:

```json
{"profile_hash":"...","limitations":[]}
```

`limitations` reports profile-specific incomplete handshake behaviors; it is not
an assertion that all browser behavior is implemented. The engine supports HTTP/2,
HTTP/1.1 with ALPN fallback, and automatic gzip, deflate (zlib or raw), Brotli,
and Zstandard decoding. It does not follow redirects or stream response delivery,
or implement a browser certificate-selection retry mechanism. Unknown content
codings and corrupt compressed bodies fail explicitly; use
`disable_content_decoding` to inspect original encoded bytes. New optional fields
require an updated engine; old ABI 1 builds reject them rather than ignoring them.

`ruts_profile_import(json, length, allow_opaque)` converts a Peet capture into a
native profile object and returns that object directly as JSON, with handle zero.
`allow_opaque` must be 0 or 1. It opts into audited advertised-only behaviors;
profile validation still rejects unsupported unsafe payloads. It does not import
arbitrary requests_go configuration formats.

## Requests and completions

`ruts_request_submit(session_id, metadata, metadata_length, body, body_length)`
accepts this request-level metadata:

```json
{
  "method":"POST",
  "url":"https://example.com/",
  "headers":[
    {"name":"x-a","value":"1"},
    {"name":"x-a","value":"2"},
    {"name":"x-b","value":"middle"}
  ],
  "headers_order":["x-a","x-b","x-a"],
  "timeout_ms":20000
}
```

Method defaults to GET. `timeout_ms` is a total request deadline including queue
waiting and body consumption; zero/omitted means no total deadline. It must be
nonnegative and fit a Go duration. Session shutdown and cancellation can still
end requests without a deadline; the engine also has its connection handshake
deadline.

Headers are ordered occurrences, never a map. An empty `headers_order` preserves
their input order, with generated fields following them. A name listed once groups its occurrences in original
order. Repeated names schedule individual occurrences, and their count must match
the supplied header occurrences. Generated fields participate in sorting even
when absent from the input; other absent names are ignored. Unlisted headers
follow in their original relative order. Matching is case-insensitive. HTTP/1.1
preserves supplied field name spelling; HTTP/2 lowercases names on the wire.
Pseudo-header order belongs to the immutable profile. See the Go API for each
protocol's field validation constraints.

Once HTTP/1.1 is selected, Cookie occurrences are combined with `; ` after
ordering, at the first Cookie's position and with its spelling. Empty fragments
are omitted; all-empty occurrences retain one empty field. Thus repeated Cookie
entries in `headers_order` count the original occurrences, before combining.
HTTP/2 keeps separate Cookie occurrences. Other valid repeated fields keep their
ordered occurrences. This applies to direct, forced and negotiated HTTP/1.1.

Content-Length comes from the final body byte length, replacing a supplied
single field's value while keeping its spelling and position. Duplicate
Content-Length fields are rejected. Missing Content-Length is generated for
nonempty bodies and POST/PUT/PATCH, including zero-length bodies, before ordering.
HTTP/1.1 also generates a missing Host before ordering. The default HTTP/1.1
connection persistence does not generate Connection; explicitly supplied
Connection fields participate in ordering. HTTP/2 rejects these fields.

Accepted submit returns immediately with a new request handle and no payload.
JSON-level errors can fail submission immediately; semantic request errors such
as invalid header ordering are reported as code 3 in its completion. Each
accepted request produces exactly one completion unless released or its Session
is closed. Calls may complete out of order.

`ruts_session_poll(session_id, timeout_ms)` consumes one completion. Use -1 to
wait indefinitely, 0 to check immediately, or a positive millisecond timeout.
An idle poll returns code 1 and handle zero. There are no callbacks into Python;
one dispatcher thread per Session can poll and deliver to synchronous waiters or
event-loop Futures. Multiple concurrent pollers are also safe, but any one event
goes to only one poller.

A successful completion has `handle = request_id` and JSON:

```json
{
  "status_code":200,
  "headers":[{"name":"set-cookie","value":"a=1"},{"name":"set-cookie","value":"b=2"}],
  "protocol":"HTTP/2.0",
  "body_size":123,
  "decoded":true
}
```

`ruts_request_body(request_id)` returns a fresh body byte copy after completion,
with the same request handle. Calling before completion returns code 3. Failed
requests return their original error. Reading or polling does not release the
request handle. Response bodies are currently fully buffered subject to the
response limit. `decoded` indicates that a content coding was removed; original
Content-Encoding and Content-Length fields remain available in `headers`.

Outstanding handles, including completed but unreleased results, are bounded by
`max_concurrent_requests + max_pending_requests`. Submit returns code 5 when that
limit is reached. Always release a result after copying its response body.
Canceled-but-released work retains its admission slot until its Go execution
finishes, preventing repeated submit/release from creating unbounded goroutines.

## Cancellation, release, and close

- `ruts_request_cancel(request_id)` requests cancellation and keeps the handle.
  The request delivers one terminal completion. Completion can win a race with
  cancellation, so a successful response is still possible. Unknown handles
  return code 4.
- `ruts_request_release(request_id)` cancels pending work, suppresses a completion
  that has not already been consumed, and discards retained body/metadata. It is
  idempotent, including unknown handles. A concurrently consumed completion may
  already have reached a poller; reading its released body then returns code 4.
- `ruts_session_close(session_id)` rejects new admissions, wakes pollers, cancels
  all its work, closes connections, waits for goroutines, and removes all owned
  handles. Concurrent/repeated close is idempotent, including unknown handles.
  A poll already waiting returns code 2; a new call after handle removal returns
  code 4. Pending completions are discarded on close.

Calls on shared Sessions are safe concurrently. A short registry mutex protects
only handles and completion state; network I/O and waits never hold it. Handles
are monotonically allocated and never reused. Callers must not reuse a loaded Go
runtime or its handles in a child process after fork; initialize in a fresh
process instead. Do not unload the shared library while Go runtime threads exist.

## Errors

Errors from result-returning functions contain `{"message":"..."}`. A completion
error includes its request handle; other errors normally have handle zero.
Integer-returning lifecycle functions return only a code. Ordinary entry-point
Go panics are converted to code 10; invalid C memory and runtime-fatal failures
are outside this guarantee.

| Code | Name |
| --- | --- |
| 0 | Success |
| 1 | Poll timeout |
| 2 | Session closed |
| 3 | Invalid input |
| 4 | Invalid handle |
| 5 | Outstanding request queue full |
| 6 | Canceled |
| 7 | Total deadline exceeded |
| 8 | Response too large |
| 9 | Transport error |
| 10 | Internal error |

Only requests proven unprocessed by the HTTP/2 peer may be retried by the engine.
Ambiguous network failures are not automatically replayed.

## Validation

```sh
go test -race ./native ./cmd/requests-utls-shared
go vet ./native ./cmd/requests-utls-shared
```

Native tests use a local TLS/HTTP2 capture server to verify 64 concurrent requests
with independent body/header-order/cookie snapshots, response duplicate fields,
bounded retained results, cancellation, deadlines, release, concurrent close,
strict input/error classification, and cleanup of registries. Entry-point tests
cover NULL/oversized inputs and independent C-owned response buffers.
