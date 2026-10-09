# Prototype verification — 2026-09-06

Code was exercised on macOS arm64 with Go 1.27.1. The HTTP/2 fork uses
`golang.org/x/net v0.59.0`; TLS uses `refraction-networking/utls v1.8.2`.

## Local checks

`go test -race ./...`, `go vet ./...`, and CLI build passed. Local acceptance
tests include:

- Capture ClientHello cipher/extension order and payloads, including the complete
  captured trust_anchors (51764) bytes at the same extension position.
- Make two independent Chrome-profile connections; verify fresh key shares.
- Verify exact H2 SETTINGS, connection WINDOW_UPDATE and HEADERS priority.
- Hold **64 requests simultaneously on one reused HTTP/2 connection**; each has
  independent ordered duplicate headers, marker values and explicit Cookie.
- Apply different request-level `headers_order` values across 64 held streams:
  exact input order, grouped repeats and explicitly interleaved occurrences.
- Exercise native ABI 1 input copying, bounded handles and retained bodies,
  cancellation/deadlines, completion polling and concurrent close/release under
  the race detector. The independent Python client passed 55 tests against the
  real shared library, including a fresh wheel installation outside either
  source checkout and 32 simultaneous streams per sync/async API.
- Verify default TLS session resumption against real TLS servers: new connection,
  server `DidResume=true`, PSK extension last, unchanged cold ClientHello, TLS 1.2
  tickets, rejected tickets, Session/port isolation, concurrent cache close and
  16 concurrent resumed connections. Exercise the exact PSK+HelloRetryRequest
  pre-HTTP full-handshake fallback; certificate failures are not retried.
- Cancel one stream while a sibling continues; close active Sessions, exhaust
  queues, cancel queued work and verify admission capacity is recovered.
- Exercise HTTP CONNECT and both URL/separate Basic credentials; origin sees no
  proxy authentication. Check credentials are copied, tunnel reuse, buffered
  bytes, malformed/oversized replies and cancellation.
- Use the standard Go HTTP/2 server for a request and response spanning flow
  windows, duplicate fields and repeated connection use.
- Verify safe retries with actual GOAWAY frames: unprocessed POST body is
  replayed exactly; processed POST, protocol errors and ambiguous failures are
  not replayed. Test retry limits and cancellation of shared dial waiters.

## Live endpoint

Endpoint: `https://tls.peet.ws/api/all`.

Proxy: an explicitly configured HTTP CONNECT proxy using standard Basic
authentication. The reports contain only test results and protocol fingerprints.

| Run | Conditions | Result |
| --- | --- | --- |
| [Single request](peet-proxy-single.json) | 30-second deadline | 1/1 passed |
| [Concurrent, 30 seconds](peet-proxy-30s.json) | One Session, 8 tasks, 4 workers, up to 8 proven-unprocessed retries per task | 7/8 passed; one total deadline exceeded |
| [Concurrent, 60 seconds](peet-proxy-60s.json) | Same settings, 60-second deadline | **8/8 passed**, observed task times approximately 3.8–48.8 seconds |

Every successful response passed all eight checks:

1. HTTP 200 with h2.
2. Extension 51764 present with the complete expected payload.
3. JA3 string matches the supplied Chrome 152 sample.
4. JA3 hash matches.
5. JA4 matches.
6. Peetprint hash matches.
7. HTTP/2 Akamai fingerprint matches.
8. Ordered/interleaved duplicate request fields and the unique request Cookie
   match the task that received the response.

Reference values:

```text
JA3 hash: 36b4aa19269d847d0680175adbf9b96f
JA4: t13d1517h2_8daaf6152771_cb7bf5808d99
Peetprint hash: fc97c1cdfb1409c9a9326c1b726d1dee
HTTP/2: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

The endpoint sent graceful GOAWAY while requests were outstanding. This exposed
a missing safe-retry path in the first implementation. The final implementation
retries only errors proving a request was not processed, with a configurable
bound. The live checker explicitly uses 8; normal Sessions default to 3. These
results do not imply that the endpoint accepts persistent concurrent streams on
one connection; the local 64-stream test separately verifies actual multiplexing.


## Reproduce

Provide the authenticated proxy URL through an environment variable without
putting credentials in process arguments or reports:

```sh
go run ./cmd/peetcheck \
  -proxy-env REQUESTS_UTLS_TEST_PROXY \
  -n 8 -c 4 -unprocessed-retries 8 -timeout 60s
```

These are bounded observations against one captured profile and endpoint, not a
claim of complete Chrome behavior or a general throughput benchmark. Full Trust
Anchor IDs negotiation, unsupported PQ signature verification and application of
peer ALPS HTTP/2 settings remain outside the prototype. The reports preserve
those capability notes alongside the successful fingerprint checks.

## Connection lifetime — local verification, 2026-10-09

The unreleased Go/native changes were tested on macOS with the local Go 1.27.1
toolchain. All network fixtures bind loopback and use generated certificates.
They do not load external proxy settings, credentials or business URLs.

```sh
go test -race ./...
go vet ./...
RUTS_LIFETIME_LONG=1 go test -race -run TestConnectionLifetimeLongProxy -timeout 8m -v .
```

The full race suite and vet passed. The opt-in long test passed in 331.793 seconds.
Each group retains one Session for three cycles, sends keepalive traffic every
two seconds for 90 seconds, then starts a POST whose body completes 20 seconds
later. The proxy half-closes its client-facing TCP write side at a fixed tunnel
age of 100 seconds. This explicitly exercises local socket `CloseWrite`/FIN
behavior; no packet capture was collected.

| Protocol | Maximum age / jitter | Slow POST results | Physical CONNECTs |
| --- | --- | --- | --- |
| H2 | disabled | 3 expected unexpected-EOF failures at about 100 seconds per cycle | 3 |
| H1 | disabled | 3 expected unexpected-EOF failures at about 100 seconds per cycle | 3 |
| H2 | 60s / 10s | 3 complete bodies, no errors | 6 |
| H1 | 60s / 10s | 3 complete bodies, no errors | 6 |

Evidence and interpretation:

- `TestConnectionLifetimeSlowBodyAndPOST` compares server-side remote socket
  identities and CONNECT counts, holds a partially delivered response across
  retirement, checks the old tracked socket remains open, then verifies its
  removal after completion. Every unique POST ID executes exactly once.
- `internal/h2` lifetime tests concurrently reject reservations after expiry,
  retain an outstanding reservation, check final stream admission, keep buffered
  body bytes owned after END_STREAM, and wake a blocked stream-quota waiter.
- Concurrent replacement admits 32 requests through one replacement H2 dial.
  Stream cancellation leaves its sibling body intact. Repeated rotation and
  concurrent Close leave no tracked physical connections; fixture cleanup joins
  proxy workers. These are ownership assertions, not an OS-wide FD leak audit.
- H1 forced negotiation, ALPN fallback, and cleartext paths rotate; separate
  origins keep independent ages. Disabled sessions continue reusing their socket.
- Tiny ages fail before any HTTP request, replacement CONNECT stalls obey the
  original deadline, invalid native values fail validation, and an overlong POST
  still receives the original transport error without replay.
- Python integration uses the rebuilt shared library to prove configuration
  reaches the transport and that Cookie configuration and real TLS ticket
  acceptance survive replacement; see the Python repository's verification log.

The 100-second proxy experiment is synthetic and does not establish any external
provider's behavior. This public record covers synthetic local tests only.
No private proxy scripts, configuration, packet captures or historical evidence
were copied into this repo.
