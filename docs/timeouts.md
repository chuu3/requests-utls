# Phase timeouts and error diagnostics

The request timeout/context remains the total budget, including admission queue,
connection establishment, request writes, headers and body. Phase limits can only
shorten it. Session settings are immutable and shared safely by concurrent calls.

| Phase | Python option (seconds) | Go option (time.Duration) | Default |
| --- | --- | --- | --- |
| DNS and TCP to target or proxy | connect_timeout | ConnectTimeout | 10 seconds |
| Proxy CONNECT exchange, after TCP | proxy_connect_timeout | ProxyConnectTimeout | 10 seconds |
| Target TLS handshake | tls_handshake_timeout | TLSHandshakeTimeout | 10 seconds |
| Final response headers, after request write | response_header_timeout | ResponseHeaderTimeout | No additional limit |
| Response body consumption | body_timeout | BodyTimeout | No additional limit |

Python accepts positive finite numbers; None omits the setting. Go/native zero
selects the default shown above; negative values are rejected. Header/body limits
cover the whole phase, not an idle interval renewed with each byte. Informational
responses do not restart the response-header timer. Request writes and waiting
for an H2 connection/stream remain bounded by the total request timeout.

Connection establishment previously shared one hard-coded 10-second budget.
It now has independent connect, proxy and TLS budgets, each bounded by the total
request deadline. A TLS retry starts a new handshake attempt; the total request
deadline is never reset. Existing connection reuse performs no new connect/TLS
phase. Setting Python timeout=None removes the total deadline, not these default
connection phase limits.

An H1 read timeout retires that connection. H2 header/body timeout cancels only
the affected stream, preserving other requests on the shared connection. Body
limits govern buffered consumption; there is no new streaming API. Decoder CPU
work is not forcibly preempted; cancellation is observed at I/O boundaries.

Errors retain their existing classes/categories and gain optional stage and
elapsed time. Socket deadline errors consistently map to Timeout in Python and
context.DeadlineExceeded in Go, even when the socket timer fires before the
context timer becomes observable. Cancellation and Session closure retain their
own classification.

Stages are queue, connect, proxy_connect, tls, write, response_headers and body.
H2 may report request when it fails before an observable connection assignment;
that is not presented as a measured TLS or DNS phase. DNS is included in connect.
No successful-request timing breakdown is exposed by this version.

Go errors can be inspected with errors.As into *requestsutls.StageError; its
Stage and Elapsed describe the failed phase, and errors.Is works through Unwrap.
Python RequestError subclasses expose stage and elapsed_ms (None if unavailable).
They measure the failed phase, not the total request duration. Old native builds
still return errors without those fields; non-default phase options require the
new engine and old engines reject unknown configuration fields.
