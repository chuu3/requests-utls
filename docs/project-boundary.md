# Go and Python project boundary

`requests-utls` owns the Go transport, TLS profile compiler, request lifecycle,
proxy tunneling and native ABI. `requests-utls-python` owns the Python API,
packaging and its CFFI client. Both are independent Git repositories.

- Go: <https://github.com/chuu3/requests-utls>
- Python: <https://github.com/chuu3/requests-utls-python>

The source dependency points in one direction: the native entry point imports
the Go engine. Python imports no Go modules and does not compile Go source during
installation. At runtime Python loads an ABI-compatible shared library by explicit
path or `REQUESTS_UTLS_LIBRARY`.

## Build artifacts

The Go project builds and tests its library independently:

```sh
make shared
```

The OS-specific output is `dist/librequests_utls.dylib`, `.so`, or `.dll`, with
public ABI declaration `include/requests_utls.h`. OS and architecture must match
the Python process. CI defines native builds for Linux, macOS and Windows; local
verification currently covers macOS arm64 only.

The Python wheel contains Python code and depends on CFFI. For this development
release, install the engine artifact separately and set its path; no native
download or package publication happens automatically. A future platform wheel
can bundle a pinned Go artifact without vendoring Go source, but must carry the
correct platform tag and licenses.

## Compatibility

- The consumer checks ABI version 1 before making Session calls.
- Engine/Python release versions can change independently while ABI 1 remains
  compatible. Incompatible struct/signature/ownership changes require a new ABI.
- Profile schema version and ABI version are separate. The Go engine validates
  profile support and reports unsupported capabilities to Python.
- Request metadata includes request-local `headers_order`. Profile objects and
  Session transport configuration do not change while requests run.
- Session creation accepts `disable_session_resumption`. Python enables
  resumption by default and requires an engine build supporting this field; older engines
  fail on the unknown field. TLS tickets are private mutable protocol state in
  a bounded, concurrent Session cache; they do not modify the supplied profile.
- Profile JSON and request metadata cross the boundary as copied UTF-8 bytes;
  request and response bodies use separate binary buffers, not base64 JSON.
- Go schedules requests. Each Python Session uses one completion-dispatch thread;
  asyncio tasks do not consume one waiting thread per request.

## Independent integration fixture

The Go project also builds `cmd/requests-utls-testpeer` (`make testpeer`), a local TLS/HTTP2 wire
peer used by cross-language tests. Python integration tests receive its executable
path through `REQUESTS_UTLS_TEST_PEER`. They do not read or build a sibling Go
source checkout implicitly. The fixture's certificate is temporary and explicitly
trusted only by the test Session.

The native and Python implementations both require explicit Session closure.
Cancellation and closure must release native request handles, response bodies
and completion records. Parent-process Go runtimes must never be entered from
a forked child; Python rejects this before touching native code or inherited
locks. Use multiprocessing's spawn method for separate processes.
