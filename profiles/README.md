# Profile format v1

Profiles describe the ClientHello and HTTP wire settings independently of
connection state. `profile.Load` reads native JSON;
`profile.ImportPeet(capture, allowOpaque)` converts a `tls.peet.ws/api/all` capture.
The importer accepts HTTP/2 and HTTP/1.1 captures. It never imports captured
request headers, cookies, IP addresses, SNI, client randoms, session identifiers,
private keys, key-share bytes or encrypted ECH payloads.

```go
p, err := profile.ImportPeet(captureJSON, true)
// Handle err and inspect p.Limitations().
spec, err := p.NewClientHelloSpecWithOptions(profile.ClientHelloOptions{
    RandomJA3: false,
    ForceHTTP1: false,
})
```

Each call creates a new spec with independently owned extension instances. The
immutable `Profile` can be shared by concurrent requests. Never reuse a spec
across connections: uTLS mutates it during `ApplyPreset`. `HTTP2()` returns a
deep copy, and `Hash()` identifies the canonical native profile JSON.

`NewClientHelloSpec()` remains equivalent to passing zero options. Extension,
cipher, signature and group order is preserved by default. Legal repeated
signature algorithms are preserved, including Safari's duplicated values.
The importer cross-checks numeric signature vectors from `peetprint` and
`ja4_r`, when present, to correct Peet's historical Ed448-as-Ed25519 label bug.
Conflicting numeric vectors or unrelated name/ID disagreements are rejected.

## Connection options and protocol metadata

`RandomJA3` shuffles ordinary TLS extensions separately for each new connection.
It uses `crypto/rand`, preserves the positions of GREASE and padding, and never
changes the shared profile. Session resumption appends its own PSK extension
last. This is a Chrome-style extension permutation policy; it does not emulate
every browser's complete randomization distribution. Reusing an open connection
does not create another ClientHello or another permutation.

The optional native `http_version` field is `h2` (the default) or `http/1.1`.
`HTTPVersion()` returns this metadata. It does not implicitly rewrite the TLS
ALPN extension. A capture containing HTTP/1.1 has no sampled HTTP/2 settings;
if a server negotiates h2, the transport uses its default HTTP/2 settings and
the profile reports this limitation.

Explicit `ForceHTTP1` restricts an existing ALPN/NPN list to `http/1.1` and
removes HTTP/2 ALPS extensions. Those intentional edits change the TLS
fingerprint. An absent ALPN extension remains absent.

## Cipher suites and extension values

Native profiles use numeric 16-bit cipher IDs. Peet import accepts IANA cipher
names, numeric IDs and numeric strings. `profile/cipher_registry.go` contains a
snapshot of every named entry in the [IANA cipher registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4),
fetched on 2026-09-06, with the upstream uTLS dictionary as a compatibility
fallback. Future numeric cipher IDs do not require a package update. The older
Peet names `TLS_EMPTY_RENEGOTIATION_INFO` and `TLS_FALLBACK` map to their SCSV IDs.

Advertising a registry ID does not add its cryptographic implementation to
uTLS. Unsupported cipher suites, named groups, signature schemes, EC point
formats and TLS version advertisements are identified in `Limitations()`.
The connection fails if the server requires an algorithm uTLS cannot perform.
Key shares still require a group whose keys uTLS can actually generate; they
cannot be supplied as captured raw bytes. The engine permits TLS 1.0 through
TLS 1.3 negotiation, and retains unsupported version advertisements with a
limitation rather than claiming to negotiate those versions.

Typed extension builders include:

| Native type | TLS ID | Additional fields |
| --- | --- | --- |
| `server_name` | 0 | SNI comes from the request destination |
| `status_request`, `status_request_v2` | 5, 17 | Standard empty OCSP requests |
| `supported_groups`, `ec_point_formats` | 10, 11 | Ordered `values` |
| `signature_algorithms`, `signature_algorithms_cert` | 13, 50 | Ordered `values`, optional `allow_unsupported` |
| `alpn`, `npn` | 16, 13172 | Ordered `protocols` |
| `sct`, `extended_master_secret` | 18, 23 | No data fields |
| `padding` | 21 | `padding_length` in wire bytes, including zero |
| `token_binding` | 24 | `values`: major version, minor version, then key parameter IDs |
| `compress_certificate` | 27 | Ordered compression algorithm `values` |
| `record_size_limit` | 28 | `record_size_limit` in 64..16385 |
| `delegated_credentials` | 34 | Ordered signature `values`, optional `allow_unsupported` |
| `session_ticket` | 35 | An empty advertisement, never a captured ticket |
| `supported_versions`, `psk_key_exchange_modes` | 43, 45 | Ordered `values` |
| `key_share` | 51 | Group `values`; fresh keys generated per connection |
| `application_settings`, `application_settings_new` | 17513, 17613 | Ordered `protocols` |
| `channel_id_old`, `channel_id` | 30031, 30032 | Advertisement only |
| `grease_ech` | 65037 | Optional `payload_lengths` and `ech_cipher_suites` |
| `renegotiation_info` | 65281 | Empty initial renegotiation state |
| `grease` | GREASE placeholder | A fresh GREASE value per connection |

These use the [uTLS extension implementations](https://github.com/refraction-networking/utls/blob/v1.8.2/u_tls_extensions.go).
uTLS's delegated credentials, record size limit, token binding and channel ID
builders advertise those extensions without implementing their full protocol
behavior. ALPS negotiation is delegated to uTLS, but this transport does not
apply peer HTTP/2 ALPS settings or configure custom client ALPS payloads.
These limitations are returned by `Limitations()`.

GREASE ECH preserves the captured outer payload shape and supported HPKE
KDF/AEAD identifiers while generating new key material, config ID and ciphertext.
`ech_cipher_suites` is an array of `{ "kdf_id": 1, "aead_id": 1 }` entries.
Importing a shape does not establish genuine ECH support. Captured encrypted
material is never retained. GREASE extension body lengths are not present in
Peet captures; uTLS's BoringSSL convention supplies an empty first body and a
single zero byte second body.

## Explicit opaque payloads and excluded session state

`allowOpaque=true` permits unsupported signature advertisements and static
extensions that have an explicit raw payload. Unknown static extensions use
`{ "type": "raw", "id": 60000, "data_hex": "1234", "allow_opaque": true }`.
They preserve bytes and position, and report that their protocol behavior is
not implemented. Strict import continues to reject those opt-ins.

Known typed protocol extensions cannot bypass validation through `raw`.
PSK (41), early data (42), retry cookies (44), nonempty session tickets (35),
captured key shares, ECH and legacy ESNI state cannot be replayed this way.
Resumed/retry captures are explicitly rejected even with `allowOpaque=true`;
provide a fresh full-handshake capture. Runtime session resumption independently
obtains and uses the Session's own valid tickets.

The bundled `chrome_152.json` opts into the static trust anchors extension
51764 and signature IDs 0x0904, 0x0905 and 0x0906. Sending extension 51764 does
not implement its certificate selection/retry protocol. Those signatures are
advertised but cannot be verified by uTLS v1.8.2 if selected by the server.

## HTTP/2 metadata

SETTINGS and pseudo headers use ordered arrays. Unknown numeric SETTINGS IDs
are preserved; Peet `UNKNOWN_SETTING_<number>` names are accepted. Zero values
are retained. `connection_window_update` is the increment beyond 65,535 bytes.
`header_priority.weight` uses 1..256, converted to the wire range 0..255.
Captured initial PRIORITY frames are retained as `initial_priorities` metadata,
but the current transport does not emit them; the limitation explicitly states
that the complete HTTP/2 fingerprint is not reproduced for those profiles.

`profile.schema.json` provides structural validation. Go validation additionally
checks lengths, duplicate extensions, supported key generation and consistency.
An optional local corpus test builds ClientHellos without making connections:

```sh
REQUESTS_UTLS_CAPTURE_DIRS=/absolute/captures:/absolute/other-captures \
    go test ./profile -run TestLocalCaptureCorpus -v
```

This is a local import/build check, not proof of a successful remote handshake
or identical server-observed fingerprints.

Peet's `padding_data_length` counts hexadecimal characters, as its
[parser implementation](https://github.com/pagpeter/TrackMe/blob/master/pkg/tls/parse_client_hello.go#L349-L358)
reports the length of the encoded extension data. Import converts that count
to wire bytes by dividing by two and rejects odd or oversized counts. Native
`padding_length` always uses bytes.

Older captures can contain mutually inconsistent fingerprint fields. For
example, [TrackMe PR 40](https://github.com/pagpeter/TrackMe/pull/40) fixed JA4's
incorrect exclusion of padding on 2026-08-26. Such captures include padding in
their extension list and JA3 while omitting it from JA4's extension hash input.
Preserving the captured TLS extensions produces the corrected current JA4,
so the old literal JA4 cannot also match. Validation must report this baseline
inconsistency separately; it must not remove a captured wire extension or
silently count the old literal fingerprint as an exact match.
