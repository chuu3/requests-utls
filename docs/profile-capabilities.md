# Profile capabilities

Treat these as separate questions: can the profile be imported, can the peer
complete a handshake, do the observed fingerprint fields match, and is the
complete negotiated feature implemented? A result at one level does not imply
the next. `Profile.Limitations()` and Python `session.limitations` expose known
limits for a selected profile.

| Feature | What the engine reproduces | Boundary |
| --- | --- | --- |
| Cipher IDs | Numeric IDs and captured ordering; named IANA entries can be imported | The selected algorithm must be implemented by uTLS |
| Extension ordering | Profile order, or optional per-connection shuffling | A capture represents one ordering, not a complete browser distribution |
| GREASE | Profile-selected occurrences and positions, with fresh values | Presence is controlled by the profile; it is not added by a universal browser rule |
| Key shares and TLS randoms | Configured group order and freshly generated material | Captured private keys and random bytes are not replayed |
| `trust_anchors` 51764 | Explicitly opted-in static payload and position | Certificate selection, dynamic anchor state and retry behavior are not implemented |
| ECH | GREASE ECH with newly generated contents | This does not implement encrypted SNI |
| ALPS | uTLS extension advertisement and negotiation behavior | Custom client payloads and applying peer HTTP/2 application settings are not implemented |
| Session resumption | Real tickets cached within the Session; fresh binders on reconnect | Captured PSK/ticket state is not imported; the server may decline resumption |
| HTTP/2 | Configured initial settings, window update, pseudo-header and regular-field order | Full browser HPACK policy, arbitrary frame scheduling and HTTP/3 are outside this implementation |
| HTTP/1.1 | Header spelling, ordered occurrences and connection reuse | Forcing HTTP/1.1 can change ALPN and the resulting TLS fingerprint |

See the [profile reference](../profiles/README.md) for individual builders and
validation rules. The builtins `chrome_150` and `chrome_152` are separate sanitized
captures declared in `profiles/builtin.json`. Neither certifies every platform
of that browser version or every server-selected feature.

Local tests inspect ClientHello and HTTP frames against controlled servers.
The [live acceptance procedure](https://github.com/chuu3/requests-utls-python/blob/main/docs/profile-acceptance.md)
separately compares captured and observed fingerprints. Historical comparison
failures remain recorded even when a change in the endpoint's fingerprint
calculation explains them.

A CONNECT proxy that only forwards bytes preserves the target ClientHello. A
proxy performing TLS interception creates a separate connection to the target;
the target then observes that proxy's TLS behavior. Disabling certificate
validation does not prevent interception or preserve a replaced ClientHello.
