# Security policy

Security fixes target the latest release and current development branch; older
0.x versions do not have separate security branches.

Use **Security → Report a vulnerability** when available. Otherwise, open an
issue asking for a private reporting channel without disclosing vulnerability
details. Never post credentials, private captures, session tickets or exploits
in public reports. Include the engine commit, ABI, platform and a minimal reproducer.

Certificate verification is enabled by default. Request isolation, proxy
credential isolation, cancellation, resource bounds and native ownership are
supported guarantees; report violations even when triggered by malformed peers.
Profile advertisements do not guarantee full protocol implementation. See
[profile capabilities](docs/profile-capabilities.md) and
[upstream maintenance](docs/maintenance.md).
