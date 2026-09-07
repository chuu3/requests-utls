# Security policy

## Supported versions

Security fixes target the latest released version and the current development
branch. Older 0.x releases are not maintained as separate security branches.
When reporting an issue, include the engine commit and ABI version; Python users
should also include their package version and platform.

## Reporting

Use this repository's **Security → Report a vulnerability** option when it is
available. If the private reporting option is unavailable, open an issue asking
the maintainer for a private reporting channel, without vulnerability details.
Do not post credentials, private captures, session tickets or an exploit in a
public issue. A useful private report includes affected versions, a minimal
reproducer, observed impact and relevant configuration.

## Scope and maintenance

Certificate validation is enabled by default. Explicitly disabling validation
changes that trust boundary. TLS profiles may opt into advertisements whose
complete protocol behavior is not implemented; these limits are described in
[profile capabilities](docs/profile-capabilities.md) and returned by the engine.

Resource limits, cancellation, proxy credential isolation and C ABI ownership
are part of the supported contract. Report failures of these guarantees even if
they require a malformed peer response.

Dependency scanning is complemented by a separate review of the copied HTTP/2
implementation. A clean vulnerability scan does not establish that the local
fork contains every upstream fix. See [maintenance](docs/maintenance.md).
