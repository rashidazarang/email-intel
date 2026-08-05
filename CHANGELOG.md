# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-08-05

First public release, extracted from a private package.

### Added

- The `EmailIntel` library: DNS profile, provider fingerprints (36 services), SMTP probe, header analysis, and a security scorer that maps SPF, DKIM, DMARC, and TLS to a letter grade.
- `email-intel-cli`: domain intelligence and header analysis as JSON on stdout.
- `EmailIntelMCP`: an MCP server over stdio with 4 tools (`email_intel`, `dns_lookup`, `smtp_probe`, `email_headers`).
- Governance set: SECURITY, CONTRIBUTING, SUPPORT, AGENTS, and a prose gate (Vale, STE style).
- CI: build with warnings as errors, 116 tests, prose lint, and a version sync check.

### Changed

- The MCP server now reads its version from `EmailIntel.version`. Before, it reported a stale hardcoded value.

### Removed

- The license gate from the private distribution. Every tool runs without a key.

[0.2.0]: https://github.com/rashidazarang/email-intel/releases/tag/v0.2.0
