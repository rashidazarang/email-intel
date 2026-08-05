# email-intel

**Email infrastructure fingerprinting for Swift.** Given a domain, email-intel tells you who runs its mail (Google Workspace, Microsoft 365, SendGrid, Mailgun, Klaviyo, …), how strict its anti-spoofing posture is (SPF, DKIM, DMARC, STARTTLS — scored to a letter grade), and what its raw headers reveal about the path a message took to your inbox.

From the team behind [warming.email](https://warming.email).

[![CI](https://github.com/rashidazarang/email-intel/actions/workflows/ci.yml/badge.svg)](https://github.com/rashidazarang/email-intel/actions/workflows/ci.yml)
![Swift 6](https://img.shields.io/badge/Swift-6-orange)
![macOS 13+](https://img.shields.io/badge/macOS-13%2B-blue)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Built on Swift 6 strict concurrency. **Zero external dependencies** — DNS-over-HTTPS via `URLSession`, SMTP via `Network.framework`, JSON via `Foundation`. 116 tests; the whole tree builds with `-warnings-as-errors`.

## Three ways in

| Product | Type | Use it from |
|---|---|---|
| `EmailIntel` | Swift library | Any Swift 6 / macOS 13+ project (SwiftPM) |
| `email-intel-cli` | CLI | Your terminal, or subprocess it from any language (JSON on stdout) |
| `EmailIntelMCP` | MCP server | Any MCP client (Claude Code, Claude Desktop, Cursor, …) over stdio |

## Quick start (CLI)

```bash
git clone https://github.com/rashidazarang/email-intel.git
cd email-intel && swift build -c release

.build/release/email-intel-cli stripe.com
```

```jsonc
{
  "domain": "stripe.com",
  "classification": { "isDisposable": false, "isWebmail": false, "mxProvider": "Google Workspace" },
  "security": { "grade": "a", "score": 85, "findings": [ /* … */ ] },
  "summary": {
    "mailboxProviders": ["Google Workspace"],
    "transactionalServices": ["SendGrid", "Mandrill"],
    "securityPosture": "strict"
  },
  "dns": { "dmarcPolicy": "reject", "dkimFound": true /* … */ }
}
```

Analyze raw headers offline:

```bash
.build/release/email-intel-cli headers message.eml
.build/release/email-intel-cli headers -   # from stdin
```

## MCP server

Point any MCP client at the binary — no key, no config beyond the path:

```json
{
  "mcpServers": {
    "email-intel": {
      "command": "/path/to/email-intel/.build/release/EmailIntelMCP"
    }
  }
}
```

| Tool | Input | Output |
|---|---|---|
| `email_intel` | `{ "domain": "example.com" }` | Full `EmailIntelligence` — providers, security score, DNS profile, summary |
| `dns_lookup` | `{ "domain": "example.com" }` | `DNSProfile` — MX, SPF, DKIM presence, DMARC, TXT records |
| `smtp_probe` | `{ "host": "mail.example.com", "port": 25 }` | `SMTPProfile` — banner, EHLO extensions, STARTTLS support |
| `email_headers` | `{ "raw_headers": "Received: ..." }` | `EmailHeaderAnalysis` — Received chain, auth results, ARC sets, originating IP |

## Swift library

```swift
.package(url: "https://github.com/rashidazarang/email-intel.git", branch: "main"),
```

```swift
import EmailIntel

let engine = EmailIntelligenceEngine()
let dns = try await DNSResolver().resolveAll(domain: "stripe.com")
let smtp = await SMTPProber().probe(host: "smtp.stripe.com", port: 25)
let intel = try await engine.assembleFromData(domain: "stripe.com", dns: dns, smtp: smtp)

print(intel.security.grade)                // .a
print(intel.summary.mailboxProviders)      // ["Google Workspace"]
print(intel.summary.transactionalServices) // ["SendGrid", "Mandrill"]
```

Or just analyze headers, fully offline:

```swift
let analysis = await engine.analyzeHeaders(rawHeaders: rawMessage)
print(analysis.receivedChain.count)
print(analysis.authenticationResults.first?.results)
```

## What's inside

```
Sources/EmailIntel/
├── Models/         # DNSProfile, MailSecurity, SMTPProfile, EmailProvider,
│                   # EmailHeaderAnalysis, EmailIntelligence (all Codable + Sendable)
├── Fingerprints/   # 36-service signature database (SPF includes, DKIM selectors,
│                   # MX patterns, TXT verification tokens)
├── DNS/            # DoH resolver (Cloudflare JSON API), MX/SPF/DMARC/DKIM/BIMI parsers
├── SMTP/           # NWConnection-based prober — banner, EHLO, STARTTLS detection
├── Headers/        # RFC 5322 folding, RFC 7601 Authentication-Results, RFC 8617 ARC
├── Classification/ # webmail / disposable / provider classification
└── Engine/         # SecurityScorer (4-dimension rubric → A+/A/B/C/D/F),
                    # EmailIntelligenceEngine (assembles everything)

Sources/EmailIntelMCP/   # line-delimited JSON-RPC 2.0 over stdin/stdout, 4 tools
Sources/EmailIntelCLI/   # thin CLI over the same engine, JSON on stdout
```

### Security scoring rubric

100 points across four dimensions, mapped to a letter grade:

| Dimension | 25 pts | 20 pts | 10 pts | 5 pts | 0 pts |
|---|---|---|---|---|---|
| **SPF** | `-all` (hardfail) | `~all` (softfail) | `?all` (neutral) | `+all` (critical) | missing |
| **DKIM** | present | — | — | — | missing |
| **DMARC** | `p=reject` | `p=quarantine` | `p=none` | — | missing |
| **TLS** | STARTTLS supported | — | — | — | not supported (15 if unprobed) |

Grade boundaries: **A+** ≥95, **A** 85–94, **B** 70–84, **C** 55–69, **D** 40–54, **F** <40.
Posture: A+/A → `strict`, B → `moderate`, C/D/F → `minimal`.

> A note on grades: DKIM is only detectable when a domain publishes selectors this tool can
> discover, so a domain can grade lower here than its true posture. The grade measures what an
> outside observer can verify — which is exactly what receiving mail servers see.

## Conventions

- **macOS 13+** minimum, **Swift 6** strict concurrency (`Sendable` everywhere, actors for stateful resolvers/probers)
- **No force unwraps** and no `as!` in `Sources/**`
- **Zero external SPM dependencies**
- `os.Logger` for logging — no `print()` outside the CLI's output path
- `swift build -Xswiftc -warnings-as-errors && swift test` is the bar for every change

## Why this exists

Deliverability work starts with a question most senders never ask: *what does my domain look like from the outside?* email-intel answers it — for your own domain before a campaign, or for a prospect's domain before you write to them. If your domain grades below A, [warming.email](https://warming.email) gets it ready to send.

## License

[Apache-2.0](LICENSE) © Rashid Azarang
