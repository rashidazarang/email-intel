# email-intel

**Email infrastructure fingerprinting for Swift.** Give email-intel a domain. It tells you who runs the domain's mail (Google Workspace, Microsoft 365, SendGrid, Mailgun, Klaviyo, and 30 more). It scores the anti-spoofing posture (SPF, DKIM, DMARC, STARTTLS) to a letter grade. It also parses raw headers and shows the path a message took to your inbox.

From the team behind [warming.email](https://warming.email).

[![CI](https://github.com/rashidazarang/email-intel/actions/workflows/ci.yml/badge.svg)](https://github.com/rashidazarang/email-intel/actions/workflows/ci.yml)
![Swift 6](https://img.shields.io/badge/Swift-6-orange)
![macOS 13+](https://img.shields.io/badge/macOS-13%2B-blue)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

The package uses Swift 6 strict concurrency and has **zero external dependencies**. DNS runs over HTTPS through `URLSession`. SMTP runs through `Network.framework`. JSON comes from `Foundation`. The suite has 116 tests. The full tree builds with `-warnings-as-errors`.

## Three ways in

| Product | Type | Use it from |
|---|---|---|
| `EmailIntel` | Swift library | Any Swift 6 / macOS 13+ project (SwiftPM) |
| `email-intel-cli` | CLI | Your terminal, or a subprocess from any language (JSON on stdout) |
| `EmailIntelMCP` | MCP server | Any MCP client (Claude Code, Claude Desktop, Cursor) over stdio |

## Quick start (CLI)

```bash
npx -y -p email-intel-mcp email-intel-cli stripe.com
```

Or build from source:

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

Add the server to any MCP client with one config block. npm delivers the bundled macOS binaries. There is no key and no build step:

```json
{
  "mcpServers": {
    "email-intel": {
      "command": "npx",
      "args": ["-y", "email-intel-mcp"]
    }
  }
}
```

For Claude Code:

```bash
claude mcp add email-intel -- npx -y email-intel-mcp
```

If you build from source, point the client at the binary instead: `.build/release/EmailIntelMCP`.

| Tool | Input | Output |
|---|---|---|
| `email_intel` | `{ "domain": "example.com" }` | Full `EmailIntelligence`: providers, security score, DNS profile, summary |
| `dns_lookup` | `{ "domain": "example.com" }` | `DNSProfile`: MX, SPF, DKIM presence, DMARC, TXT records |
| `smtp_probe` | `{ "host": "mail.example.com", "port": 25 }` | `SMTPProfile`: banner, EHLO extensions, STARTTLS support |
| `email_headers` | `{ "raw_headers": "Received: ..." }` | `EmailHeaderAnalysis`: Received chain, auth results, ARC sets, originating IP |

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

You can also analyze headers offline, with no network access:

```swift
let analysis = await engine.analyzeHeaders(rawHeaders: rawMessage)
print(analysis.receivedChain.count)
print(analysis.authenticationResults.first?.results)
```

## What is inside

```
Sources/EmailIntel/
├── Models/         # DNSProfile, MailSecurity, SMTPProfile, EmailProvider,
│                   # EmailHeaderAnalysis, EmailIntelligence (all Codable + Sendable)
├── Fingerprints/   # 36-service signature database (SPF includes, DKIM selectors,
│                   # MX patterns, TXT verification tokens)
├── DNS/            # DoH resolver (Cloudflare JSON API), MX/SPF/DMARC/DKIM/BIMI parsers
├── SMTP/           # NWConnection-based prober: banner, EHLO, STARTTLS detection
├── Headers/        # RFC 5322 folding, RFC 7601 Authentication-Results, RFC 8617 ARC
├── Classification/ # webmail / disposable / provider classification
└── Engine/         # SecurityScorer (4-dimension rubric → A+/A/B/C/D/F),
                    # EmailIntelligenceEngine (assembles everything)

Sources/EmailIntelMCP/   # line-delimited JSON-RPC 2.0 over stdin/stdout, 4 tools
Sources/EmailIntelCLI/   # thin CLI over the same engine, JSON on stdout
```

### Security scoring rubric

The scorer assigns 100 points across four dimensions, then maps the total to a letter grade:

| Dimension | 25 pts | 20 pts | 10 pts | 5 pts | 0 pts |
|---|---|---|---|---|---|
| **SPF** | `-all` (hardfail) | `~all` (softfail) | `?all` (neutral) | `+all` (critical) | missing |
| **DKIM** | present | - | - | - | missing |
| **DMARC** | `p=reject` | `p=quarantine` | `p=none` | - | missing |
| **TLS** | STARTTLS supported | - | - | - | not supported (15 if unprobed) |

Grade boundaries: **A+** ≥95, **A** 85–94, **B** 70–84, **C** 55–69, **D** 40–54, **F** <40.
Posture: A+/A → `strict`, B → `moderate`, C/D/F → `minimal`.

> A note on grades. DKIM detection needs selectors that this tool can discover. A domain can
> grade lower here than its true posture. The grade measures what an outside observer can
> verify. Receiving mail servers see the same thing.

## Conventions

- macOS 13+ minimum. Swift 6 strict concurrency: `Sendable` everywhere, actors for stateful resolvers and probers.
- No force unwraps and no `as!` in `Sources/**`.
- Zero external SPM dependencies.
- `os.Logger` for logging. No `print()` outside the CLI's output path.
- The bar for every change: `swift build -Xswiftc -warnings-as-errors && swift test`.

## Why this exists

Deliverability work starts with a question that most senders never ask: what does my domain look like from the outside? email-intel answers it. Check your own domain before a campaign. Check a prospect's domain before you write to them. If your domain grades below A, [warming.email](https://warming.email) gets it ready to send.

## License

[Apache-2.0](LICENSE) © Rashid Azarang
