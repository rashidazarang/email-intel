# Security

## Report a vulnerability

Use GitHub private vulnerability reporting on this repository. Do not open a public issue for a security problem. You get an acknowledgment within 7 days.

## What this tool does on the network

Know what the tool touches before you run it:

1. **DNS over HTTPS.** The resolver sends queries for the target domain to the Cloudflare JSON API (`cloudflare-dns.com`). Cloudflare sees every domain that you look up.
2. **SMTP probes.** The `smtp_probe` tool and the full `email_intel` assembly open a TCP connection to a mail host, read the banner, send `EHLO`, and check for STARTTLS. The probe sends no mail and no credentials.
3. **Nothing else.** The header analyzer works offline. The tool has no telemetry, no analytics, and no update checks.

## Rules for use

Do not probe hosts that you do not have the right to probe. An SMTP connection to port 25 is visible to the target and to networks on the path. Some providers treat unrequested probes as abuse. You are responsible for the targets that you select.

## Known limitations

The controls are honest about what they do not guarantee:

1. **DKIM detection is partial.** The tool finds DKIM only through discoverable selectors. A domain with a custom selector can grade lower than its true posture.
2. **The security grade is an outside view.** It measures published DNS policy and STARTTLS support. It does not measure inbox placement, content filtering, or internal controls.
3. **Networks block SMTP probes.** Firewalls and providers block port 25. A blocked probe lowers the TLS dimension to its unprobed value. That is a measurement gap, not a finding.
4. **DoH is a third party.** Query privacy depends on Cloudflare's policies. If that matters for your use, run the tool inside a network that you control.
5. **The parser trusts no input.** The header parser accepts arbitrary text. Parser bugs are possible. Report them through the channel above.
6. **No rate limiting.** The tool does not throttle itself. A caller that loops over many domains builds its own rate control.

## Supported versions

Only the latest release receives fixes.
