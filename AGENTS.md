# Working on email-intel

Rules for any agent or human who edits this repository. `CLAUDE.md` is a symlink to this file, so every tool reads the same guidance.

## The bar

**Every change passes the full gate before commit.**

```bash
swift build -Xswiftc -warnings-as-errors
swift test
vale README.md SECURITY.md CONTRIBUTING.md SUPPORT.md AGENTS.md
./scripts/check-versions.sh
```

## Code rules

**No force unwraps and no `as!` in `Sources/**`.** Handle the nil case or fail with a message.

**No new dependencies.** The package has zero external dependencies. Keep it that way. DNS runs through `URLSession`, SMTP through `Network.framework`, JSON through `Foundation`.

**Strict concurrency everywhere.** All models stay `Sendable`. Stateful resolvers and probers stay actors.

**Fix every instance.** When you find a bug pattern, search for it across the tree and fix all of it.

**A fix must simplify.** If your fix adds a layer, a flag, or a special case, look for the version that removes one instead.

## Writing rules

All prose follows a reduced ASD-STE100 style. Prose means README, docs, commit messages, PR text, and CHANGELOG entries.

- **Never use an em dash.** Use a period, a comma, a colon, or parentheses.
- **Write short sentences.** Target 20 words for an instruction, 25 for a description.
- **Give one instruction per sentence.** Use a numbered list for a sequence.
- **Use the active voice and the present tense.** Name the actor.
- **Keep the articles.** Write "run the script", not "run script".
- **Use one name for one thing.** The product is email-intel. The library is `EmailIntel`. The CLI is `email-intel-cli`. The server is `EmailIntelMCP`.
- **No marketing words.** Describe what the tool does.

Tables, code blocks, JSON examples, and CHANGELOG history are exempt.

## Version rules

`EmailIntel.version` in `Sources/EmailIntel/EmailIntel.swift` is the only version constant. The CLI and the MCP server read it. When shipped behavior changes:

1. Bump `EmailIntel.version`.
2. Add a CHANGELOG entry with the same version and today's date.
3. Tag the release as `v<version>` after merge.

`scripts/check-versions.sh` fails when these disagree. CI runs it.

## Security rules

Do not add telemetry, analytics, or update checks. Do not add code that probes hosts the caller did not name. Update `SECURITY.md` when the network behavior changes.
