# Contributing

Thank you for the interest. This is a small tool with a high bar. Keep changes small and complete.

## Build and test

```bash
swift build -Xswiftc -warnings-as-errors
swift test
```

Both commands must pass before you open a PR. CI runs the same commands.

## The quality bar

- No force unwraps and no `as!` in `Sources/**`.
- No new dependencies. The package stays at zero external dependencies.
- Fix every instance of a problem, not only the reported one.
- A fix must make the code simpler, not more complex.

## The writing standard

All prose follows a reduced ASD-STE100 style. The full rules are in `AGENTS.md`. The short version:

- Never use an em dash.
- Write short sentences. Use the active voice.
- Give one instruction per sentence.

Run the prose gate before you push:

```bash
vale README.md SECURITY.md CONTRIBUTING.md SUPPORT.md AGENTS.md
```

## Versioning

`EmailIntel.version` in `Sources/EmailIntel/EmailIntel.swift` is the only version constant. When you change shipped behavior:

1. Bump `EmailIntel.version`.
2. Add a CHANGELOG entry with the same version.
3. Run `scripts/check-versions.sh`.
