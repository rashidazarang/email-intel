#!/usr/bin/env bash
# Assemble the npm package in npm/.
# Builds the universal macOS binaries, copies them with the resource bundle
# into npm/vendor/, copies the README, and runs a launcher smoke test.
set -euo pipefail

cd "$(dirname "$0")/.."

swift build -c release --arch arm64 --arch x86_64

PRODUCTS=.build/apple/Products/Release
rm -rf npm/vendor
mkdir -p npm/vendor
cp "$PRODUCTS/EmailIntelMCP" npm/vendor/
cp "$PRODUCTS/email-intel-cli" npm/vendor/
cp -R "$PRODUCTS/email-intel_EmailIntel.bundle" npm/vendor/
cp README.md npm/README.md

lipo -info npm/vendor/EmailIntelMCP

node npm/bin/email-intel-cli.js --version
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | node npm/bin/email-intel-mcp.js \
  | grep -q '"serverInfo"' && echo "MCP launcher: OK"

echo "build-npm: OK"
