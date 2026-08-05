// Shared launcher. Spawns a bundled universal macOS binary with stdio passthrough.
"use strict";
const { spawn } = require("node:child_process");
const { join } = require("node:path");
const { existsSync } = require("node:fs");

function launch(binaryName) {
  if (process.platform !== "darwin") {
    process.stderr.write(
      `${binaryName} runs on macOS 13 or later only. ` +
        "It uses Network.framework for SMTP probes.\n" +
        "See https://github.com/rashidazarang/email-intel for the Swift source.\n",
    );
    process.exit(1);
  }

  const binary = join(__dirname, "..", "vendor", binaryName);
  if (!existsSync(binary)) {
    process.stderr.write(`Bundled binary not found: ${binary}. Reinstall the package.\n`);
    process.exit(1);
  }

  const child = spawn(binary, process.argv.slice(2), { stdio: "inherit" });
  child.on("exit", (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code === null ? 1 : code);
  });
  child.on("error", (err) => {
    process.stderr.write(`Failed to start ${binaryName}: ${err.message}\n`);
    process.exit(1);
  });
}

module.exports = { launch };
