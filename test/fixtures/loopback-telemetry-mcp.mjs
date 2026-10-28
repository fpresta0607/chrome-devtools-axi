// Route real MCP telemetry to the test recorder, even if its opt-out regresses.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

const recorderUrl = readFileSync(join(homedir(), "recorder-url"), "utf8");
process.argv.push(
  `--clearcut-endpoint=${recorderUrl}/clearcut`,
  "--clearcut-force-flush-interval-ms=100",
);
const packageDir = dirname(
  createRequire(import.meta.url).resolve("chrome-devtools-mcp/package.json"),
);
await import(
  pathToFileURL(join(packageDir, "build/src/bin/chrome-devtools-mcp.js")).href
);
