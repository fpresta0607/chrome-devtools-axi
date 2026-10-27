import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type AddressInfo } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  closeBridgeTransport,
  createTransport,
  resolveTransport,
} from "../src/bridge.js";

/**
 * Starts the real chrome-devtools-mcp through the bridge's own transport from
 * a fresh home, where its update cache is absent, so its startup update check
 * would run if anything let it. The home's `.npmrc` points the registry at a
 * loopback recorder, as does the telemetry fixture, so requests stay local.
 */

const MCP_PATH = fileURLToPath(
  new URL("./fixtures/loopback-telemetry-mcp.mjs", import.meta.url),
);
const HOME_VARIABLES = ["HOME", "USERPROFILE", "LOCALAPPDATA"] as const;
const SAVED_VARIABLES = [
  ...HOME_VARIABLES,
  "CHROME_DEVTOOLS_AXI_MCP_PATH",
  "CHROME_DEVTOOLS_AXI_MCP_SERVER_URL",
] as const;
// How long a detached update checker gets to reach the registry: it starts
// npm, reads the registry setting, then fetches, about two seconds on Windows.
const CHECKER_WINDOW_MS = 3_000;

const saved = Object.fromEntries(
  SAVED_VARIABLES.map((name) => [name, process.env[name]]),
);
const cleanups: (() => Promise<void> | void)[] = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  for (const name of SAVED_VARIABLES) {
    if (saved[name] === undefined) delete process.env[name];
    else process.env[name] = saved[name];
  }
});

describe("chrome-devtools-mcp started by the bridge", () => {
  it("runs no update check, writes no telemetry state and asks no registry from a fresh home", async () => {
    // Arrange
    const requests: string[] = [];
    const recorder = createServer((request, response) => {
      requests.push(`${request.method} ${request.url}`);
      response.writeHead(404).end();
    });
    await new Promise<void>((resolveListen) =>
      recorder.listen(0, "127.0.0.1", resolveListen),
    );
    cleanups.push(
      () =>
        new Promise<void>((resolveClose) =>
          recorder.close(() => resolveClose()),
        ),
    );
    const { port } = recorder.address() as AddressInfo;
    const home = mkdtempSync(join(tmpdir(), "cdp-offline-home-"));
    cleanups.push(() =>
      rmSync(home, { recursive: true, force: true, maxRetries: 5 }),
    );
    const recorderUrl = `http://127.0.0.1:${port}`;
    writeFileSync(join(home, ".npmrc"), `registry=${recorderUrl}/\n`);
    writeFileSync(join(home, "recorder-url"), recorderUrl);
    for (const name of HOME_VARIABLES) process.env[name] = home;
    process.env.CHROME_DEVTOOLS_AXI_MCP_PATH = MCP_PATH;
    delete process.env.CHROME_DEVTOOLS_AXI_MCP_SERVER_URL;
    const bridgeTransport = createTransport(resolveTransport());
    const client = new Client({ name: "offline-proof", version: "0.0.0" });
    cleanups.push(() => closeBridgeTransport(bridgeTransport));

    // Act
    await client.connect(bridgeTransport.transport);
    const deadline = Date.now() + CHECKER_WINDOW_MS;
    while (Date.now() < deadline && requests.length === 0)
      await sleep(100);

    // Assert
    expect(requests).toEqual([]);
    expect(readdirSync(home, { recursive: true }).sort()).toEqual([
      ".npmrc",
      "recorder-url",
    ]);
  }, 60_000);
});
