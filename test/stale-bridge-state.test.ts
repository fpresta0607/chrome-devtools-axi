import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer as createNetServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createBridgeServer } from "../src/bridge.js";
import { createBridgeAuth } from "../src/bridge-auth.js";
import { readBridgeState, writeBridgeState } from "../src/bridge-state.js";
import { ensureBridge, stopBridge, type SpawnedBridge } from "../src/client.js";
import { resolveSessionPidFile } from "../src/sessions.js";

/**
 * A bridge that dies without its shutdown handler (a forced kill, a crash, a
 * reboot) leaves bridge.pid behind, and Windows soon hands that pid to an
 * unrelated process. These run the real ACL and process checks.
 */

const SESSION = "reused-pid";
const SAVED_ENVIRONMENT = Object.fromEntries(
  [
    "HOME",
    "USERPROFILE",
    "CHROME_DEVTOOLS_AXI_SESSION",
    "CHROME_DEVTOOLS_AXI_PORT",
  ].map((key) => [key, process.env[key]]),
);

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function freePort(): Promise<number> {
  return new Promise((resolvePort, rejectPort) => {
    const probe = createNetServer();
    probe.once("error", rejectPort);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address() as AddressInfo;
      probe.close(() => resolvePort(port));
    });
  });
}

describe("a bridge record whose pid now belongs to an unrelated process", () => {
  let home: string;
  let unrelated: ChildProcess;
  let unrelatedPid: number;

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "axi-stale-state-"));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    process.env.CHROME_DEVTOOLS_AXI_SESSION = SESSION;
    delete process.env.CHROME_DEVTOOLS_AXI_PORT;
    unrelated = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
      stdio: "ignore",
      windowsHide: true,
    });
    await once(unrelated, "spawn");
    unrelatedPid = unrelated.pid as number;
  });

  afterEach(async () => {
    if (unrelated.exitCode === null) {
      const exited = once(unrelated, "exit");
      unrelated.kill("SIGKILL");
      await exited;
    }
    for (const [key, value] of Object.entries(SAVED_ENVIRONMENT)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(home, { recursive: true, force: true });
  });

  it("is cleared by stop without terminating that process", async () => {
    writeBridgeState(await freePort(), "a".repeat(64), SESSION, unrelatedPid);

    await expect(stopBridge()).resolves.toBe(false);

    expect(existsSync(resolveSessionPidFile(SESSION))).toBe(false);
    expect(isAlive(unrelatedPid)).toBe(true);
  }, 30_000);

  it("is replaced by a fresh bridge without terminating that process", async () => {
    const port = await freePort();
    process.env.CHROME_DEVTOOLS_AXI_PORT = String(port);
    writeBridgeState(port, "a".repeat(64), SESSION, unrelatedPid);
    const secret = "d".repeat(64);
    const replacement = createBridgeServer(
      {
        listTools: async () => ({ tools: [] }),
        callTool: async () => ({
          content: [
            { type: "text", text: "## Pages\n1: about:blank [selected]" },
          ],
        }),
        close: async () => {},
      },
      SESSION,
      undefined,
      createBridgeAuth(secret),
    );

    try {
      const resolvedPort = await ensureBridge(() => {
        replacement.listen(port, "127.0.0.1", () =>
          writeBridgeState(port, secret, SESSION),
        );
        return new EventEmitter() as unknown as SpawnedBridge;
      });

      expect(resolvedPort).toBe(port);
      expect(readBridgeState(SESSION)?.secret === secret).toBe(true);
      expect(isAlive(unrelatedPid)).toBe(true);
    } finally {
      replacement.closeAllConnections();
      await new Promise<void>((closed) => replacement.close(() => closed()));
    }
  }, 60_000);
});
