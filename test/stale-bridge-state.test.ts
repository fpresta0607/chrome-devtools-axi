import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createNetServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createBridgeServer } from "../src/bridge.js";
import { createBridgeAuth, RESPONSE_PROOF_HEADER } from "../src/bridge-auth.js";
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

  it("preserves a confirmed bridge when its listener does not authenticate", async () => {
    const bridge = spawn(
      process.execPath,
      [resolve("test/fixtures/legacy/chrome-devtools-axi-bridge.js")],
      { stdio: ["ignore", "pipe", "ignore"], windowsHide: true },
    );
    const exited = once(bridge, "exit");
    try {
      const [line] = await once(bridge.stdout, "data");
      if (!bridge.pid) throw new Error("Bridge fixture did not start");
      const port = Number(String(line).trim());
      writeBridgeState(port, "a".repeat(64), SESSION, bridge.pid);
      const start = vi.fn();

      await expect(ensureBridge(start)).rejects.toThrow(
        /authentication failed/,
      );

      expect(start).not.toHaveBeenCalled();
      expect(readBridgeState(SESSION)?.pid).toBe(bridge.pid);
      expect(isAlive(bridge.pid)).toBe(true);
    } finally {
      bridge.kill();
      await exited;
    }
  }, 30_000);

  it.each(["absent", "unsigned", "wrongly signed"])(
    "is replaced without terminating that process when the old listener is %s",
    async (listener) => {
      const port = await freePort();
      process.env.CHROME_DEVTOOLS_AXI_PORT = String(port);
      const squatter = createServer((request, response) => {
        const body = JSON.stringify({ status: "ok", session: SESSION });
        if (listener === "wrongly signed") {
          response.setHeader(
            RESPONSE_PROOF_HEADER,
            createBridgeAuth("b".repeat(64)).signResponse(
              request.headers.authorization ?? "",
              200,
              body,
            ),
          );
        }
        response.end(body);
      });
      let oldPort = port;
      if (listener !== "absent") {
        await new Promise<void>((ready) =>
          squatter.listen(0, "127.0.0.1", ready),
        );
        oldPort = (squatter.address() as AddressInfo).port;
      }
      writeBridgeState(oldPort, "a".repeat(64), SESSION, unrelatedPid);
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
        squatter.closeAllConnections();
        await new Promise<void>((closed) => squatter.close(() => closed()));
      }
    },
    60_000,
  );
});
