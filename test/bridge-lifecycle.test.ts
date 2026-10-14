import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createConnection, createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAuthHeaders } from "../src/bridge-auth.js";
import { parsePagesList } from "../src/pages.js";

/**
 * Runs the real bridge process, detached as `ensureBridge` spawns it, against
 * a fake stdio MCP server (`fixtures/fake-mcp-server.mjs`) so its lifecycle can
 * be observed without launching a browser. Unit coverage of the idle rules
 * lives in `test/idle.test.ts`; this file proves the process actually exits.
 */

const ROOT = resolve(import.meta.dirname, "..");
const BRIDGE_SOURCE = join(ROOT, "bin", "chrome-devtools-axi-bridge.ts");
const FAKE_MCP = join(import.meta.dirname, "fixtures", "fake-mcp-server.mjs");
const SESSION = "lifecycle-test";

interface RunningBridge {
  child: ChildProcess;
  exited: Promise<number | null>;
  home: string;
  pidFile: string;
  mcpPid: number;
}

const started: RunningBridge[] = [];

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
    const probe = createServer();
    probe.once("error", rejectPort);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address() as AddressInfo;
      probe.close(() => resolvePort(port));
    });
  });
}

function withTimeout<T>(promise: Promise<T>, ms: number, what: string) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`Timed out after ${ms}ms: ${what}`)),
        ms,
      );
    }),
  ]).finally(() => clearTimeout(timer));
}

async function startBridge(
  extraEnv: Record<string, string> = {},
  home = mkdtempSync(join(tmpdir(), "axi-bridge-lifecycle-")),
): Promise<RunningBridge> {
  const mcpPidFile = join(home, "fake-mcp.pid");
  // Drop inherited AXI settings so a developer's own configuration (a shared
  // MCP URL, an idle timeout) cannot change which lifecycle is under test.
  const env: NodeJS.ProcessEnv = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) => !key.startsWith("CHROME_DEVTOOLS_AXI_"),
    ),
  );
  const child = spawn(process.execPath, ["--import", "tsx", BRIDGE_SOURCE], {
    cwd: ROOT,
    detached: true,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...env,
      HOME: home,
      USERPROFILE: home,
      CHROME_DEVTOOLS_AXI_SESSION: SESSION,
      CHROME_DEVTOOLS_AXI_PORT: String(await freePort()),
      CHROME_DEVTOOLS_AXI_MCP_PATH: FAKE_MCP,
      ...extraEnv,
    },
  });
  const exited = new Promise<number | null>((resolveExit) => {
    child.once("exit", (code) => resolveExit(code));
  });
  const running: RunningBridge = {
    child,
    exited,
    home,
    pidFile: join(
      home,
      ".chrome-devtools-axi",
      "sessions",
      SESSION,
      "bridge.pid",
    ),
    mcpPid: 0,
  };
  started.push(running);

  let stderr = "";
  child.stderr?.on("data", (chunk) => (stderr += chunk));
  await withTimeout(
    new Promise<void>((ready, fail) => {
      let stdout = "";
      child.stdout?.on("data", (chunk) => {
        stdout += chunk;
        if (stdout.includes("READY")) ready();
      });
      void exited.then((code) =>
        fail(new Error(`bridge exited (${code}) before READY: ${stderr}`)),
      );
    }),
    45_000,
    "bridge READY",
  );
  running.mcpPid = Number(readFileSync(mcpPidFile, "utf8"));
  return running;
}

afterEach(() => {
  for (const running of started.splice(0)) {
    for (const pid of [running.child.pid, running.mcpPid]) {
      if (pid && isAlive(pid)) process.kill(pid, "SIGKILL");
    }
    rmSync(running.home, { recursive: true, force: true });
  }
});

describe("bridge process lifecycle", () => {
  it("serves pages after initial and changed workspace roots", async () => {
    const running = await startBridge();
    const { port, secret } = JSON.parse(readFileSync(running.pidFile, "utf8"));

    for (const roots of [[running.home], [running.home], [ROOT]]) {
      const body = JSON.stringify({ name: "list_pages", args: {}, roots });
      const response = await fetch(`http://127.0.0.1:${port}/call`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...createAuthHeaders(secret, "POST", "/call", body),
        },
        body,
        signal: AbortSignal.timeout(5_000),
      });
      const payload = await response.json();

      expect(payload.error).toBeUndefined();
      expect(response.status).toBe(200);
      expect(parsePagesList(payload.result)).toEqual([
        { id: 1, url: "about:blank", selected: true },
      ]);
    }
  }, 90_000);

  it("stays up while idle when no idle timeout is configured", async () => {
    const running = await startBridge();

    await new Promise((settle) => setTimeout(settle, 2_000));

    expect(running.child.exitCode).toBeNull();
    expect(isAlive(running.mcpPid)).toBe(true);
    expect(existsSync(running.pidFile)).toBe(true);
  }, 90_000);

  it("shuts down after CHROME_DEVTOOLS_AXI_IDLE_TIMEOUT_MS with no requests", async () => {
    const running = await startBridge({
      CHROME_DEVTOOLS_AXI_IDLE_TIMEOUT_MS: "1000",
    });

    await expect(
      withTimeout(running.exited, 8_000, "idle bridge exit"),
    ).resolves.toBe(0);
    expect(existsSync(running.pidFile)).toBe(false);
    const deadline = Date.now() + 5_000;
    while (isAlive(running.mcpPid) && Date.now() < deadline) {
      await new Promise((settle) => setTimeout(settle, 50));
    }
    expect(isAlive(running.mcpPid)).toBe(false);
  }, 90_000);

  it("shuts down when its MCP server ends", async () => {
    const running = await startBridge();

    process.kill(running.mcpPid, "SIGKILL");

    await expect(
      withTimeout(running.exited, 8_000, "bridge exit after MCP server died"),
    ).resolves.toBe(0);
    expect(existsSync(running.pidFile)).toBe(false);
  }, 90_000);

  it.each(["unfinished body", "unfinished headers", "idle socket"])(
    "exits and stops MCP despite an unauthenticated %s",
    async (connection) => {
      const running = await startBridge({
        CHROME_DEVTOOLS_AXI_IDLE_TIMEOUT_MS: "1000",
      });
      const { port } = JSON.parse(readFileSync(running.pidFile, "utf8"));
      const socket = createConnection({ host: "127.0.0.1", port });
      socket.on("error", () => {});
      try {
        await once(socket, "connect");
        if (connection === "unfinished body") {
          socket.write(
            `POST /call HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nAuthorization: AXI-HMAC forged\r\nContent-Length: 1024\r\n\r\n{`,
          );
        } else if (connection === "unfinished headers") {
          socket.write(`POST /call HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n`);
        }

        await expect(
          withTimeout(
            running.exited,
            8_000,
            "idle bridge exit with a peer connected",
          ),
        ).resolves.toBe(0);
        expect(existsSync(running.pidFile)).toBe(false);
        const deadline = Date.now() + 5_000;
        while (isAlive(running.mcpPid) && Date.now() < deadline) {
          await new Promise((settle) => setTimeout(settle, 50));
        }
        expect(isAlive(running.mcpPid)).toBe(false);
      } finally {
        socket.destroy();
      }
    },
    90_000,
  );

  it("cleans up and rotates the authentication key when the same session restarts", async () => {
    const original = await startBridge();
    const originalSecret = JSON.parse(
      readFileSync(original.pidFile, "utf8"),
    ).secret;
    process.kill(original.mcpPid, "SIGKILL");
    await withTimeout(original.exited, 8_000, "original bridge exit");
    expect(existsSync(original.pidFile)).toBe(false);

    const restarted = await startBridge({}, original.home);
    const restartedSecret = JSON.parse(
      readFileSync(restarted.pidFile, "utf8"),
    ).secret;

    expect(typeof originalSecret).toBe("string");
    expect(typeof restartedSecret).toBe("string");
    expect(originalSecret === restartedSecret).toBe(false);
    expect(restarted.child.exitCode).toBeNull();
  }, 90_000);
});
