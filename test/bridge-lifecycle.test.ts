import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

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
): Promise<RunningBridge> {
  const home = mkdtempSync(join(tmpdir(), "axi-bridge-lifecycle-"));
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
    15_000,
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
  it("stays up while idle when no idle timeout is configured", async () => {
    const running = await startBridge();

    await new Promise((settle) => setTimeout(settle, 2_000));

    expect(running.child.exitCode).toBeNull();
    expect(isAlive(running.mcpPid)).toBe(true);
    expect(existsSync(running.pidFile)).toBe(true);
  }, 20_000);

  it("shuts down after CHROME_DEVTOOLS_AXI_IDLE_TIMEOUT_MS with no requests", async () => {
    const running = await startBridge({
      CHROME_DEVTOOLS_AXI_IDLE_TIMEOUT_MS: "1000",
    });

    await expect(
      withTimeout(running.exited, 8_000, "idle bridge exit"),
    ).resolves.toBe(0);
    expect(existsSync(running.pidFile)).toBe(false);
    await withTimeout(
      (async () => {
        while (isAlive(running.mcpPid)) {
          await new Promise((settle) => setTimeout(settle, 50));
        }
      })(),
      5_000,
      "MCP server exit after idle shutdown",
    );
  }, 30_000);

  it("shuts down when its MCP server ends", async () => {
    const running = await startBridge();

    process.kill(running.mcpPid, "SIGKILL");

    await expect(
      withTimeout(running.exited, 8_000, "bridge exit after MCP server died"),
    ).resolves.toBe(0);
    expect(existsSync(running.pidFile)).toBe(false);
  }, 30_000);
});
