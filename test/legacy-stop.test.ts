import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { prepareSessionState } from "../src/bridge-state.js";
import { ensureBridge, stopBridge } from "../src/client.js";
import { resolveSessionPidFile } from "../src/sessions.js";

describe("legacy bridge migration", () => {
  it("requires explicit stop and verifies the owner's legacy process before termination", async () => {
    const savedEnvironment = {
      HOME: process.env.HOME,
      USERPROFILE: process.env.USERPROFILE,
      CHROME_DEVTOOLS_AXI_SESSION: process.env.CHROME_DEVTOOLS_AXI_SESSION,
    };
    const home = mkdtempSync(join(tmpdir(), "axi-legacy-stop-"));
    const child = spawn(
      process.execPath,
      [resolve("test/fixtures/legacy/chrome-devtools-axi-bridge.js")],
      { stdio: "ignore", windowsHide: true },
    );
    const exited = once(child, "exit");
    try {
      await once(child, "spawn");
      if (!child.pid) throw new Error("Legacy fixture did not start");
      process.env.HOME = home;
      process.env.USERPROFILE = home;
      process.env.CHROME_DEVTOOLS_AXI_SESSION = "legacy-test";
      prepareSessionState();
      const stateFile = resolveSessionPidFile();
      writeFileSync(stateFile, JSON.stringify({ pid: child.pid, port: 9224 }), {
        mode: 0o600,
      });
      const start = vi.fn();

      await expect(ensureBridge(start)).rejects.toThrow(
        /authenticated bridge state/,
      );
      expect(start).not.toHaveBeenCalled();
      expect(child.exitCode).toBeNull();
      await expect(stopBridge()).resolves.toBe(true);

      await exited;
      expect(existsSync(stateFile)).toBe(false);
    } finally {
      if (child.exitCode === null) child.kill("SIGKILL");
      await exited;
      for (const [key, value] of Object.entries(savedEnvironment)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      rmSync(home, { recursive: true, force: true });
    }
  }, 30_000);
});
