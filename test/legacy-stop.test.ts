import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { readBridgeState, writeBridgeState } from "../src/bridge-state.js";
import { ensureBridge, stopBridge } from "../src/client.js";
import {
  resolveSessionPidFile,
  resolveSessionStateDir,
} from "../src/sessions.js";

describe("legacy bridge migration", () => {
  it.each(["default", "legacy-test"])(
    "migrates legacy permissions through explicit stop for %s",
    async (session) => {
      const savedEnvironment = {
        HOME: process.env.HOME,
        USERPROFILE: process.env.USERPROFILE,
        CHROME_DEVTOOLS_AXI_SESSION: process.env.CHROME_DEVTOOLS_AXI_SESSION,
      };
      const home = mkdtempSync(join(tmpdir(), "axi-legacy-stop-"));
      const child = spawn(
        process.execPath,
        [resolve("test/fixtures/legacy/chrome-devtools-axi-bridge.js")],
        { stdio: ["ignore", "pipe", "ignore"], windowsHide: true },
      );
      const exited = once(child, "exit");
      try {
        const [line] = await once(child.stdout, "data");
        const port = Number(String(line).trim());
        if (!child.pid) throw new Error("Legacy fixture did not start");
        process.env.HOME = home;
        process.env.USERPROFILE = home;
        process.env.CHROME_DEVTOOLS_AXI_SESSION = session;
        const root = resolveSessionStateDir("default");
        const directories =
          session === "default"
            ? [root]
            : [root, join(root, "sessions"), resolveSessionStateDir(session)];
        for (const directory of directories) {
          mkdirSync(directory, { mode: 0o755 });
          if (process.platform !== "win32") chmodSync(directory, 0o755);
        }
        const stateFile = resolveSessionPidFile();
        writeFileSync(stateFile, JSON.stringify({ pid: child.pid, port }), {
          mode: 0o644,
        });
        if (process.platform !== "win32") chmodSync(stateFile, 0o644);
        const start = vi.fn();

        await expect(ensureBridge(start)).rejects.toThrow(
          /Run stop, then start/,
        );
        expect(start).not.toHaveBeenCalled();
        expect(child.exitCode).toBeNull();
        await expect(stopBridge()).resolves.toBe(true);

        await exited;
        expect(existsSync(stateFile)).toBe(false);
        writeBridgeState(port, "a".repeat(64));
        expect(readBridgeState()?.secret).toBe("a".repeat(64));
      } finally {
        if (child.exitCode === null) child.kill("SIGKILL");
        await exited;
        for (const [key, value] of Object.entries(savedEnvironment)) {
          if (value === undefined) delete process.env[key];
          else process.env[key] = value;
        }
        rmSync(home, { recursive: true, force: true });
      }
    },
    30_000,
  );
});
