import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { home, secureWindowsPath } = vi.hoisted(() => ({
  home: { value: "" },
  secureWindowsPath: vi.fn(),
}));

vi.mock("node:os", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:os")>()),
  homedir: () => home.value,
}));
vi.mock("../src/windows-acl.js", () => ({
  secureWindowsPath,
  secureWindowsPaths: (paths: string[], mode: string) =>
    paths.forEach((path) => secureWindowsPath(path, mode)),
  verifyWindowsState: (directories: string[], file: string) => {
    directories.forEach((path) => secureWindowsPath(path, "verify-directory"));
    secureWindowsPath(file, "verify-file");
  },
}));

import {
  prepareSessionState,
  readBridgeState,
  writeBridgeState,
} from "../src/bridge-state.js";
import { resolveSessionPidFile } from "../src/sessions.js";
import { removePidFile } from "../src/bridge.js";

describe("protected bridge state", () => {
  beforeEach(() => {
    home.value = mkdtempSync(join(tmpdir(), "axi-auth-state-"));
    secureWindowsPath.mockReset();
    secureWindowsPath.mockImplementation((path: string, mode: string) => {
      if (mode === "prepare-directory") mkdirSync(path, { recursive: true });
    });
  });

  afterEach(() => rmSync(home.value, { recursive: true, force: true }));

  it.each(["default", "worker-1"])(
    "persists and cleans up authenticated state for %s",
    (session) => {
      const secret = "a".repeat(64);

      writeBridgeState(9224, secret, session);

      expect(readBridgeState(session)).toEqual({
        pid: process.pid,
        port: 9224,
        secret,
        bridge_transport:
          process.platform === "win32" ? "windows-user-v1" : "user-v1",
      });
      removePidFile(process.pid + 1, session);
      expect(readBridgeState(session)?.secret).toBe(secret);
      removePidFile(process.pid, session);
      expect(readBridgeState(session)).toBeNull();
    },
  );

  it("replaces stale state with a fresh secret without retaining temporary files", () => {
    writeBridgeState(9224, "a".repeat(64), "default");

    writeBridgeState(9224, "b".repeat(64), "default");

    expect(readBridgeState("default")?.secret).toBe("b".repeat(64));
    expect(readdirSync(dirname(resolveSessionPidFile("default")))).toEqual([
      "bridge.pid",
    ]);
  });

  it("treats missing or malformed state as nothing to remove", () => {
    expect(() => removePidFile(process.pid, "default")).not.toThrow();
    writeBridgeState(9224, "a".repeat(64), "default");
    writeFileSync(resolveSessionPidFile("default"), "not json");

    expect(() => removePidFile(process.pid, "default")).not.toThrow();
    expect(existsSync(resolveSessionPidFile("default"))).toBe(true);
  });

  it("rejects legacy state instead of enabling unauthenticated reuse", () => {
    prepareSessionState("default");
    writeFileSync(
      resolveSessionPidFile("default"),
      JSON.stringify({ pid: process.pid, port: 9224 }),
      { mode: 0o600 },
    );

    expect(() => readBridgeState("default")).toThrow(
      /authenticated bridge state/i,
    );
  });

  it.each(["../escape", "..", "a/b"])(
    "rejects unsafe explicit session %s before writing",
    (session) => {
      expect(() => writeBridgeState(9224, "a".repeat(64), session)).toThrow(
        /Invalid/,
      );
      expect(readdirSync(home.value)).toEqual([]);
    },
  );

  it.runIf(process.platform === "win32")(
    "creates no secret when directory ACL enforcement fails",
    () => {
      secureWindowsPath.mockImplementation(() => {
        throw new Error("ACL refused");
      });

      expect(() => writeBridgeState(9224, "a".repeat(64), "default")).toThrow(
        /ACL/,
      );
      expect(existsSync(resolveSessionPidFile("default"))).toBe(false);
      expect(readdirSync(home.value)).toEqual([]);
    },
  );

  it.runIf(process.platform === "win32")(
    "verifies the empty token file before the first secret write",
    () => {
      const secret = "a".repeat(64);
      let verifiedEmptyFile = false;
      secureWindowsPath.mockImplementation((path: string, mode: string) => {
        if (mode === "prepare-directory") mkdirSync(path, { recursive: true });
        if (mode === "verify-file") {
          expect(readFileSync(path).length).toBe(0);
          verifiedEmptyFile = true;
          throw new Error("ACL refused");
        }
      });

      expect(() => writeBridgeState(9224, secret, "worker-1")).toThrow(/ACL/);
      expect(verifiedEmptyFile).toBe(true);
      expect(readdirSync(dirname(resolveSessionPidFile("worker-1")))).toEqual(
        [],
      );
    },
  );

  it.runIf(process.platform === "win32")(
    "revalidates existing directory and token ACLs on every read",
    () => {
      writeBridgeState(9224, "a".repeat(64), "worker-1");
      secureWindowsPath.mockClear();

      readBridgeState("worker-1");
      readBridgeState("worker-1");

      expect(
        secureWindowsPath.mock.calls.filter(
          ([, mode]) => mode === "verify-file",
        ),
      ).toHaveLength(2);
      expect(
        secureWindowsPath.mock.calls.filter(
          ([, mode]) => mode === "verify-directory",
        ),
      ).toHaveLength(6);
    },
  );

  it.runIf(process.platform === "win32")(
    "leaves state untouched when cleanup cannot revalidate its token ACL",
    () => {
      writeBridgeState(9224, "a".repeat(64), "default");
      secureWindowsPath.mockImplementation((path: string, mode: string) => {
        if (mode === "verify-file") throw new Error("Unsafe Windows ACL");
      });

      removePidFile(process.pid, "default");

      expect(existsSync(resolveSessionPidFile("default"))).toBe(true);
    },
  );

  it.runIf(process.platform === "win32")(
    "refuses an existing token after its ACL becomes unsafe without exposing it",
    () => {
      const secret = "a".repeat(64);
      writeBridgeState(9224, secret, "default");
      secureWindowsPath.mockImplementation((path: string, mode: string) => {
        if (mode === "verify-file") throw new Error("Unsafe Windows ACL");
      });

      expect(() => readBridgeState("default")).toThrow(/ACL/);
      try {
        readBridgeState("default");
      } catch (error) {
        expect(String(error)).not.toContain(secret);
      }
    },
  );
});
