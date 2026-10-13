import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
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
vi.mock("node:fs", async (importOriginal) => {
  const filesystem = await importOriginal<typeof import("node:fs")>();
  return {
    ...filesystem,
    lstatSync: vi.fn(filesystem.lstatSync),
    mkdirSync: vi.fn(filesystem.mkdirSync),
    readFileSync: vi.fn(filesystem.readFileSync),
    unlinkSync: vi.fn(filesystem.unlinkSync),
  };
});
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
  readBridgeStateForStop,
  removeBridgeState,
  writeBridgeState,
} from "../src/bridge-state.js";
import {
  resolveSessionPidFile,
  resolveSessionStateDir,
} from "../src/sessions.js";
import { removePidFile } from "../src/bridge.js";

describe("protected bridge state", () => {
  beforeEach(() => {
    home.value = mkdtempSync(join(tmpdir(), "axi-auth-state-"));
    secureWindowsPath.mockReset();
    secureWindowsPath.mockImplementation((path: string, mode: string) => {
      if (mode === "prepare-directory") mkdirSync(path, { recursive: true });
    });
  });

  afterEach(() => {
    vi.mocked(lstatSync).mockRestore();
    vi.mocked(mkdirSync).mockRestore();
    vi.mocked(readFileSync).mockRestore();
    vi.mocked(unlinkSync).mockRestore();
    rmSync(home.value, { recursive: true, force: true });
  });

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

  describe.each(["default", "worker-1"])(
    "concurrent cleanup for %s",
    (session) => {
      it.each([
        ["read", "lstat"],
        ["read", "read"],
        ["stop", "lstat"],
        ["stop", "read"],
        ["remove", "lstat"],
        ["remove", "read"],
        ["remove", "unlink"],
      ])(
        "handles %s failing at %s only when the record disappeared",
        async (action, boundary) => {
          const filesystem =
            await vi.importActual<typeof import("node:fs")>("node:fs");
          const stateFile = resolveSessionPidFile(session);
          const failure = new Error("State operation failed");
          for (const should_disappear of [false, true]) {
            writeBridgeState(9224, "a".repeat(64), session);
            const state = filesystem.readFileSync(stateFile, "utf8");
            let has_failed = false;
            const fail = () => {
              has_failed = true;
              if (should_disappear) filesystem.unlinkSync(stateFile);
              throw failure;
            };
            if (boundary === "lstat") {
              vi.mocked(lstatSync).mockImplementation((path, options) => {
                if (path === stateFile && !has_failed) fail();
                return filesystem.lstatSync(path, options);
              });
            } else if (boundary === "read") {
              vi.mocked(readFileSync).mockImplementation((path, options) => {
                if (path === stateFile && !has_failed) fail();
                return filesystem.readFileSync(path, options);
              });
            } else {
              vi.mocked(unlinkSync).mockImplementation((path) => {
                if (path === stateFile && !has_failed) fail();
                return filesystem.unlinkSync(path);
              });
            }
            const operation = () =>
              action === "read"
                ? readBridgeState(session)
                : action === "stop"
                  ? readBridgeStateForStop(session, true)
                  : removeBridgeState(process.pid, session);

            if (should_disappear) {
              expect(operation()).toBe(action === "remove" ? undefined : null);
              expect(existsSync(stateFile)).toBe(false);
            } else {
              expect(operation).toThrow();
              expect(filesystem.readFileSync(stateFile, "utf8")).toBe(state);
            }
            expect(has_failed).toBe(true);
            vi.mocked(lstatSync).mockRestore();
            vi.mocked(readFileSync).mockRestore();
            vi.mocked(unlinkSync).mockRestore();
          }
        },
      );

      it("rejects malformed records during reads, stop and removal", () => {
        writeBridgeState(9224, "a".repeat(64), session);
        const stateFile = resolveSessionPidFile(session);
        writeFileSync(stateFile, "not json");

        expect(() => readBridgeState(session)).toThrow(/Invalid/);
        expect(() => readBridgeStateForStop(session, true)).toThrow(/Invalid/);
        expect(() => removeBridgeState(process.pid, session)).toThrow(
          /Invalid/,
        );
        expect(readFileSync(stateFile, "utf8")).toBe("not json");
      });

      it("fails closed when the disappearance recheck cannot access the record", () => {
        writeBridgeState(9224, "a".repeat(64), session);
        const stateFile = resolveSessionPidFile(session);
        vi.mocked(readFileSync).mockImplementationOnce(() => {
          vi.mocked(lstatSync).mockImplementationOnce(() => {
            throw Object.assign(new Error("Access denied"), { code: "EACCES" });
          });
          throw new Error("Read failed");
        });

        expect(() => readBridgeState(session)).toThrow();
        expect(existsSync(stateFile)).toBe(true);
      });

      it.runIf(process.platform === "win32")(
        "treats disappearance during stop migration as missing state",
        () => {
          writeBridgeState(9224, "a".repeat(64), session);
          const stateFile = resolveSessionPidFile(session);
          secureWindowsPath.mockImplementationOnce(() => {
            unlinkSync(stateFile);
            throw new Error("Windows bridge ACL verification failed");
          });

          expect(readBridgeStateForStop(session, true)).toBeNull();
          expect(existsSync(stateFile)).toBe(false);
        },
      );
    },
  );

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

  it.each(["default", "worker-1"])(
    "rejects multiply linked state during stop migration for %s",
    (session) => {
      writeBridgeState(9224, "a".repeat(64), session);
      const stateFile = resolveSessionPidFile(session);
      linkSync(stateFile, join(home.value, "linked-state"));

      expect(() => readBridgeStateForStop(session, true)).toThrow(/Unsafe/);
      expect(existsSync(stateFile)).toBe(true);
      expect(lstatSync(stateFile).nlink).toBe(2);
    },
  );

  describe.runIf(process.platform !== "win32")("POSIX state migration", () => {
    it.each([false, true])(
      "handles disappearance during directory verification with migration %s",
      async (should_migrate) => {
        const filesystem =
          await vi.importActual<typeof import("node:fs")>("node:fs");
        writeBridgeState(9224, "a".repeat(64), "worker-1");
        const stateFile = resolveSessionPidFile("worker-1");
        const root = resolveSessionStateDir("default");
        vi.mocked(lstatSync).mockImplementation((path, options) => {
          if (path === root) {
            unlinkSync(stateFile);
            throw new Error("Directory verification failed");
          }
          return filesystem.lstatSync(path, options);
        });

        expect(readBridgeStateForStop("worker-1", should_migrate)).toBeNull();
        expect(existsSync(stateFile)).toBe(false);
      },
    );

    it("rejects a dangling state symlink as unsafe rather than absent", () => {
      prepareSessionState("default");
      const stateFile = resolveSessionPidFile("default");
      symlinkSync(join(home.value, "missing-state"), stateFile);

      expect(() => readBridgeState("default")).toThrow(/Unsafe/);
      expect(() => readBridgeStateForStop("default", true)).toThrow(/Unsafe/);
      expect(lstatSync(stateFile).isSymbolicLink()).toBe(true);
    });

    it.each(["default", "worker-1"])(
      "repairs legacy directories on a fresh start for %s",
      (session) => {
        const root = resolveSessionStateDir("default");
        const directories =
          session === "default"
            ? [root]
            : [root, join(root, "sessions"), resolveSessionStateDir(session)];
        for (const directory of directories) {
          mkdirSync(directory, { mode: 0o755 });
          chmodSync(directory, 0o755);
        }

        expect(readBridgeState(session)).toBeNull();
        writeBridgeState(9224, "a".repeat(64), session);

        expect(readBridgeState(session)?.secret).toBe("a".repeat(64));
        for (const directory of directories) {
          expect(lstatSync(directory).mode & 0o777).toBe(0o700);
        }
      },
    );

    it.each(["default", "worker-1"])(
      "tightens owned legacy directories and file before stop reads %s",
      (session) => {
        writeBridgeState(9224, "a".repeat(64), session);
        const root = resolveSessionStateDir("default");
        const directories =
          session === "default"
            ? [root]
            : [root, join(root, "sessions"), resolveSessionStateDir(session)];
        for (const directory of directories) chmodSync(directory, 0o755);
        const stateFile = resolveSessionPidFile(session);
        chmodSync(stateFile, 0o644);

        expect(() => readBridgeState(session)).toThrow(/Run stop, then start/);
        expect(readBridgeStateForStop(session, true)).toEqual({
          pid: process.pid,
          port: 9224,
        });

        for (const directory of directories) {
          expect(lstatSync(directory).mode & 0o777).toBe(0o700);
        }
        expect(lstatSync(stateFile).mode & 0o777).toBe(0o600);
        expect(readBridgeState(session)?.secret).toBe("a".repeat(64));
      },
    );

    it("does not migrate a symlinked state file", () => {
      prepareSessionState("default");
      const target = join(home.value, "other-state");
      writeFileSync(target, JSON.stringify({ pid: process.pid, port: 9224 }));
      chmodSync(target, 0o644);
      symlinkSync(target, resolveSessionPidFile("default"));

      expect(() => readBridgeStateForStop("default", true)).toThrow(/Unsafe/);
      expect(lstatSync(target).mode & 0o777).toBe(0o644);
    });

    it.each([0, 1, 2])(
      "tolerates concurrent creation of state directory %i and enforces permissions",
      async (index) => {
        const filesystem =
          await vi.importActual<typeof import("node:fs")>("node:fs");
        const root = resolveSessionStateDir("default");
        const directories = [
          root,
          join(root, "sessions"),
          resolveSessionStateDir("worker-1"),
        ];
        let has_raced = false;
        vi.mocked(mkdirSync).mockImplementation((path, options) => {
          if (path === directories[index]) {
            has_raced = true;
            filesystem.mkdirSync(path, { mode: 0o755 });
            chmodSync(path, 0o755);
            throw Object.assign(new Error("Already exists"), {
              code: "EEXIST",
            });
          }
          return filesystem.mkdirSync(path, options);
        });

        writeBridgeState(9224, "a".repeat(64), "worker-1");

        expect(has_raced).toBe(true);
        expect(readBridgeState("worker-1")?.secret).toBe("a".repeat(64));
        for (const directory of directories) {
          expect(lstatSync(directory).mode & 0o777).toBe(0o700);
        }
      },
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
