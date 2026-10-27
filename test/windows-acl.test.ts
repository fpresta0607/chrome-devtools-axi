import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  isWindowsBridgeProcess,
  secureWindowsPath,
  secureWindowsPaths,
  verifyWindowsState,
} from "../src/windows-acl.js";

function grant(path: string, sid: string): void {
  execFileSync("icacls.exe", [path, "/grant", `*${sid}:(R)`], {
    windowsHide: true,
    stdio: "ignore",
  });
}

describe.runIf(process.platform === "win32")("Windows ACL enforcement", () => {
  // These tests block on PowerShell synchronously, and Vitest moves from one
  // synchronous test to the next without turning the event loop. Its worker's
  // task update replies then wait behind all of them and time out after 60s.
  afterEach(() => new Promise((resolve) => setImmediate(resolve)));

  it.each(["PSModulePath", "PSMODULEPATH"])(
    "verifies ACLs and processes despite an incompatible inherited %s",
    (variable) => {
      const home = mkdtempSync(join(tmpdir(), "axi-windows-acl-"));
      const modules = join(home, "modules");
      const module = join(modules, "Microsoft.PowerShell.Utility");
      const directory = join(home, "protected-state");
      const file = join(directory, "bridge.pid");
      try {
        mkdirSync(module, { recursive: true });
        writeFileSync(
          join(module, "Microsoft.PowerShell.Utility.psd1"),
          "@{ ModuleVersion = '7.0.0'; PowerShellVersion = '7.0'; CmdletsToExport = @('ConvertFrom-Json') }",
        );
        vi.stubEnv(variable, modules);

        secureWindowsPaths([directory], "prepare-directory");
        writeFileSync(file, "legacy state");
        grant(file, "S-1-1-0");
        expect(() => verifyWindowsState([directory], file)).toThrow(/ACL/);
        secureWindowsPaths([directory], "prepare-directory", file);

        expect(() =>
          secureWindowsPath(directory, "verify-directory"),
        ).not.toThrow();
        expect(() => secureWindowsPath(file, "verify-file")).not.toThrow();
        expect(() => verifyWindowsState([directory], file)).not.toThrow();
        expect(readFileSync(file, "utf8")).toBe("legacy state");
        expect(isWindowsBridgeProcess(process.pid, 9224)).toBe(false);
        expect(process.env[variable]).toBe(modules);
      } finally {
        vi.unstubAllEnvs();
        rmSync(home, { recursive: true, force: true });
      }
    },
    30_000,
  );

  it("migrates owned inherited state and removes explicit grants before reading", () => {
    const home = mkdtempSync(join(tmpdir(), "axi-windows-acl-"));
    const directory = join(home, "legacy-state");
    const file = join(directory, "bridge.pid");
    try {
      mkdirSync(directory);
      writeFileSync(file, JSON.stringify({ pid: process.pid, port: 9224 }));
      grant(directory, "S-1-1-0");
      grant(file, "S-1-1-0");
      expect(() => verifyWindowsState([directory], file)).toThrow(/ACL/);

      secureWindowsPaths([directory], "prepare-directory", file);

      expect(() => verifyWindowsState([directory], file)).not.toThrow();
      expect(JSON.parse(readFileSync(file, "utf8"))).toEqual({
        pid: process.pid,
        port: 9224,
      });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 20_000);

  it("migrates owned state whose ACL grants its owner only Modify", () => {
    const systemRoot = process.env.SystemRoot;
    if (!systemRoot) throw new Error("Missing Windows system directory");
    const home = mkdtempSync(join(tmpdir(), "axi-windows-acl-"));
    const directory = join(home, "legacy-state");
    const file = join(directory, "bridge.pid");
    const user = execFileSync(
      join(systemRoot, "System32", "whoami.exe"),
      ["/user", "/fo", "csv", "/nh"],
      { encoding: "utf8", windowsHide: true },
    )
      .trim()
      .split(",")
      .at(-1)
      ?.replaceAll('"', "");
    try {
      mkdirSync(directory);
      // Modify carries no WRITE_OWNER, as under a drive root where only
      // Authenticated Users grants the owner its access.
      execFileSync(
        "icacls.exe",
        [directory, "/inheritance:r", "/grant", `*${user}:(OI)(CI)(M)`],
        { windowsHide: true, stdio: "ignore" },
      );
      writeFileSync(file, JSON.stringify({ pid: process.pid, port: 9224 }));
      grant(file, "S-1-1-0");
      expect(() => verifyWindowsState([directory], file)).toThrow(/ACL/);

      secureWindowsPaths([directory], "prepare-directory", file);

      expect(() => verifyWindowsState([directory], file)).not.toThrow();
      expect(JSON.parse(readFileSync(file, "utf8"))).toEqual({
        pid: process.pid,
        port: 9224,
      });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 20_000);

  it("rejects a legacy directory junction before changing its target ACL", () => {
    const home = mkdtempSync(join(tmpdir(), "axi-windows-acl-"));
    const target = join(home, "target");
    const directory = join(home, "legacy-state");
    try {
      mkdirSync(target);
      grant(target, "S-1-1-0");
      writeFileSync(join(target, "bridge.pid"), "{}");
      symlinkSync(target, directory, "junction");

      expect(() =>
        secureWindowsPaths(
          [directory],
          "prepare-directory",
          join(directory, "bridge.pid"),
        ),
      ).toThrow(/ACL/);
      expect(() => secureWindowsPath(target, "verify-directory")).toThrow(
        /ACL/,
      );
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 20_000);

  it("creates and revalidates owner-protected directories and inherited token ACLs", () => {
    const home = mkdtempSync(join(tmpdir(), "axi-windows-acl-"));
    const directory = join(home, "protected-state");
    try {
      secureWindowsPath(directory, "prepare-directory");
      const file = join(directory, "empty-token");
      writeFileSync(file, "", { flag: "wx" });

      expect(() =>
        secureWindowsPath(directory, "verify-directory"),
      ).not.toThrow();
      expect(() => secureWindowsPath(file, "verify-file")).not.toThrow();
      expect(() => verifyWindowsState([directory], file)).not.toThrow();
      expect(() => verifyWindowsState([home], file)).toThrow(/ACL/);
      expect(() => verifyWindowsState([directory], directory)).toThrow(/ACL/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 20_000);

  it.each([
    ["Everyone", "S-1-1-0"],
    ["Authenticated Users", "S-1-5-11"],
    ["Users", "S-1-5-32-545"],
    ["INTERACTIVE", "S-1-5-4"],
  ])(
    "rejects state readable by %s",
    (_name, sid) => {
      const home = mkdtempSync(join(tmpdir(), "axi-windows-acl-"));
      const directory = join(home, "protected-state");
      const file = join(directory, "token");
      try {
        secureWindowsPath(directory, "prepare-directory");
        writeFileSync(file, "", { flag: "wx" });
        expect(() => verifyWindowsState([directory], file)).not.toThrow();

        grant(file, sid);
        expect(() => verifyWindowsState([directory], file)).toThrow(/ACL/);
        expect(() =>
          secureWindowsPath(directory, "verify-directory"),
        ).not.toThrow();

        grant(directory, sid);
        expect(() => secureWindowsPath(directory, "verify-directory")).toThrow(
          /ACL/,
        );
      } finally {
        rmSync(home, { recursive: true, force: true });
      }
    },
    30_000,
  );

  it("protects a profile path with non-ASCII characters at its exact location", () => {
    const home = mkdtempSync(join(tmpdir(), "axi-windows-acl-"));
    const directory = join(home, "état-Grüße-用户");
    try {
      secureWindowsPath(directory, "prepare-directory");

      expect(existsSync(directory)).toBe(true);
      expect(() =>
        secureWindowsPath(directory, "verify-directory"),
      ).not.toThrow();
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 20_000);

  it("identifies only this user's bridge listening on its recorded port", async () => {
    const bridge = spawn(
      process.execPath,
      [resolve("test/fixtures/legacy/chrome-devtools-axi-bridge.js")],
      { stdio: ["ignore", "pipe", "ignore"], windowsHide: true },
    );
    const exited = once(bridge, "exit");
    try {
      const [line] = await once(bridge.stdout, "data");
      const port = Number(String(line).trim());
      if (!bridge.pid) throw new Error("Bridge fixture did not start");

      expect(isWindowsBridgeProcess(bridge.pid, port)).toBe(true);
      expect(
        isWindowsBridgeProcess(bridge.pid, port === 1 ? 2 : port - 1),
      ).toBe(false);
      expect(isWindowsBridgeProcess(process.pid, port)).toBe(false);
    } finally {
      bridge.kill();
      await exited;
    }
  }, 30_000);
});
