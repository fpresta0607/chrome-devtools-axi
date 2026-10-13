import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  secureWindowsPath,
  verifyWindowsBridgeProcess,
} from "../src/windows-acl.js";

describe.runIf(process.platform === "win32")("Windows ACL enforcement", () => {
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
      expect(() => secureWindowsPath(home, "verify-directory")).toThrow(/ACL/);
      expect(() => verifyWindowsBridgeProcess(process.pid)).toThrow(
        /ownership/,
      );
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 20_000);
});
