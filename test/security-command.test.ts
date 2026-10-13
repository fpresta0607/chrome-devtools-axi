import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { VERSION } from "../src/version.js";

describe("security capability command", () => {
  it("emits one JSON object without starting a browser or creating session state", () => {
    const home = mkdtempSync(join(tmpdir(), "axi-security-command-"));
    try {
      const result = spawnSync(
        process.execPath,
        [
          "--import",
          "tsx",
          resolve("bin/chrome-devtools-axi.ts"),
          "security",
          "--json",
        ],
        {
          encoding: "utf8",
          timeout: 10_000,
          windowsHide: true,
          env: {
            ...process.env,
            HOME: home,
            USERPROFILE: home,
            CHROME_DEVTOOLS_AXI_SESSION: "security-offline",
            CHROME_DEVTOOLS_AXI_MCP_PATH: join(home, "must-not-be-started.js"),
            CHROME_DEVTOOLS_AXI_MCP_SERVER_URL: "",
          },
        },
      );

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toEqual({
        version: VERSION,
        platform: process.platform,
        bridge_transport:
          process.platform === "win32" ? "windows-user-v1" : "user-v1",
      });
      expect(readdirSync(home)).toEqual([]);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
