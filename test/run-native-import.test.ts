import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

/**
 * `runScript` imports the script it writes to a temp file. Vitest resolves a
 * bare Windows path such as `D:\...\script.mjs` on its own, so only Node's
 * own ESM loader shows whether that import works: this spawns the built
 * module under plain `node`, the way the installed CLI runs it.
 */

const ROOT = resolve(import.meta.dirname, "..");
const RUN_MODULE = join(ROOT, "dist", "src", "run.js");

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("runScript under Node's own ESM loader", () => {
  it("imports the script it wrote from an absolute temp path", () => {
    expect(existsSync(RUN_MODULE), "build first: pnpm run build").toBe(true);
    const scriptTmp = mkdtempSync(join(tmpdir(), "cda-run-native-"));
    dirs.push(scriptTmp);
    if (process.platform === "win32") {
      expect(scriptTmp).toMatch(/^[A-Za-z]:\\/);
    }
    const driver = `
const { runScript } = await import(${JSON.stringify(pathToFileURL(RUN_MODULE).href)});
const result = await runScript('console.log("ran from " + typeof page);', async () => "");
process.stdout.write(result.stdout);
`;

    const result = spawnSync(
      process.execPath,
      ["--input-type=module", "-e", driver],
      {
        encoding: "utf8",
        windowsHide: true,
        env: {
          ...process.env,
          TEMP: scriptTmp,
          TMP: scriptTmp,
          TMPDIR: scriptTmp,
        },
      },
    );

    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("ran from object\n");
    expect(readdirSync(scriptTmp)).toEqual([]);
  });
});
