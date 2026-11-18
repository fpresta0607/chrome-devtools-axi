import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const workflowsDir = fileURLToPath(
  new URL("../.github/workflows", import.meta.url),
);

interface Step {
  uses?: unknown;
  run?: unknown;
}

interface Job {
  uses?: unknown;
  steps?: Step[];
}

function findReleaseSteps(name: string): string[] {
  const workflow = parse(readFileSync(join(workflowsDir, name), "utf8")) as {
    jobs?: Record<string, Job>;
  } | null;
  const violations: string[] = [];
  for (const [jobName, job] of Object.entries(workflow?.jobs ?? {})) {
    const uses = [job.uses, ...(job.steps ?? []).map((step) => step.uses)];
    if (uses.some((value) => String(value ?? "").includes("release-please"))) {
      violations.push(`${name} job ${jobName} runs release-please`);
    }
    const runs = (job.steps ?? []).map((step) => String(step.run ?? ""));
    if (runs.some((run) => /\bnpm\s+publish\b/.test(run))) {
      violations.push(`${name} job ${jobName} runs npm publish`);
    }
  }
  return violations;
}

describe("fork release workflows", () => {
  it("runs neither release-please nor npm publish in any workflow", () => {
    const workflows = readdirSync(workflowsDir).filter((name) =>
      /\.ya?ml$/.test(name),
    );

    const violations = workflows.flatMap(findReleaseSteps);

    expect(workflows.length).toBeGreaterThan(0);
    expect(violations).toEqual([]);
  });
});
