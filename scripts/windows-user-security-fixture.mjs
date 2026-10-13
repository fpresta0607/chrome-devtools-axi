import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import {
  existsSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const [mode, repository, proofRoot, expectedSid] = process.argv.slice(2);
const OWNER_HOME = join(proofRoot, "owner-home");
const READY_FILE = join(proofRoot, "owner-output", "ready.json");
const STOP_FILE = join(proofRoot, "finish");
const PAGE_URL = "https://windows-user-proof.invalid/";
const CHILDREN_FILE = join(proofRoot, "owner-output", "children.json");
const childPids = [];
const bridgeSecrets = [];
const ROUTES = [
  ["GET", "/health", ""],
  ["GET", "/health?deep=1", ""],
  ["GET", "/tools", ""],
  ["POST", "/call", JSON.stringify({ name: "list_pages", args: {} })],
];

assert.equal(process.platform, "win32", "This proof requires Windows");
assert.equal(process.env.GITHUB_ACTIONS, "true", "GitHub Actions required");
assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
assert.equal(process.env.GITHUB_REPOSITORY, "fpresta0607/chrome-devtools-axi");
assert.ok(["owner", "alternate"].includes(mode));
const identity = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], {
  encoding: "utf8",
  windowsHide: true,
  timeout: 5_000,
});
assert.ok(identity.includes(`"${expectedSid}"`), "Unexpected Windows identity");
const groups = execFileSync("whoami.exe", ["/groups", "/fo", "csv", "/nh"], {
  encoding: "utf8",
  windowsHide: true,
  timeout: 5_000,
});
assert.ok(!groups.includes('"S-1-5-32-544"'), "Proof user must be non-admin");
for (const name of Object.keys(process.env)) {
  if (name.startsWith("CHROME_DEVTOOLS_AXI_")) delete process.env[name];
}
process.env.CHROME_DEVTOOLS_AXI_MCP_PATH = join(
  proofRoot,
  "must-not-launch-mcp.js",
);
const { createBridgeAuth, createAuthHeaders } = await import(
  pathToFileURL(join(repository, "dist", "src", "bridge-auth.js")).href
);

async function request(port, method, path, body, headers = {}) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {
      ...headers,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body } : {}),
    signal: AbortSignal.timeout(5_000),
  });
  return { status: response.status, text: await response.text() };
}

function writeJson(file, value) {
  writeFileSync(`${file}.tmp`, JSON.stringify(value));
  renameSync(`${file}.tmp`, file);
}

function runCli(args, environment = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [join(repository, "dist", "bin", "chrome-devtools-axi.js"), ...args],
      {
        cwd: OWNER_HOME,
        env: { ...process.env, ...environment },
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    child.once("spawn", () => {
      childPids.push(child.pid);
      writeJson(CHILDREN_FILE, childPids);
      console.log(`owner CLI pid=${child.pid}`);
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill(), 15_000);
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code !== 0)
        reject(
          new Error(`Owner CLI failed with exit ${code}: ${stdout}${stderr}`),
        );
      else resolve({ stdout, stderr });
    });
  });
}

async function proveOwner() {
  process.env.USERPROFILE = OWNER_HOME;
  assert.equal(homedir(), OWNER_HOME);
  const { createBridgeServer } = await import(
    pathToFileURL(join(repository, "dist", "src", "bridge.js")).href
  );
  const { prepareSessionState, writeBridgeState, readBridgeState } =
    await import(
      pathToFileURL(join(repository, "dist", "src", "bridge-state.js")).href
    );
  const { resolveSessionPidFile } = await import(
    pathToFileURL(join(repository, "dist", "src", "sessions.js")).href
  );
  const servers = [];
  const sessions = [];
  let toolCalls = 0;
  const client = {
    async listTools() {
      toolCalls++;
      return { tools: [{ name: "list_pages", description: "proof fixture" }] };
    },
    async callTool({ name }) {
      toolCalls++;
      assert.equal(name, "list_pages");
      return { content: [{ type: "text", text: `0: ${PAGE_URL} [selected]` }] };
    },
    async close() {},
  };
  try {
    const capability = await runCli(["security", "--json"]);
    const security = JSON.parse(capability.stdout);
    assert.equal(security.platform, "win32");
    assert.equal(security.bridge_transport, "windows-user-v1");
    assert.equal(typeof security.version, "string");
    for (const session of ["default", "cross-user-proof"]) {
      assert.ok(
        !existsSync(resolveSessionPidFile(session)),
        "security started a bridge",
      );
    }
    for (const session of ["default", "cross-user-proof"]) {
      process.env.CHROME_DEVTOOLS_AXI_SESSION = session;
      await prepareSessionState(session);
      const secret = randomBytes(32).toString("hex");
      bridgeSecrets.push(secret);
      const server = createBridgeServer(
        client,
        session,
        undefined,
        createBridgeAuth(secret),
      );
      servers.push(server);
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      const { port } = server.address();
      await writeBridgeState(port, secret, session);
      const state = await readBridgeState(session);
      assert.ok(state.secret === secret, "Persisted state secret differs");
      assert.equal(state.port, port);
      const secretFile = resolveSessionPidFile(session);
      assert.ok(
        JSON.parse(readFileSync(secretFile, "utf8")).secret === secret,
        "Secret file differs from bridge state",
      );
      for (const [method, path, body] of ROUTES) {
        const response = await request(
          port,
          method,
          path,
          body,
          createAuthHeaders(secret, method, path, body),
        );
        assert.equal(response.status, 200, `Owner ${session} ${path}`);
        assert.ok(!response.text.includes(secret), "Response leaked secret");
      }
      const output = await runCli(["pages"], {
        CHROME_DEVTOOLS_AXI_SESSION: session,
        CHROME_DEVTOOLS_AXI_PORT: String(port),
      });
      assert.ok(
        output.stdout.includes(PAGE_URL),
        "CLI did not return stub page",
      );
      assert.equal(
        (await readBridgeState(session)).pid,
        process.pid,
        "CLI replaced fixture bridge",
      );
      for (const value of bridgeSecrets) {
        assert.ok(!`${output.stdout}${output.stderr}`.includes(value));
      }
      sessions.push({ session, port, secretFile });
    }
    const baselineCalls = toolCalls;
    writeJson(READY_FILE, { pid: process.pid, sid: expectedSid, sessions });
    const deadline = Date.now() + 120_000;
    while (!existsSync(STOP_FILE) && Date.now() < deadline) await delay(200);
    assert.ok(existsSync(STOP_FILE), "Timed out waiting for alternate user");
    assert.equal(toolCalls, baselineCalls, "Unauthorized request reached MCP");
    console.log(
      "Owner CLI and all authenticated routes passed for both sessions",
    );
  } finally {
    for (const server of servers) {
      server.closeAllConnections();
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
    rmSync(join(OWNER_HOME, ".chrome-devtools-axi"), {
      recursive: true,
      force: true,
    });
  }
}

async function proveAlternate() {
  const ready = JSON.parse(readFileSync(READY_FILE, "utf8"));
  assert.notEqual(ready.sid, expectedSid, "The users must have different SIDs");
  assert.equal(
    readFileSync(join(OWNER_HOME, "readable-control"), "utf8"),
    "control",
  );
  const observations = [];
  for (const { session, port, secretFile } of ready.sessions) {
    assert.throws(
      () => readFileSync(secretFile, "utf8"),
      (error) => error.code === "EACCES" || error.code === "EPERM",
      `Alternate user must be denied reading ${session} secret`,
    );
    for (const [method, path, body] of ROUTES) {
      for (const credential of ["absent", "wrong"]) {
        const headers =
          credential === "wrong"
            ? createAuthHeaders(
                randomBytes(32).toString("hex"),
                method,
                path,
                body,
              )
            : {};
        const response = await request(port, method, path, body, headers);
        assert.equal(response.status, 401, `${session} ${path} ${credential}`);
        assert.ok(!response.text.includes(PAGE_URL));
        assert.ok(!response.text.includes("proof fixture"));
        const payload = JSON.parse(response.text);
        for (const field of [
          "session",
          "tools",
          "result",
          "bridge_transport",
          "version",
        ]) {
          assert.ok(
            !Object.hasOwn(payload, field),
            `Unauthorized response leaked ${field}`,
          );
        }
        observations.push({ session, method, path, credential, status: 401 });
      }
    }
  }
  writeJson(join(proofRoot, "alternate-output", "result.json"), {
    sid: expectedSid,
    secretReadsDenied: 2,
    observations,
  });
  console.log(
    "Alternate non-admin user denied both secrets and all 16 HTTP requests",
  );
}

try {
  await (mode === "owner" ? proveOwner() : proveAlternate());
} catch (error) {
  let diagnostic = error instanceof Error ? error.stack : String(error);
  for (const secret of bridgeSecrets)
    diagnostic = diagnostic.replaceAll(secret, "[redacted]");
  console.error(diagnostic);
  process.exitCode = 1;
}
