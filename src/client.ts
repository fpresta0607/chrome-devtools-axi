/**
 * HTTP client for the chrome-devtools-axi bridge + bridge lifecycle management.
 */

import { isUtf8 } from "node:buffer";
import { execFileSync, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { request, type IncomingMessage } from "node:http";
import { dirname, join } from "node:path";
import { AxiError } from "axi-sdk-js";
import {
  BRIDGE_PORT_IN_USE_EXIT_CODE,
  PAGE_IDENTITY_CHANGED_ERROR,
  resolveBridgeScript,
} from "./bridge-script.js";
import {
  createAuthHeaders,
  RESPONSE_PROOF_HEADER,
  verifyResponse,
} from "./bridge-auth.js";
import {
  readBridgeState,
  readBridgeStateForStop,
  removeBridgeState,
  type BridgeState,
} from "./bridge-state.js";
import { isWindowsBridgeProcess } from "./windows-acl.js";
import { needsPageId } from "./pages.js";
import {
  clearSelectedPageId,
  getSelectedPageId,
  rememberToolRouting,
} from "./selected-page.js";
import { resolveSessionName, resolveSessionPort } from "./sessions.js";

const DEFAULT_BRIDGE_TIMEOUT_MS = 30_000;
const MIN_BRIDGE_TIMEOUT_MS = 1_000;
const BRIDGE_COLLISION_GRACE_MS = 5_000;
const HEALTH_TIMEOUT_MS = 2_000;
const DEEP_HEALTH_TIMEOUT_MS = 5_000;
const MAX_BRIDGE_RESPONSE_BYTES = 64 * 1024 * 1024;

/**
 * Resolve the bridge readiness deadline in milliseconds.
 *
 * Honors `CHROME_DEVTOOLS_AXI_BRIDGE_TIMEOUT_MS` for systems where npx
 * bootstrap or Chrome launch is slow (>30s). Values below 1s are clamped to
 * 1s to avoid pathological retries.
 */
export function resolveBridgeTimeoutMs(): number {
  const raw = process.env.CHROME_DEVTOOLS_AXI_BRIDGE_TIMEOUT_MS;
  if (!raw) return DEFAULT_BRIDGE_TIMEOUT_MS;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed <= 0) return DEFAULT_BRIDGE_TIMEOUT_MS;
  return Math.max(parsed, MIN_BRIDGE_TIMEOUT_MS);
}

export type ErrorCode =
  | "BRIDGE_NOT_READY"
  | "REF_NOT_FOUND"
  | "STALE_REF"
  | "TIMEOUT"
  | "BROWSER_ERROR"
  | "VALIDATION_ERROR"
  | "UNKNOWN";

export class CdpError extends AxiError {
  constructor(
    message: string,
    public readonly code: ErrorCode,
    public readonly suggestions: string[] = [],
  ) {
    super(message, code, suggestions);
    this.name = "CdpError";
  }
}

class BridgeAuthenticationError extends CdpError {
  constructor() {
    super(
      "Bridge authentication failed. Run stop, then start this session",
      "BRIDGE_NOT_READY",
    );
  }
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function authenticatedRequest(
  port: number,
  path: string,
  secret: string,
  method: "GET" | "POST",
  payload: string,
  timeoutMs: number,
  is_ambient = false,
): Promise<string> {
  const headers = createAuthHeaders(secret, method, path, payload, is_ambient);
  return new Promise((resolve, reject) => {
    let response: IncomingMessage | undefined;
    const req = request(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method,
        // Synchronous ACL checks can outlast a pooled socket's idle timeout.
        agent: false,
        headers: {
          ...headers,
          ...(method === "POST"
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(payload),
              }
            : {}),
        },
      },
      (res) => {
        response = res;
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_BRIDGE_RESPONSE_BYTES) {
            req.destroy(new Error("Bridge response is too large"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("error", () => reject(new BridgeAuthenticationError()));
        res.on("end", () => {
          const body = Buffer.concat(chunks);
          if (!isUtf8(body)) {
            reject(new BridgeAuthenticationError());
            return;
          }
          const data = body.toString("utf8");
          if (
            !verifyResponse(
              secret,
              headers.authorization,
              res.statusCode ?? 0,
              data,
              res.headers[RESPONSE_PROOF_HEADER],
            )
          ) {
            reject(new BridgeAuthenticationError());
          } else if (method === "POST" && (res.statusCode ?? 0) >= 400) {
            reject(new Error(data));
          } else {
            resolve(data);
          }
        });
      },
    );
    // A whole-request deadline rather than a socket idle timeout, so a peer
    // that trickles bytes cannot hold the CLI open.
    const deadline = setTimeout(
      () => req.destroy(new Error("timeout")),
      timeoutMs,
    );
    deadline.unref();
    req.on("upgrade", (_response, socket) => {
      socket.destroy();
      reject(new BridgeAuthenticationError());
    });
    req.on("close", () => {
      clearTimeout(deadline);
      if (!response?.complete) reject(new BridgeAuthenticationError());
    });
    req.on("error", reject);
    req.end(payload);
  });
}

/**
 * Probe the bridge's `/health` endpoint. With `deep: true`, asks the bridge
 * to drive one CDP-backed MCP call (`list_pages`) so callers can distinguish
 * "MCP server is up but the attached browser is gone" from genuine readiness.
 *
 * With `expectedSession`, a bridge that reports a *different* session name is
 * treated as unhealthy, so a session never silently reuses another session's
 * bridge after a port collision (two sessions pinned to one port via a global
 * `CHROME_DEVTOOLS_AXI_PORT`). Legacy or unsigned responses are rejected.
 *
 * With `notice`, a healthy *deep* probe writes the bridge's `pageIdentityChanged`
 * flag into that caller-owned holder (see {@link PageIdentityNotice}).
 *
 * With `ambient`, the probe is marked as observation only, so it does not
 * renew an opted-in idle timeout (see {@link AMBIENT_REQUEST_HEADER}).
 *
 * Exported for tests; production code uses it via {@link ensureBridge}.
 */
export async function checkBridgeHealth(
  port: number,
  opts: {
    deep?: boolean;
    expectedSession?: string;
    notice?: PageIdentityNotice;
    ambient?: boolean;
    secret?: string;
  } = {},
): Promise<boolean> {
  const state = opts.secret ? null : readBridgeState(opts.expectedSession);
  const secret =
    opts.secret ?? (state?.port === port ? state.secret : undefined);
  if (!secret) return false;
  try {
    const path = opts.deep ? "/health?deep=1" : "/health";
    const timeoutMs = opts.deep ? DEEP_HEALTH_TIMEOUT_MS : HEALTH_TIMEOUT_MS;
    const resp = await authenticatedRequest(
      port,
      path,
      secret,
      "GET",
      "",
      timeoutMs,
      opts.ambient,
    );
    const data = JSON.parse(resp);
    if (data.status !== "ok") return false;
    if (
      opts.expectedSession !== undefined &&
      data.session !== opts.expectedSession
    ) {
      return false;
    }
    if (opts.deep && opts.notice) {
      opts.notice.pageIdentityChanged = data.pageIdentityChanged === true;
    }
    return true;
  } catch (error) {
    if (error instanceof BridgeAuthenticationError) throw error;
    return false;
  }
}

/**
 * One {@link callTool} invocation's reconnect notice: whether the deep probe
 * that ran for *this* call reported that chrome-devtools-mcp had reissued every
 * page id *and* that this took a selection with it. The bridge gates the flag
 * on the clear having removed an id, so a session that never selected a page is
 * never told it lost one.
 *
 * `ensureBridge` deep-probes before every command, and that probe's
 * `list_pages` is what consumes chrome-devtools-mcp's one-shot reconnect marker
 * and clears the persisted selection - so without this relay the command that
 * follows finds no selection and blames the caller for never selecting a page.
 *
 * The holder is created by the caller and threaded through, never module state:
 * a `run` script can have several `callTool`s in flight at once, and a shared
 * slot would let one call's probe overwrite - or one call's resolution consume -
 * another's attribution, so a reconnect could be reported against the wrong
 * operation or dropped entirely. Per-invocation ownership also keeps the signal
 * one-shot in the same spirit as the marker it relays: it explains only the call
 * whose own probe consumed the marker, and is discarded with that call rather
 * than relabelling later no-selection errors in the same process. A call that
 * resolves no selection simply drops it - `pages` only calls `list_pages`, and
 * the home view probe carries no holder at all, since its own health check is
 * shallow and its `take_snapshot` carries the persisted id without coming
 * through here.
 */
export interface PageIdentityNotice {
  /** Written by the last deep probe of the owning `ensureBridge` call. */
  pageIdentityChanged: boolean;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export async function waitForProcessExit(
  pid: number,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!isProcessAlive(pid)) return true;
    await sleep(50);
  }
  return !isProcessAlive(pid);
}

/**
 * Whether `pid` is still this session's bridge. False means the recorded pid
 * now belongs to an unrelated process, which must never be terminated. On
 * Windows the check also binds the pid to the recorded loopback port and throws
 * when ownership cannot be determined.
 */
function isBridgeProcess(pid: number, port: number): boolean {
  if (process.platform === "win32") return isWindowsBridgeProcess(pid, port);
  try {
    const command = execFileSync("ps", ["-p", String(pid), "-o", "command="], {
      encoding: "utf-8",
      timeout: 1000,
    });
    return command.includes("chrome-devtools-axi-bridge");
  } catch {
    return false;
  }
}

/**
 * Terminate a bridge process and, when requested, its owned children so they
 * cannot survive as orphans. Windows tree termination uses taskkill /T /F.
 * POSIX termination sends SIGTERM, then escalates to SIGKILL on the detached
 * process group. Returns once the bridge PID is gone or the exit grace expires.
 */
export async function terminateBridgeProcess(
  pid: number,
  opts: { killProcessGroup?: boolean } = {},
): Promise<void> {
  if (!isProcessAlive(pid)) return;
  const killProcessGroup = opts.killProcessGroup === true;
  if (process.platform === "win32" && killProcessGroup) {
    const systemRoot = process.env.SystemRoot;
    if (!systemRoot) throw new Error("Missing Windows system directory");
    try {
      execFileSync(
        join(systemRoot, "System32", "taskkill.exe"),
        ["/PID", String(pid), "/T", "/F"],
        { timeout: 10_000, windowsHide: true, stdio: "ignore" },
      );
    } catch (error) {
      if (isProcessAlive(pid)) throw error;
    }
    await waitForProcessExit(pid, 3000);
    return;
  }

  // Give the bridge a chance to run its own shutdown handler (which kills its
  // process group on `exit`).
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    return;
  }

  if (await waitForProcessExit(pid, 2000)) {
    if (killProcessGroup) {
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        // Group already gone or pid was never a group leader — fine.
      }
    }
    return;
  }

  // Escalate: kill the whole process group so children get reaped together.
  if (killProcessGroup) {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Already dead.
      }
    }
  } else {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Already dead.
    }
  }
  await waitForProcessExit(pid, 1000);
}

/**
 * Minimal view of the spawned bridge process that {@link ensureBridge} needs:
 * an `exit` notification so a bridge that dies before reporting healthy can be
 * detected. The default {@link spawnBridgeProcess} returns a `ChildProcess`
 * (which satisfies this); tests inject a fake.
 */
export interface SpawnedBridge {
  on(
    event: "exit",
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): void;
}

/**
 * Spawn the detached bridge process. Prefers the sibling `.ts` (dev mode, run
 * via tsx) and falls back to the built `.js`, so dev and dist behave the same.
 */
function spawnBridgeProcess(port: number, sessionName: string): SpawnedBridge {
  const bridgeScript = resolveBridgeScript(import.meta.dirname);
  const script = existsSync(bridgeScript.replace(/\.js$/, ".ts"))
    ? bridgeScript.replace(/\.js$/, ".ts")
    : bridgeScript;
  const child = spawn(
    process.execPath,
    script.endsWith(".ts") ? ["--import", "tsx", script] : [script],
    {
      stdio: "ignore",
      env: {
        ...process.env,
        CHROME_DEVTOOLS_AXI_PORT: String(port),
        CHROME_DEVTOOLS_AXI_SESSION: sessionName,
      },
      detached: true,
      windowsHide: true,
    },
  );
  child.unref();
  return child;
}
type SharedMcpMode = "direct" | "proxy" | null;

function resolveSharedMcpMode(): SharedMcpMode {
  const sharedServerUrl =
    process.env.CHROME_DEVTOOLS_AXI_MCP_SERVER_URL?.trim();
  if (!sharedServerUrl) return null;
  return process.env.CHROME_DEVTOOLS_AXI_MCP_PATH?.trim() ? "proxy" : "direct";
}

function sharedMcpSuggestions(mode: Exclude<SharedMcpMode, null>): string[] {
  if (mode === "direct") {
    return [
      "Shared MCP direct mode is enabled by CHROME_DEVTOOLS_AXI_MCP_SERVER_URL; AXI connects directly to that Streamable HTTP endpoint without launching a local MCP process.",
      "Verify CHROME_DEVTOOLS_AXI_MCP_SERVER_URL is an absolute http(s) MCP endpoint and that the service is running and reachable there.",
    ];
  }
  return [
    "Shared MCP proxy mode is enabled by CHROME_DEVTOOLS_AXI_MCP_SERVER_URL; this mode does not launch Chrome locally.",
    "Set CHROME_DEVTOOLS_AXI_MCP_PATH to a runnable chrome-devtools-mcp build that advertises --serverUrl in --help.",
    "Use the proxy-capable MCP build from the companion shared-server change, then restart this AXI session.",
  ];
}

/**
 * Build the error thrown when a freshly spawned bridge exits before it ever
 * reports healthy. Surfacing this the moment the child dies - rather than
 * polling the full readiness deadline - turns an early death into a fast,
 * actionable failure instead of a slow, generic "failed to start" timeout.
 *
 * The guidance is attributed by exit code. Only {@link BRIDGE_PORT_IN_USE_EXIT_CODE}
 * (the bridge's EADDRINUSE sentinel) gets the port-in-use explanation; any
 * other early death is a startup failure. Direct shared-MCP configuration gets
 * endpoint-specific guidance; proxy configuration gets `MCP_PATH`/`--serverUrl`
 * prerequisites; local mode covers npx resolution, a broken
 * `CHROME_DEVTOOLS_AXI_MCP_PATH`, or a Chrome launch failure. In either mode, a
 * single-session user with a broken install is not misdirected to port advice.
 */
export function buildBridgeEarlyExitError(
  sessionName: string,
  port: number,
  code: number | null,
  signal: NodeJS.Signals | null,
): CdpError {
  const how =
    signal != null
      ? `was killed by ${signal}`
      : `exited with code ${code ?? "unknown"}`;
  const message = `Bridge for session "${sessionName}" ${how} before becoming ready on port ${port}`;

  if (code === BRIDGE_PORT_IN_USE_EXIT_CODE) {
    return new CdpError(message, "BRIDGE_NOT_READY", [
      `Port ${port} is already in use. It may be held by another chrome-devtools-axi session's bridge (a hashed-port collision, or a globally-exported CHROME_DEVTOOLS_AXI_PORT forcing every session onto one port), by a stale or crashed bridge that could not be reused, or by an unrelated process.`,
      "Set a distinct CHROME_DEVTOOLS_AXI_PORT for this session, unset a global CHROME_DEVTOOLS_AXI_PORT so every session derives its own, or free whatever is holding the port.",
    ]);
  }
  const sharedMcpMode = resolveSharedMcpMode();
  if (sharedMcpMode) {
    return new CdpError(
      message,
      "BRIDGE_NOT_READY",
      sharedMcpSuggestions(sharedMcpMode),
    );
  }

  const suggestions = [
    "Check that chrome-devtools-mcp can start: npx chrome-devtools-mcp@latest --help",
  ];
  if (process.env.CHROME_DEVTOOLS_AXI_MCP_PATH?.trim()) {
    suggestions.push(
      "Verify CHROME_DEVTOOLS_AXI_MCP_PATH points to a valid chrome-devtools-mcp build.",
    );
  } else {
    suggestions.push(
      "`npx -y chrome-devtools-mcp@latest` may have failed to resolve/download the package (offline, or a slow cold first run); install it globally and set:",
      '  export CHROME_DEVTOOLS_AXI_MCP_PATH="$(npm prefix -g)/lib/node_modules/chrome-devtools-mcp/build/src/bin/chrome-devtools-mcp.js"',
    );
  }
  suggestions.push(
    "Or Chrome failed to launch; confirm a usable Chrome is installed.",
  );
  return new CdpError(message, "BRIDGE_NOT_READY", suggestions);
}

/**
 * Ensure the bridge is running, starting it if needed. Returns the port.
 *
 * Verifies a *deep* health check (one round-trip CDP-backed MCP call) before
 * declaring the bridge ready, so a bridge whose attached browser/Electron
 * target was killed while still answering local /health requests gets torn
 * down + restarted instead of being reused as a stale endpoint.
 *
 * `spawnBridge` is injectable for tests; production uses {@link spawnBridgeProcess}.
 *
 * `notice` is the caller's own {@link PageIdentityNotice} holder; every deep
 * probe this call makes writes its `pageIdentityChanged` flag there, so the
 * reconnect attribution belongs to this invocation and cannot cross a
 * concurrent one.
 */
export async function ensureBridge(
  spawnBridge: (
    port: number,
    sessionName: string,
  ) => SpawnedBridge = spawnBridgeProcess,
  notice?: PageIdentityNotice,
): Promise<number> {
  const sessionName = resolveSessionName();
  const port = resolveSessionPort(sessionName);

  // Check existing bridge via PID file. Use a deep probe so a bridge whose
  // attached CDP target has gone away gets recycled instead of returned.
  const pidInfo = readBridgeState(sessionName);
  if (pidInfo) {
    if (isProcessAlive(pidInfo.pid)) {
      let authenticationError: BridgeAuthenticationError | undefined;
      try {
        if (
          await checkBridgeHealth(pidInfo.port, {
            deep: true,
            expectedSession: sessionName,
            notice,
            secret: pidInfo.secret,
          })
        ) {
          return pidInfo.port;
        }
      } catch (error) {
        if (!(error instanceof BridgeAuthenticationError)) throw error;
        authenticationError = error;
      }
      if (isBridgeProcess(pidInfo.pid, pidInfo.port)) {
        if (authenticationError) throw authenticationError;
        await terminateBridgeProcess(pidInfo.pid, { killProcessGroup: true });
        if (isProcessAlive(pidInfo.pid))
          throw new CdpError("Bridge process did not stop", "BRIDGE_NOT_READY");
      }
    }
    // A force-killed bridge leaves its record behind, and a reused pid now
    // belongs to an unrelated process that is left running. Either way the old
    // key is stale and must not be used to probe the replacement bridge.
    removeBridgeState(pidInfo.pid, sessionName);
  }

  // MCP page ids reset with a new process; a leftover session id would
  // target the wrong tab (or none). Keep the file when reusing a live bridge.
  // Clearing here is also why a respawn never reports a reconnect: the new
  // bridge's first deep probe finds no selection left to drop, so its 200
  // omits `pageIdentityChanged` and the poll loop below records no notice.
  clearSelectedPageId();

  // Start a new bridge
  const child = spawnBridge(port, sessionName);

  const timeoutMs = resolveBridgeTimeoutMs();
  let deadline = Date.now() + timeoutMs;
  let childExited = false;
  let exitCode: number | null = null;
  let exitSignal: NodeJS.Signals | null = null;
  child.on("exit", (code, signal) => {
    childExited = true;
    exitCode = code;
    exitSignal = signal;
    if (code === BRIDGE_PORT_IN_USE_EXIT_CODE) {
      deadline = Math.min(deadline, Date.now() + BRIDGE_COLLISION_GRACE_MS);
    }
  });

  // A probe that meets a bridge whose key does not match the session record
  // proves nothing yet, so it counts as not ready rather than as a failure.
  const isReady = async (deep: boolean) => {
    try {
      return await checkBridgeHealth(port, {
        deep,
        expectedSession: sessionName,
        ...(deep ? { notice } : {}),
      });
    } catch (error) {
      if (error instanceof BridgeAuthenticationError) return false;
      throw error;
    }
  };

  // Poll for health — Chrome launch + npx bootstrap can be slow.
  // Track whether the *shallow* health check ever passed so we can attribute
  // the failure correctly: shallow-but-no-deep means the MCP server came up
  // but the attached CDP target is dead, vs. nothing-came-up which is the
  // generic startup-timeout case.
  let sawShallowReady = false;
  while (Date.now() < deadline) {
    if (await isReady(true)) {
      return port;
    }
    if (childExited && exitCode !== BRIDGE_PORT_IN_USE_EXIT_CODE) {
      if (await isReady(true)) {
        return port;
      }
      throw buildBridgeEarlyExitError(sessionName, port, exitCode, exitSignal);
    }
    if (!sawShallowReady && (await isReady(false))) {
      sawShallowReady = true;
    }
    await sleep(500);
  }

  if (childExited) {
    throw buildBridgeEarlyExitError(sessionName, port, exitCode, exitSignal);
  }

  const seconds = Math.round(timeoutMs / 1000);

  const sharedMcpMode = resolveSharedMcpMode();
  if (sawShallowReady) {
    const suggestions = sharedMcpMode
      ? [
          ...sharedMcpSuggestions(sharedMcpMode),
          "The shared MCP service may be reachable while its attached Chrome target is unavailable.",
        ]
      : [
          "The Chrome/Electron instance the bridge was attached to may have exited.",
          "Verify the target is still listening on its remote-debugging port, then re-run the command.",
          "If the target was restarted, the bridge has already been recycled — this run will succeed once the target is reachable.",
        ];
    throw new CdpError(
      "Bridge is running but the attached CDP target appears to have gone away",
      "BRIDGE_NOT_READY",
      suggestions,
    );
  }

  const suggestions =
    sharedMcpMode === "direct"
      ? sharedMcpSuggestions("direct")
      : sharedMcpMode === "proxy"
        ? sharedMcpSuggestions("proxy")
        : [
            "Check that chrome-devtools-mcp is installed: npx chrome-devtools-mcp@latest --help",
          ];
  if (!sharedMcpMode && !process.env.CHROME_DEVTOOLS_AXI_MCP_PATH?.trim()) {
    suggestions.push(
      "If `npx -y chrome-devtools-mcp@latest` is slow on this machine, install mcp globally and set:",
      '  export CHROME_DEVTOOLS_AXI_MCP_PATH="$(npm prefix -g)/lib/node_modules/chrome-devtools-mcp/build/src/bin/chrome-devtools-mcp.js"',
    );
  }
  suggestions.push(
    "Or extend the deadline: export CHROME_DEVTOOLS_AXI_BRIDGE_TIMEOUT_MS=60000",
  );
  throw new CdpError(
    `Bridge failed to start within ${seconds}s`,
    "BRIDGE_NOT_READY",
    suggestions,
  );
}

function parseCallResponse(resp: string): string {
  const data = JSON.parse(resp);
  if (data.error) {
    throw new Error(data.error);
  }
  return data.result ?? "";
}

async function postTool(
  port: number,
  name: string,
  args: Record<string, unknown>,
  opts: { roots?: string[]; timeoutMs?: number; ambient?: boolean } = {},
): Promise<string> {
  const body: Record<string, unknown> = { name, args };
  if (opts.roots && opts.roots.length > 0) body.roots = opts.roots;
  const state = readBridgeState();
  if (!state || state.port !== port) throw new BridgeAuthenticationError();
  const resp = await authenticatedRequest(
    port,
    "/call",
    state.secret,
    "POST",
    JSON.stringify(body),
    opts.timeoutMs ?? 120_000,
    opts.ambient,
  );
  return parseCallResponse(resp);
}

/**
 * Tool argument keys whose value is a caller-supplied output path, resolved to
 * an absolute path by `resolveOutputPath` before it reaches here. The nearest
 * existing ancestor of their parent directory (or of a directory argument
 * itself) is negotiated as an MCP workspace root, so the write is not restricted
 * to the OS temp directory and missing directories can be created beneath an
 * allowed root (issue #96). Add a key here when a new file-writing tool argument
 * is introduced.
 */
const FILE_OUTPUT_ARGS_BY_TOOL = new Map<string, readonly string[]>([
  ["take_screenshot", ["filePath"]],
  ["get_network_request", ["responseFilePath", "requestFilePath"]],
  ["performance_start_trace", ["filePath"]],
  ["performance_stop_trace", ["filePath"]],
  ["take_memory_snapshot", ["filePath"]],
]);
const DIR_OUTPUT_ARGS_BY_TOOL = new Map<string, readonly string[]>([
  ["lighthouse_audit", ["outputDirPath"]],
]);

function nearestExistingAncestor(path: string): string {
  let candidate = path;
  while (!existsSync(candidate)) {
    const parent = dirname(candidate);
    if (parent === candidate) return candidate;
    candidate = parent;
  }
  return candidate;
}

/**
 * The workspace roots a call needs: always the invoking cwd (so writes under it
 * pass), plus the nearest existing ancestor of any output path argument (so a
 * write outside cwd, e.g. `$HOME/a.png`, passes too).
 */
export function collectRootDirs(
  name: string,
  args: Record<string, unknown>,
): string[] {
  const dirs = new Set<string>([process.cwd()]);
  for (const key of FILE_OUTPUT_ARGS_BY_TOOL.get(name) ?? []) {
    const value = args[key];
    if (typeof value === "string" && value.length > 0) {
      dirs.add(nearestExistingAncestor(dirname(value)));
    }
  }
  for (const key of DIR_OUTPUT_ARGS_BY_TOOL.get(name) ?? []) {
    const value = args[key];
    if (typeof value === "string" && value.length > 0) {
      dirs.add(nearestExistingAncestor(value));
    }
  }
  return [...dirs];
}

/**
 * Resolve the page AXI last selected in this session. Fails loudly when
 * nothing has been selected — AXI will not guess a pageId from
 * `list_pages` `[selected]` (titles/dialogs can forge that marker), and
 * chrome-devtools-mcp 1.8+ will not either (`Required at pageId`).
 *
 * When this invocation's own deep probe reported a browser reconnect
 * (`reconnected`), the missing selection is that reconnect's doing rather than
 * the caller's, so the error names it. The two cases stay distinct: a session
 * that never selected a page, or whose bridge was just respawned, still gets
 * the plain message.
 */
function resolveSelectedPageId(reconnected: boolean): number {
  const pageId = getSelectedPageId();
  if (pageId === null) {
    if (reconnected) throw pageIdentityClearedError();
    throw new CdpError("No page is currently selected", "BROWSER_ERROR", [
      "Run `chrome-devtools-axi open <url>` to open a page",
      "Run `chrome-devtools-axi pages` to list tabs",
      "Run `chrome-devtools-axi selectpage <id>` to select a tab",
    ]);
  }
  return pageId;
}

function resolveToolArgs(
  name: string,
  args: Record<string, unknown>,
  reconnected: boolean,
): Record<string, unknown> {
  if (!needsPageId(name, args)) return args;
  return { ...args, pageId: resolveSelectedPageId(reconnected) };
}

/**
 * Call an MCP tool via the bridge. Returns the text result.
 *
 * Page-scoped tools (eval/snapshot/click/fill and the rest of
 * `PAGE_SCOPED_TOOLS` in `src/pages.ts`) get the session's last
 * `select_page` / created `new_page` `pageId` injected so they satisfy
 * chrome-devtools-mcp 1.8+ defaults. `list_pages` is never consulted.
 */
export async function callTool(
  name: string,
  args: Record<string, unknown> = {},
): Promise<string> {
  // Owned by this call alone, so a concurrent `run`-script call cannot
  // overwrite or consume this one's reconnect attribution.
  const notice: PageIdentityNotice = { pageIdentityChanged: false };
  const port = await ensureBridge(undefined, notice);
  let resolved = args;

  try {
    resolved = resolveToolArgs(name, args, notice.pageIdentityChanged);
    const result = await postTool(port, name, resolved, {
      roots: collectRootDirs(name, resolved),
    });
    rememberToolRouting(name, resolved, result);
    return result;
  } catch (err) {
    if (err instanceof CdpError) throw err;
    const message = err instanceof Error ? err.message : String(err);
    if (isMissingPageError(message)) {
      const pageId =
        typeof resolved.pageId === "number" ? resolved.pageId : null;
      if (pageId !== null && getSelectedPageId() === pageId) {
        clearSelectedPageId();
      }
      throw missingPageError(pageId);
    }
    throw mapErrorMessage(message);
  }
}

/**
 * chrome-devtools-mcp text the bridge flattens into a `/call` error body: a
 * bare line when the tool handler rethrows, or an `Error: `-prefixed line when
 * the response builder appends it. `The selected page has been closed.` leads a
 * sentence that interpolates the `list_pages` tool name, so only its stable
 * clause is anchored.
 */
const MCP_MISSING_PAGE_LINE = "No page found";
const MCP_CLOSED_PAGE_LINE_PREFIX = "The selected page has been closed.";

/**
 * Whether the bridge error body names a page chrome-devtools-mcp itself could
 * not resolve. The body is the *whole* flattened MCP response, and page-owned
 * strings upstream interpolates verbatim (a dialog message, a title) may carry
 * raw newlines, so any line in the middle of the body can be page-controlled.
 * Only the final non-empty line is consulted, which rules those out.
 *
 * It does NOT make the marker unforgeable. Upstream's last element is
 * `Error: <errorMessage>` with the raw exception message interpolated, and
 * that message can itself contain a raw newline, so a page that throws
 * "\nNo page found" ends the body with a line that is exactly the sentence.
 * No purely text-based matcher can separate page bytes inside `errorMessage`
 * from upstream's own sentence. The consequence is fail-closed - a spurious
 * loud error plus dropped routing, never a silent retarget - and the sibling
 * reconnect matcher in `src/bridge.ts` is unaffected, because a forged first
 * line still carries upstream's literal `Error: ` prefix.
 *
 * UNVERIFIED DEPENDENCY CONTRACT: this assumes chrome-devtools-mcp appends
 * `Error: <message>` LAST, after every page-derived block (and, for the
 * sibling reconnect matcher in `src/bridge.ts`, emits its notice FIRST).
 * See `didMcpPageIdentityChange` in `src/bridge.ts` for why this dependency
 * ordering is unverified. If upstream reorders, a genuine missing page falls
 * through to `mapErrorMessage` and surfaces as a less specific error rather
 * than retargeting anything; upstream hands out page ids from a process-wide
 * monotonic counter, so a stale id fails to resolve instead of landing on an
 * unrelated page.
 */
function isMissingPageError(message: string): boolean {
  const line = lastNonEmptyLine(message).replace(/^Error:\s*/, "");
  return (
    line === MCP_MISSING_PAGE_LINE ||
    line.startsWith(MCP_CLOSED_PAGE_LINE_PREFIX)
  );
}

function lastNonEmptyLine(message: string): string {
  const lines = message.split(/\r?\n/);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i].trim();
    if (line) return line;
  }
  return "";
}

function missingPageError(pageId: number | null): CdpError {
  return new CdpError(
    pageId === null
      ? "The selected page is no longer available"
      : `Page ${pageId} is no longer available`,
    "BROWSER_ERROR",
    [
      "Run `chrome-devtools-axi pages` to list the remaining tabs",
      "Run `chrome-devtools-axi selectpage <id>` to select a tab, or `chrome-devtools-axi open <url>` to open one",
    ],
  );
}

const PAGE_IDENTITY_SUGGESTIONS = [
  "Run `chrome-devtools-axi pages` to list the current tabs and their new ids",
  "Run `chrome-devtools-axi selectpage <id>` to re-select a tab after the reconnect, then retry",
];

function pageIdentityChangedError(): CdpError {
  return new CdpError(
    PAGE_IDENTITY_CHANGED_ERROR,
    "BROWSER_ERROR",
    PAGE_IDENTITY_SUGGESTIONS,
  );
}

/**
 * The reconnect already happened before this command ran: the deep probe
 * consumed the marker and dropped the routing it invalidated, so nothing was
 * sent to a wrong tab and there is nothing to retarget — the caller just has
 * to re-select. Keeps the `BROWSER_ERROR` code and the "no page" clause of the
 * plain no-selection message so `open`'s existing recovery still applies (it
 * creates a new tab; see AGENTS.md).
 *
 * Exported so the `open` / `page.open` recovery tests build their rejection
 * from the message this ships rather than a copy of it, which is what makes
 * them fail if a reword breaks that match.
 */
export function pageIdentityClearedError(): CdpError {
  return new CdpError(
    "The browser reconnected and every page id changed, so no page is currently selected",
    "BROWSER_ERROR",
    PAGE_IDENTITY_SUGGESTIONS,
  );
}

export function mapErrorMessage(message: string): CdpError {
  if (message === PAGE_IDENTITY_CHANGED_ERROR) {
    return pageIdentityChangedError();
  }
  if (isMissingPageError(message)) return missingPageError(null);
  if (message.includes("ECONNREFUSED") || message.includes("ECONNRESET")) {
    return new CdpError("Bridge is not running", "BRIDGE_NOT_READY", [
      "Run `chrome-devtools-axi open <url>` — the bridge starts automatically",
    ]);
  }
  if (
    (message.includes("uid") || message.includes("element")) &&
    (message.includes("not found") || message.includes("invalid"))
  ) {
    return new CdpError(message, "REF_NOT_FOUND", [
      "Run `chrome-devtools-axi snapshot` to see available elements and their @uid refs",
    ]);
  }
  if (message.includes("timeout") || message.includes("timed out")) {
    return new CdpError(message, "TIMEOUT", [
      "Run `chrome-devtools-axi snapshot` to see current page state",
    ]);
  }
  // Try to parse JSON error
  try {
    const parsed = JSON.parse(message);
    if (parsed.error) {
      return new CdpError(parsed.error, "BROWSER_ERROR", [
        "Run `chrome-devtools-axi snapshot` to see current page state",
      ]);
    }
  } catch {
    // Not JSON
  }
  return new CdpError(message, "UNKNOWN");
}

/**
 * Get the current page snapshot without starting the bridge.
 *
 * Returns null if the bridge is not running or healthy. This is the ambient
 * home view / SessionStart probe, so it must stay cheap, never throw, and never
 * renew an opted-in idle timeout (both requests are marked ambient): an
 * invalid `CHROME_DEVTOOLS_AXI_SESSION` degrades to "no active session" (null)
 * here, while action commands (`ensureBridge` / `stopBridge`) still fail loudly.
 */
export async function getSessionSnapshotIfRunning(): Promise<string | null> {
  let sessionName: string;
  let pidInfo: BridgeState | null;
  try {
    sessionName = resolveSessionName();
    pidInfo = readBridgeState(sessionName);
  } catch {
    return null;
  }
  if (!pidInfo || !isProcessAlive(pidInfo.pid)) {
    return null;
  }
  try {
    if (
      !(await checkBridgeHealth(pidInfo.port, {
        expectedSession: sessionName,
        ambient: true,
        secret: pidInfo.secret,
      }))
    ) {
      return null;
    }
    const pageId = getSelectedPageId();
    if (pageId === null) return null;
    return await postTool(
      pidInfo.port,
      "take_snapshot",
      { pageId },
      { timeoutMs: 5000, ambient: true },
    );
  } catch {
    return null;
  }
}

/**
 * Stop the verified bridge and its owned children via {@link terminateBridgeProcess}.
 * Resolves once the bridge process is gone, leaving unrelated processes untouched.
 */
export async function stopBridge(): Promise<boolean> {
  const pidInfo = readBridgeStateForStop(resolveSessionName(), true);
  if (!pidInfo) return false;
  if (
    !isProcessAlive(pidInfo.pid) ||
    !isBridgeProcess(pidInfo.pid, pidInfo.port)
  ) {
    // No bridge of this session runs under the recorded pid, so only the
    // stale record goes. A reused pid's unrelated process is left running.
    removeBridgeState(pidInfo.pid);
    return false;
  }
  await terminateBridgeProcess(pidInfo.pid, {
    killProcessGroup: true,
  });
  if (isProcessAlive(pidInfo.pid))
    throw new CdpError("Bridge process did not stop", "BRIDGE_NOT_READY");
  removeBridgeState(pidInfo.pid);
  clearSelectedPageId();
  return true;
}
