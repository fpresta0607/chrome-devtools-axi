import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { BRIDGE_TRANSPORT } from "./bridge-auth.js";
import {
  DEFAULT_SESSION_NAME,
  resolveSessionName,
  resolveSessionPidFile,
  resolveSessionStateDir,
  validateSessionName,
} from "./sessions.js";
import {
  secureWindowsPath,
  secureWindowsPaths,
  verifyWindowsState,
} from "./windows-acl.js";

export interface BridgeState {
  pid: number;
  port: number;
  secret: string;
  bridge_transport: typeof BRIDGE_TRANSPORT;
}

const UNSAFE_STATE_MESSAGE =
  "Unsafe bridge state permissions. Run stop, then start this session";

function stateDirectories(sessionName: string): string[] {
  validateSessionName(sessionName);
  const root = resolveSessionStateDir(DEFAULT_SESSION_NAME);
  return sessionName === DEFAULT_SESSION_NAME
    ? [root]
    : [root, join(root, "sessions"), resolveSessionStateDir(sessionName)];
}

function verifyPosixPath(
  path: string,
  is_directory: boolean,
  should_prepare = false,
): void {
  const info = lstatSync(path);
  if (
    info.isSymbolicLink() ||
    (is_directory ? !info.isDirectory() : !info.isFile()) ||
    info.uid !== process.getuid?.() ||
    (!is_directory && info.nlink !== 1)
  ) {
    throw new Error(UNSAFE_STATE_MESSAGE);
  }
  if (should_prepare) {
    chmodSync(path, is_directory ? 0o700 : 0o600);
    verifyPosixPath(path, is_directory);
  } else if ((info.mode & 0o077) !== 0) {
    throw new Error(UNSAFE_STATE_MESSAGE);
  }
}

export function prepareSessionState(sessionName = resolveSessionName()): void {
  const directories = stateDirectories(sessionName);
  if (process.platform === "win32") {
    secureWindowsPaths(directories, "prepare-directory");
    return;
  }
  for (const path of directories) {
    try {
      mkdirSync(path, { mode: 0o700 });
    } catch (error) {
      if (
        !(error instanceof Error) ||
        !("code" in error) ||
        error.code !== "EEXIST"
      )
        throw error;
    }
    verifyPosixPath(path, true, true);
  }
}

function readState(
  sessionName: string,
  should_migrate = false,
): Record<string, unknown> | null {
  const directories = stateDirectories(sessionName);
  const path = resolveSessionPidFile(sessionName);
  try {
    if (!lstatSync(path, { throwIfNoEntry: false })) return null;
    if (should_migrate) {
      if (process.platform === "win32") {
        if (lstatSync(path).nlink !== 1) throw new Error(UNSAFE_STATE_MESSAGE);
        secureWindowsPaths(directories, "prepare-directory", path);
      } else {
        for (const directory of directories)
          verifyPosixPath(directory, true, true);
        verifyPosixPath(path, false, true);
      }
    }
    if (process.platform === "win32") {
      if (lstatSync(path).nlink !== 1) throw new Error(UNSAFE_STATE_MESSAGE);
      verifyWindowsState(directories, path);
    } else {
      for (const directory of directories) verifyPosixPath(directory, true);
      verifyPosixPath(path, false);
    }
    try {
      const data: unknown = JSON.parse(readFileSync(path, "utf8"));
      if (data === null || typeof data !== "object" || Array.isArray(data))
        throw new Error();
      return data as Record<string, unknown>;
    } catch {
      throw new Error(
        "Invalid authenticated bridge state. Run stop, then start this session",
      );
    }
  } catch (error) {
    if (!lstatSync(path, { throwIfNoEntry: false })) return null;
    throw error;
  }
}

export function readBridgeStateForStop(
  sessionName = resolveSessionName(),
  should_migrate = false,
): { pid: number; port: number } | null {
  const data = readState(sessionName, should_migrate);
  if (!data) return null;
  if (
    !Number.isSafeInteger(data.pid) ||
    Number(data.pid) <= 0 ||
    !Number.isSafeInteger(data.port) ||
    Number(data.port) <= 0 ||
    Number(data.port) > 65535
  ) {
    throw new Error("Invalid authenticated bridge state");
  }
  return { pid: Number(data.pid), port: Number(data.port) };
}

export function readBridgeState(
  sessionName = resolveSessionName(),
): BridgeState | null {
  const data = readState(sessionName);
  if (!data) return null;
  if (
    !Number.isSafeInteger(data.pid) ||
    Number(data.pid) <= 0 ||
    !Number.isSafeInteger(data.port) ||
    Number(data.port) <= 0 ||
    Number(data.port) > 65535 ||
    typeof data.secret !== "string" ||
    !/^[a-f0-9]{64}$/.test(data.secret) ||
    data.bridge_transport !== BRIDGE_TRANSPORT
  ) {
    throw new Error(
      "Invalid authenticated bridge state. Run stop, then start this session",
    );
  }
  return {
    pid: Number(data.pid),
    port: Number(data.port),
    secret: data.secret,
    bridge_transport: BRIDGE_TRANSPORT,
  };
}

export function writeBridgeState(
  port: number,
  secret: string,
  sessionName = resolveSessionName(),
  pid = process.pid,
): void {
  if (
    !/^[a-f0-9]{64}$/.test(secret) ||
    !Number.isSafeInteger(pid) ||
    pid <= 0 ||
    !Number.isSafeInteger(port) ||
    port <= 0 ||
    port > 65535
  )
    throw new Error("Invalid authenticated bridge state");
  prepareSessionState(sessionName);
  const destination = resolveSessionPidFile(sessionName);
  const temporary = `${destination}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  const descriptor = openSync(temporary, "wx", 0o600);
  try {
    try {
      if (process.platform === "win32")
        secureWindowsPath(temporary, "verify-file");
      else verifyPosixPath(temporary, false);
      writeFileSync(
        descriptor,
        JSON.stringify({
          pid,
          port,
          secret,
          bridge_transport: BRIDGE_TRANSPORT,
        }),
      );
    } finally {
      closeSync(descriptor);
    }
    renameSync(temporary, destination);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

export function removeBridgeState(
  pid: number,
  sessionName = resolveSessionName(),
): void {
  const state = readBridgeStateForStop(sessionName);
  if (state?.pid === pid) {
    const path = resolveSessionPidFile(sessionName);
    try {
      unlinkSync(path);
    } catch (error) {
      if (lstatSync(path, { throwIfNoEntry: false })) throw error;
    }
  }
}
