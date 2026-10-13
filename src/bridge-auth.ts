import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { AMBIENT_REQUEST_HEADER } from "./bridge-script.js";

export const BRIDGE_TRANSPORT =
  process.platform === "win32" ? "windows-user-v1" : "user-v1";
export const RESPONSE_PROOF_HEADER = "x-chrome-devtools-axi-proof";
const CLOCK_WINDOW_MS = 30_000;
const MAX_REQUEST_IDENTITIES = 4096;
const AUTH_PATTERN = /^AXI-HMAC (\d{13})\.([a-f0-9]{32})\.([a-f0-9]{64})$/;

function mac(secret: string, fields: string[]): string {
  return createHmac("sha256", Buffer.from(secret, "hex"))
    .update(fields.join("\n"))
    .digest("hex");
}

function matchesMac(expected: string, supplied: unknown): boolean {
  return (
    typeof supplied === "string" &&
    /^[a-f0-9]{64}$/.test(supplied) &&
    timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(supplied, "hex"))
  );
}

export function createAuthHeaders(
  secret: string,
  method: string,
  path: string,
  body = "",
  is_ambient = false,
): Record<string, string> {
  const timestamp = String(Date.now());
  const nonce = randomBytes(16).toString("hex");
  const signature = mac(secret, [
    "request",
    method,
    path,
    is_ambient ? "1" : "0",
    timestamp,
    nonce,
    body,
  ]);
  return {
    authorization: `AXI-HMAC ${timestamp}.${nonce}.${signature}`,
    ...(is_ambient ? { [AMBIENT_REQUEST_HEADER]: "1" } : {}),
  };
}

export function verifyResponse(
  secret: string,
  authorization: string,
  status: number,
  body: string,
  proof: unknown,
): boolean {
  const identity = AUTH_PATTERN.exec(authorization);
  return (
    identity !== null &&
    matchesMac(
      mac(secret, ["response", identity[1], identity[2], String(status), body]),
      proof,
    )
  );
}

export interface BridgeAuth {
  authenticate(req: IncomingMessage, body: string): string | null;
  signResponse(authorization: string, status: number, body: string): string;
}

export function createBridgeAuth(secret: string): BridgeAuth {
  if (!/^[a-f0-9]{64}$/.test(secret))
    throw new Error("Invalid bridge authentication key");
  const identities = new Map<string, number>();
  return {
    authenticate(req, body) {
      const authorization = req.headers.authorization;
      if (typeof authorization !== "string") return null;
      const identity = AUTH_PATTERN.exec(authorization);
      if (!identity) return null;
      const [, timestamp, nonce, signature] = identity;
      const now = Date.now();
      if (Math.abs(now - Number(timestamp)) > CLOCK_WINDOW_MS) return null;
      const expected = mac(secret, [
        "request",
        req.method ?? "",
        req.url ?? "",
        req.headers[AMBIENT_REQUEST_HEADER] === "1" ? "1" : "0",
        timestamp,
        nonce,
        body,
      ]);
      if (!matchesMac(expected, signature)) return null;
      for (const [used, expires] of identities) {
        if (expires < now) identities.delete(used);
      }
      if (identities.has(nonce) || identities.size >= MAX_REQUEST_IDENTITIES)
        return null;
      identities.set(nonce, Number(timestamp) + CLOCK_WINDOW_MS);
      return authorization;
    },
    signResponse(authorization, status, body) {
      const identity = AUTH_PATTERN.exec(authorization);
      if (!identity) throw new Error("Invalid bridge request identity");
      return mac(secret, [
        "response",
        identity[1],
        identity[2],
        String(status),
        body,
      ]);
    },
  };
}
