import { createHmac, randomBytes } from "node:crypto";
import { request, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createBridgeServer, type BridgeClient } from "../src/bridge.js";

const SECRET = "a".repeat(64);

function requestHeaders(
  method: string,
  path: string,
  body = "",
  secret = SECRET,
  timestamp = Date.now(),
  nonce = randomBytes(16).toString("hex"),
) {
  const message = [
    "request",
    method,
    path,
    "0",
    String(timestamp),
    nonce,
    body,
  ].join("\n");
  const signature = createHmac("sha256", Buffer.from(secret, "hex"))
    .update(message)
    .digest("hex");
  return { authorization: `AXI-HMAC ${timestamp}.${nonce}.${signature}` };
}

function send(
  port: number,
  path: string,
  headers: Record<string, string> = {},
  body = "",
) {
  return new Promise<{
    status: number | undefined;
    body: string;
    headers: IncomingHttpHeaders;
  }>((resolve, reject) => {
    const outgoing = request(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: path === "/call" ? "POST" : "GET",
        headers,
      },
      (incoming) => {
        let received = "";
        incoming.setEncoding("utf8");
        incoming.on("data", (chunk) => {
          received += chunk;
        });
        incoming.on("end", () =>
          resolve({
            status: incoming.statusCode,
            body: received,
            headers: incoming.headers,
          }),
        );
      },
    );
    outgoing.on("error", reject);
    outgoing.end(body);
  });
}

describe("bridge authentication boundary", () => {
  const servers: ReturnType<typeof createBridgeServer>[] = [];

  afterEach(async () => {
    await Promise.all(
      servers.splice(0).map(
        (server) =>
          new Promise<void>((resolve) => {
            server.close(() => resolve());
          }),
      ),
    );
    vi.restoreAllMocks();
  });

  it.each(["default", "worker-1"])(
    "denies unauthenticated access to every route in %s",
    async (session) => {
      const client: BridgeClient = {
        listTools: vi.fn(async () => ({ tools: [{ name: "private-tool" }] })),
        callTool: vi.fn(async () => ({
          content: [{ type: "text", text: "private-result" }],
        })),
        close: async () => {},
      };
      const server = createBridgeServer(client, session);
      servers.push(server);
      await new Promise<void>((resolve) =>
        server.listen(0, "127.0.0.1", resolve),
      );
      const { port } = server.address() as AddressInfo;

      for (const path of [
        "/health",
        "/health?deep=1",
        "/tools",
        "/call",
        "/unknown",
      ]) {
        const response = await new Promise<{
          status: number | undefined;
          body: string;
        }>((resolve, reject) => {
          const body =
            path === "/call"
              ? JSON.stringify({ name: "list_pages", args: {} })
              : "";
          const outgoing = request(
            {
              hostname: "127.0.0.1",
              port,
              path,
              method: path === "/call" ? "POST" : "GET",
            },
            (incoming) => {
              let received = "";
              incoming.on("data", (chunk) => {
                received += chunk;
              });
              incoming.on("end", () =>
                resolve({ status: incoming.statusCode, body: received }),
              );
            },
          );
          outgoing.on("error", reject);
          outgoing.end(body);
        });

        expect(response.status).toBe(401);
        expect(response.body).toBe(
          JSON.stringify({ error: "Bridge authentication required" }),
        );
      }
      expect(client.listTools).not.toHaveBeenCalled();
      expect(client.callTool).not.toHaveBeenCalled();
    },
  );

  async function startAuthenticatedServer(session = "default") {
    const modulePath = "../src/bridge-auth.js";
    const { createBridgeAuth }: typeof import("../src/bridge-auth.js") =
      await import(modulePath);
    const client: BridgeClient = {
      listTools: vi.fn(async () => ({ tools: [{ name: "private-tool" }] })),
      callTool: vi.fn(async () => ({
        content: [{ type: "text", text: "private-result" }],
      })),
      close: async () => {},
    };
    const server = createBridgeServer(
      client,
      session,
      undefined,
      createBridgeAuth(SECRET),
    );
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    return { client, port: (server.address() as AddressInfo).port };
  }

  it.each(["default", "worker-1"])(
    "authenticates every route and its response in %s",
    async (session) => {
      const { port } = await startAuthenticatedServer(session);

      for (const path of ["/health", "/health?deep=1", "/tools", "/call"]) {
        const method = path === "/call" ? "POST" : "GET";
        const body =
          method === "POST"
            ? JSON.stringify({ name: "list_pages", args: {} })
            : "";
        const headers = requestHeaders(method, path, body);

        const response = await send(port, path, headers, body);

        expect(response.status).toBe(200);
        const [timestamp, nonce] = headers.authorization
          .slice("AXI-HMAC ".length)
          .split(".");
        const expectedProof = createHmac("sha256", Buffer.from(SECRET, "hex"))
          .update(
            ["response", timestamp, nonce, "200", response.body].join("\n"),
          )
          .digest("hex");
        expect(response.headers["x-chrome-devtools-axi-proof"]).toBe(
          expectedProof,
        );
        expect(response.body).not.toContain(SECRET);
      }
    },
  );

  it.each(["/health", "/health?deep=1", "/tools", "/call"])(
    "denies wrong credentials on %s before MCP access",
    async (path) => {
      const { client, port } = await startAuthenticatedServer();
      const method = path === "/call" ? "POST" : "GET";
      const body =
        method === "POST"
          ? JSON.stringify({ name: "list_pages", args: {} })
          : "";

      const response = await send(
        port,
        path,
        requestHeaders(method, path, body, "b".repeat(64)),
        body,
      );

      expect(response.status).toBe(401);
      expect(client.listTools).not.toHaveBeenCalled();
      expect(client.callTool).not.toHaveBeenCalled();
    },
  );

  it("rejects replayed authenticated calls", async () => {
    const { client, port } = await startAuthenticatedServer();
    const body = JSON.stringify({ name: "list_pages", args: {} });
    const headers = requestHeaders("POST", "/call", body);

    expect((await send(port, "/call", headers, body)).status).toBe(200);
    expect((await send(port, "/call", headers, body)).status).toBe(401);

    expect(client.callTool).toHaveBeenCalledTimes(1);
  });

  it("rejects tampered call bodies and route substitution", async () => {
    const { client, port } = await startAuthenticatedServer();
    const body = JSON.stringify({ name: "list_pages", args: {} });

    expect(
      (
        await send(
          port,
          "/call",
          requestHeaders("POST", "/call", body),
          JSON.stringify({ name: "navigate_page", args: {} }),
        )
      ).status,
    ).toBe(401);
    expect(
      (await send(port, "/tools", requestHeaders("GET", "/health"))).status,
    ).toBe(401);

    expect(client.listTools).not.toHaveBeenCalled();
    expect(client.callTool).not.toHaveBeenCalled();
  });

  it("binds the method and ambient activity header into request authentication", async () => {
    const { client, port } = await startAuthenticatedServer();

    expect(
      (await send(port, "/tools", requestHeaders("POST", "/tools"))).status,
    ).toBe(401);
    expect(
      (
        await send(port, "/health", {
          ...requestHeaders("GET", "/health"),
          "x-chrome-devtools-axi-ambient": "1",
        })
      ).status,
    ).toBe(401);

    expect(client.listTools).not.toHaveBeenCalled();
  });

  it("verifies response integrity, request identity and distinct MAC domains", async () => {
    const modulePath = "../src/bridge-auth.js";
    const { verifyResponse }: typeof import("../src/bridge-auth.js") =
      await import(modulePath);
    const { port } = await startAuthenticatedServer();
    const headers = requestHeaders("GET", "/health");

    const response = await send(port, "/health", headers);

    const proof = response.headers["x-chrome-devtools-axi-proof"];
    expect(
      verifyResponse(SECRET, headers.authorization, 200, response.body, proof),
    ).toBe(true);
    expect(
      verifyResponse(SECRET, headers.authorization, 503, response.body, proof),
    ).toBe(false);
    expect(
      verifyResponse(
        SECRET,
        headers.authorization,
        200,
        `${response.body} `,
        proof,
      ),
    ).toBe(false);
    expect(
      verifyResponse(
        SECRET,
        requestHeaders("GET", "/health").authorization,
        200,
        response.body,
        proof,
      ),
    ).toBe(false);
    expect(
      verifyResponse(
        SECRET,
        headers.authorization,
        200,
        response.body,
        headers.authorization.split(".").at(-1),
      ),
    ).toBe(false);
    expect(
      verifyResponse(
        SECRET,
        headers.authorization,
        200,
        response.body,
        undefined,
      ),
    ).toBe(false);
    expect(headers.authorization).not.toContain(SECRET);
  });

  it.each([-60_000, 60_000])(
    "rejects proofs outside the clock window (%s ms)",
    async (offset) => {
      const { client, port } = await startAuthenticatedServer();

      const response = await send(
        port,
        "/health",
        requestHeaders("GET", "/health", "", SECRET, Date.now() + offset),
      );

      expect(response.status).toBe(401);
      expect(client.listTools).not.toHaveBeenCalled();
    },
  );

  it("keeps Host and Origin enforcement without logging supplied secrets", async () => {
    const { port } = await startAuthenticatedServer();
    const write = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    const path = `/health?token=${SECRET}`;

    const response = await send(port, path, {
      ...requestHeaders("GET", path),
      host: "rebound.example",
      origin: "https://rebound.example",
    });

    expect(response.status).toBe(403);
    expect(response.body).not.toContain(SECRET);
    expect(
      write.mock.calls.map(([chunk]) => String(chunk)).join(""),
    ).not.toContain(SECRET);
  });
});
