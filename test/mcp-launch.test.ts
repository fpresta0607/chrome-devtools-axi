import childProcess from "node:child_process";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { describe, expect, it, vi } from "vitest";

describe.runIf(process.platform === "win32")("Windows MCP child launch", () => {
  it("hides the MCP console without an Electron host and closes its owned child", async () => {
    const originalSpawn = childProcess.spawn;
    const launch = vi
      .spyOn(childProcess, "spawn")
      .mockImplementation((command, args, options) =>
        originalSpawn(command, args, { ...options, windowsHide: true }),
      );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ["-e", "process.stdin.resume()"],
    });
    try {
      await transport.start();

      const options = launch.mock.calls[0]?.[2];
      expect(options?.windowsHide).toBe(true);
      expect(options?.shell).toBe(false);
      expect(transport.pid).toBeTypeOf("number");
    } finally {
      await transport.close();
      launch.mockRestore();
    }
    expect(transport.pid).toBeNull();
  });
});
