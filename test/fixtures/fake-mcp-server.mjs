// A stand-in for chrome-devtools-mcp over stdio, for tests that run the real
// bridge process without a browser. It answers `list_pages` (the deep health
// probe) and writes its own pid to $HOME/fake-mcp.pid so a test can end it the
// way a crashed or killed chrome-devtools-mcp would end. HOME is used because
// the stdio transport passes the server only a default set of variables.
// Bridge-supplied launch flags (--isolated, --headless, ...) are ignored.
import { writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { RootsListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new McpServer({
  name: "fake-chrome-devtools-mcp",
  version: "0.0.0",
});
server.server.setNotificationHandler(
  RootsListChangedNotificationSchema,
  async () => {
    await server.server.listRoots();
  },
);
server.registerTool("list_pages", { description: "List pages" }, async () => ({
  content: [{ type: "text", text: "## Pages\n1: about:blank [selected]" }],
}));

await server.connect(new StdioServerTransport());
writeFileSync(join(homedir(), "fake-mcp.pid"), String(process.pid));
