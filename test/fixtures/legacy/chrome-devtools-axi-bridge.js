import { createServer } from "node:net";

const server = createServer().listen(0, "127.0.0.1", () => {
  process.stdout.write(`${server.address().port}\n`);
});
