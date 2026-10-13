import { createServer } from "node:http";

const server = createServer((_request, response) => response.end("{}")).listen(
  0,
  "127.0.0.1",
  () => {
    process.stdout.write(`${server.address().port}\n`);
  },
);
