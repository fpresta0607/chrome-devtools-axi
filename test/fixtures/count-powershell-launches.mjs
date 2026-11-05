// Preloaded with `node --import` so a test can count the PowerShell launches of
// a real bridge process. Each launch appends one line to the file named by
// AXI_TEST_POWERSHELL_LAUNCH_LOG before it starts.
import childProcess from "node:child_process";
import { appendFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";

const { execFileSync } = childProcess;

childProcess.execFileSync = (file, ...rest) => {
  if (/powershell\.exe$/i.test(String(file)))
    appendFileSync(process.env.AXI_TEST_POWERSHELL_LAUNCH_LOG, "launch\n");
  return execFileSync(file, ...rest);
};
syncBuiltinESMExports();
