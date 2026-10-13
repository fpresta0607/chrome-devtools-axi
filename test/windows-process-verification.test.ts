import { execFileSync } from "node:child_process";
import { afterEach, describe, expect, it, vi } from "vitest";
import { isWindowsBridgeProcess } from "../src/windows-acl.js";

vi.mock("node:child_process", async (importOriginal) => {
  const childProcess =
    await importOriginal<typeof import("node:child_process")>();
  return { ...childProcess, execFileSync: vi.fn(childProcess.execFileSync) };
});

describe.runIf(process.platform === "win32")(
  "Windows process verification failures",
  () => {
    afterEach(() => vi.mocked(execFileSync).mockRestore());

    it.each([
      {
        name: "access denied",
        owner: "@{ ReturnValue = 2 }",
        target: "bridge",
        listener: "loopback",
        verdict: "error",
      },
      {
        name: "insufficient privilege",
        owner: "@{ ReturnValue = 3 }",
        target: "bridge",
        listener: "loopback",
        verdict: "error",
      },
      {
        name: "unknown owner failure",
        owner: "@{ ReturnValue = 8 }",
        target: "bridge",
        listener: "loopback",
        verdict: "error",
      },
      {
        name: "missing owner SID",
        owner: "@{ ReturnValue = 0 }",
        target: "bridge",
        listener: "loopback",
        verdict: "error",
      },
      {
        name: "failed owner query",
        owner: "throw 'CIM unavailable'",
        target: "bridge",
        listener: "loopback",
        verdict: "error",
      },
      {
        name: "failed process query",
        owner: "@{ ReturnValue = 0; Sid = $sid.Value }",
        target: "error",
        listener: "loopback",
        verdict: "error",
      },
      {
        name: "missing process fields",
        owner: "@{ ReturnValue = 0; Sid = $sid.Value }",
        target: "incomplete",
        listener: "loopback",
        verdict: "error",
      },
      {
        name: "failed listener query",
        owner: "@{ ReturnValue = 0; Sid = $sid.Value }",
        target: "bridge",
        listener: "error",
        verdict: "error",
      },
      {
        name: "confirmed owner mismatch",
        owner: "@{ ReturnValue = 0; Sid = 'S-1-5-18' }",
        target: "incomplete",
        listener: "loopback",
        verdict: "other",
      },
      {
        name: "confirmed bridge",
        owner: "@{ ReturnValue = 0; Sid = $sid.Value }",
        target: "bridge",
        listener: "loopback",
        verdict: "bridge",
      },
    ])(
      "fails closed or identifies a $name",
      async ({ owner, target, listener, verdict }) => {
        const childProcess =
          await vi.importActual<typeof import("node:child_process")>(
            "node:child_process",
          );
        const boundary = `
function Get-CimInstance {
  param($ClassName, $Namespace, $Filter)
  if ($ClassName -eq 'Win32_Process') {
    ${target === "error" ? "throw 'CIM unavailable'" : target === "incomplete" ? "[pscustomobject]@{ ProcessId = 123 }" : "[pscustomobject]@{ ExecutablePath = 'C:\\node.exe'; CommandLine = 'node.exe C:\\chrome-devtools-axi-bridge.js' }"}
  } else {
    ${listener === "error" ? "throw 'CIM unavailable'" : "[pscustomobject]@{ LocalAddress = '127.0.0.1' }"}
  }
}
function Invoke-CimMethod {
  param($InputObject, $MethodName)
  ${owner}
}
`;
        vi.mocked(execFileSync).mockImplementationOnce(
          (file, args, options) => {
            if (!Array.isArray(args))
              throw new Error("Expected PowerShell arguments");
            const index = args.indexOf("-EncodedCommand") + 1;
            const script = Buffer.from(args[index], "base64").toString(
              "utf16le",
            );
            const injected = [...args];
            injected[index] = Buffer.from(
              boundary + script,
              "utf16le",
            ).toString("base64");
            return childProcess.execFileSync(file, injected, options);
          },
        );

        if (verdict === "error") {
          expect(() => isWindowsBridgeProcess(123, 9224)).toThrow(
            /verification failed/,
          );
        } else {
          expect(isWindowsBridgeProcess(123, 9224)).toBe(verdict === "bridge");
        }
      },
    );
  },
);
