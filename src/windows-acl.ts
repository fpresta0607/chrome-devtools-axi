import { execFileSync } from "node:child_process";
import { join } from "node:path";

const ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
try {
  $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  if ($request.mode -eq 'verify-process') {
    $target = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + [int]$request.pid)
    if ($null -eq $target) { throw 'Denied' }
    $owner = Invoke-CimMethod -InputObject $target -MethodName GetOwnerSid
    if ($owner.ReturnValue -ne 0 -or $owner.Sid -ne $sid.Value) { throw 'Denied' }
    if ([System.IO.Path]::GetFileName($target.ExecutablePath) -ine 'node.exe') { throw 'Denied' }
    if ($target.CommandLine -notmatch '(?i)(?:^|[\\/\s"''])chrome-devtools-axi-bridge\.(?:js|ts)(?:["''\s]|$)') { throw 'Denied' }
    [Console]::Out.Write('ok')
    exit 0
  }
  foreach ($path in $request.paths) {
    $isDirectory = $request.mode -ne 'verify-file'
    if ($request.mode -eq 'prepare-directory') {
      $security = New-Object System.Security.AccessControl.DirectorySecurity
      $security.SetOwner($sid)
      $security.SetAccessRuleProtection($true, $false)
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
      $security.AddAccessRule($rule)
      if (Test-Path -LiteralPath $path) {
        $item = Get-Item -Force -LiteralPath $path
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $item.PSIsContainer) { throw 'Denied' }
        $existing = Get-Acl -LiteralPath $path
        if ($existing.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Denied' }
        [System.IO.Directory]::SetAccessControl($path, $security)
      } else {
        [void][System.IO.Directory]::CreateDirectory($path, $security)
      }
    }
    $item = Get-Item -Force -LiteralPath $path
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer -ne $isDirectory) { throw 'Denied' }
    $security = Get-Acl -LiteralPath $path
    if ($security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Denied' }
    $allowed = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')
    $rules = $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    if ($rules.Count -eq 0) { throw 'Denied' }
    foreach ($rule in $rules) {
      if ($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $rule.IdentityReference.Value) { throw 'Denied' }
    }
  }
  [Console]::Out.Write('ok')
} catch {
  [Console]::Error.Write('Windows bridge access verification failed')
  exit 1
}
`;

function verifyWindowsAccess(input: object): void {
  try {
    const systemRoot = process.env.SystemRoot;
    if (!systemRoot) throw new Error("Missing Windows system directory");
    const result = execFileSync(
      join(
        systemRoot,
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      ),
      [
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        Buffer.from(ACL_SCRIPT, "utf16le").toString("base64"),
      ],
      {
        input: JSON.stringify(input),
        encoding: "utf8",
        timeout: 10_000,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    if (result.trim() !== "ok")
      throw new Error("Invalid Windows verification result");
  } catch {
    throw new Error(
      "Windows bridge ACL or process ownership verification failed",
    );
  }
}

export function secureWindowsPath(
  path: string,
  mode: "prepare-directory" | "verify-directory" | "verify-file",
): void {
  secureWindowsPaths([path], mode);
}

export function secureWindowsPaths(
  paths: string[],
  mode: "prepare-directory" | "verify-directory" | "verify-file",
): void {
  verifyWindowsAccess({ paths, mode });
}

export function verifyWindowsBridgeProcess(pid: number): void {
  verifyWindowsAccess({ pid, mode: "verify-process" });
}
