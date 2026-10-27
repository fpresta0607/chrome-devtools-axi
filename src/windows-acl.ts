import { execFileSync } from "node:child_process";
import { join } from "node:path";

const ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
function Assert-Owned([string]$path, [bool]$isDirectory, $sid) {
  $item = Get-Item -Force -LiteralPath $path
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer -ne $isDirectory) { throw 'Denied' }
  $security = Get-Acl -LiteralPath $path
  if ($security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Denied' }
  return $security
}
function Assert-Protected([string]$path, [bool]$isDirectory, $sid) {
  $security = Assert-Owned $path $isDirectory $sid
  $allowed = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')
  $rules = $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
  if ($rules.Count -eq 0) { throw 'Denied' }
  foreach ($rule in $rules) {
    if ($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $rule.IdentityReference.Value) { throw 'Denied' }
  }
}
try {
  $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  if ($request.mode -eq 'verify-process') {
    $processId = [int]$request.pid
    $isBridge = $false
    $target = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $processId)
    if ($null -ne $target) {
      $owner = Invoke-CimMethod -InputObject $target -MethodName GetOwnerSid
      if ($owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace($owner.Sid)) { throw 'Denied' }
      if ($owner.Sid -eq $sid.Value) {
        if ([string]::IsNullOrWhiteSpace($target.ExecutablePath) -or [string]::IsNullOrWhiteSpace($target.CommandLine)) { throw 'Denied' }
        $listeners = @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetTCPConnection -Filter ('State = 2 AND LocalPort = ' + [int]$request.port + ' AND OwningProcess = ' + $processId) | Where-Object { $_.LocalAddress -eq '127.0.0.1' })
        $isBridge = [System.IO.Path]::GetFileName([string]$target.ExecutablePath) -ieq 'node.exe' -and
          $target.CommandLine -match '(?i)(?:^|[\\/\s"''])chrome-devtools-axi-bridge\.(?:js|ts)(?:["''\s]|$)' -and
          $listeners.Count -gt 0
      }
    }
    [Console]::Out.Write($(if ($isBridge) { 'bridge' } else { 'other' }))
    exit 0
  }
  if ($request.file -and $request.mode -eq 'prepare-directory') {
    foreach ($path in $request.paths) { $null = Assert-Owned $path $true $sid }
    $null = Assert-Owned $request.file $false $sid
  }
  foreach ($path in $request.paths) {
    if ($request.mode -eq 'prepare-directory') {
      $security = New-Object System.Security.AccessControl.DirectorySecurity
      $security.SetAccessRuleProtection($true, $false)
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
      $security.AddAccessRule($rule)
      if (Test-Path -LiteralPath $path) {
        # Already owned, so write only the DACL: rewriting the owner needs
        # WRITE_OWNER, which an owner granted only Modify does not hold.
        $null = Assert-Owned $path $true $sid
        [System.IO.Directory]::SetAccessControl($path, $security)
      } else {
        $security.SetOwner($sid)
        [void][System.IO.Directory]::CreateDirectory($path, $security)
      }
    }
    Assert-Protected $path ($request.mode -ne 'verify-file') $sid
  }
  if ($request.file) {
    if ($request.mode -eq 'prepare-directory') {
      $null = Assert-Owned $request.file $false $sid
      $security = New-Object System.Security.AccessControl.FileSecurity
      $security.SetAccessRuleProtection($true, $false)
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
      $security.AddAccessRule($rule)
      [System.IO.File]::SetAccessControl($request.file, $security)
    }
    Assert-Protected $request.file $false $sid
  }
  [Console]::Out.Write('ok')
} catch {
  [Console]::Error.Write('Windows bridge access verification failed')
  exit 1
}
`;

function runWindowsVerification(input: object): string {
  try {
    const systemRoot = process.env.SystemRoot;
    if (!systemRoot) throw new Error("Missing Windows system directory");
    // Windows PowerShell decodes redirected stdin with the OEM code page, so a
    // non-ASCII profile path must cross the pipe as JSON escapes.
    const request = JSON.stringify(input).replace(
      /[^\x20-\x7e]/g,
      (character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
    return execFileSync(
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
        // Let Windows PowerShell rebuild its own module path after a pwsh parent.
        env: Object.fromEntries(
          Object.entries(process.env).filter(
            ([name]) => name.toUpperCase() !== "PSMODULEPATH",
          ),
        ),
        input: request,
        encoding: "utf8",
        // WMI process and socket queries can take several seconds on a loaded
        // machine.
        timeout: 30_000,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      },
    ).trim();
  } catch {
    throw new Error(
      "Windows bridge ACL or process ownership verification failed. Run stop, then start this session",
    );
  }
}

function verifyWindowsAccess(input: object): void {
  if (runWindowsVerification(input) !== "ok")
    throw new Error(
      "Windows bridge ACL or process ownership verification failed. Run stop, then start this session",
    );
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
  file?: string,
): void {
  verifyWindowsAccess({ paths, mode, file });
}

/** Verify a session's state directories and its token file in one launch. */
export function verifyWindowsState(directories: string[], file: string): void {
  verifyWindowsAccess({ paths: directories, mode: "verify-directory", file });
}

/**
 * Whether `pid` is this user's AXI bridge listening on loopback `port`. False
 * means the pid now belongs to something else, so its state record is stale.
 * Throws when ownership cannot be determined.
 */
export function isWindowsBridgeProcess(pid: number, port: number): boolean {
  const verdict = runWindowsVerification({ pid, port, mode: "verify-process" });
  if (verdict !== "bridge" && verdict !== "other")
    throw new Error(
      "Windows bridge ACL or process ownership verification failed. Run stop, then start this session",
    );
  return verdict === "bridge";
}
