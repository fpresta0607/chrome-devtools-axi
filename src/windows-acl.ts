import { execFileSync } from "node:child_process";
import { join } from "node:path";

const ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
# The ACL modes call .NET directly, because every import lengthens every launch.
# Autoloading stays off: it searches the whole module path, including the user's
# modules, and when the caller's profile is redirected that search has no
# analysis cache and can take a minute.
$PSModuleAutoLoadingPreference = 'None'
function Assert-Owned([string]$path, [bool]$isDirectory, $sid) {
  $attributes = [System.IO.File]::GetAttributes($path)
  $isItemDirectory = ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0
  if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $isItemDirectory -ne $isDirectory) { throw 'Denied' }
  $security = if ($isDirectory) { [System.IO.Directory]::GetAccessControl($path) } else { [System.IO.File]::GetAccessControl($path) }
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
  $request = @([Console]::In.ReadToEnd().Split(' ') | ForEach-Object { [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($_)) })
  $mode = $request[0]
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  if ($mode -eq 'verify-process') {
    # Load only Windows PowerShell's own modules, by path. CimCmdlets calls
    # Set-Alias as it loads, so Utility goes first.
    foreach ($module in 'Microsoft.PowerShell.Utility', 'CimCmdlets') {
      Import-Module -Name "$PSHOME\Modules\$module"
    }
    $processId = [int]$request[1]
    $isBridge = $false
    $target = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $processId)
    if ($null -ne $target) {
      $owner = Invoke-CimMethod -InputObject $target -MethodName GetOwnerSid
      if ($owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace($owner.Sid)) { throw 'Denied' }
      if ($owner.Sid -eq $sid.Value) {
        if ([string]::IsNullOrWhiteSpace($target.ExecutablePath) -or [string]::IsNullOrWhiteSpace($target.CommandLine)) { throw 'Denied' }
        $listeners = @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetTCPConnection -Filter ('State = 2 AND LocalPort = ' + [int]$request[2] + ' AND OwningProcess = ' + $processId) | Where-Object { $_.LocalAddress -eq '127.0.0.1' })
        $isBridge = [System.IO.Path]::GetFileName([string]$target.ExecutablePath) -ieq 'node.exe' -and
          $target.CommandLine -match '(?i)(?:^|[\\/\s"''])chrome-devtools-axi-bridge\.(?:js|ts)(?:["''\s]|$)' -and
          $listeners.Count -gt 0
      }
    }
    [Console]::Out.Write($(if ($isBridge) { 'bridge' } else { 'other' }))
    exit 0
  }
  $null, $file, $paths = $request
  if ($file -and $mode -eq 'prepare-directory') {
    foreach ($path in $paths) { $null = Assert-Owned $path $true $sid }
    $null = Assert-Owned $file $false $sid
  }
  foreach ($path in $paths) {
    if ($mode -ne 'verify-directory') {
      $security = [System.Security.AccessControl.DirectorySecurity]::new()
      $security.SetAccessRuleProtection($true, $false)
      $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
      $security.AddAccessRule($rule)
      if ([System.IO.Directory]::Exists($path) -or [System.IO.File]::Exists($path)) {
        # Already owned, so write only the DACL: rewriting the owner needs
        # WRITE_OWNER, which an owner granted only Modify does not hold.
        $null = Assert-Owned $path $true $sid
        [System.IO.Directory]::SetAccessControl($path, $security)
      } else {
        $security.SetOwner($sid)
        [void][System.IO.Directory]::CreateDirectory($path, $security)
      }
    }
    Assert-Protected $path $true $sid
  }
  if ($file) {
    if ($mode -eq 'create-file') {
      [System.IO.File]::Open($file, [System.IO.FileMode]::CreateNew).Dispose()
    } elseif ($mode -eq 'prepare-directory') {
      $null = Assert-Owned $file $false $sid
      $security = [System.Security.AccessControl.FileSecurity]::new()
      $security.SetAccessRuleProtection($true, $false)
      $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow')
      $security.AddAccessRule($rule)
      [System.IO.File]::SetAccessControl($file, $security)
    }
    Assert-Protected $file $false $sid
  }
  [Console]::Out.Write('ok')
} catch {
  [Console]::Error.Write('Windows bridge access verification failed')
  exit 1
}
`;

function runWindowsVerification(fields: string[]): string {
  try {
    const systemRoot = process.env.SystemRoot;
    if (!systemRoot) throw new Error("Missing Windows system directory");
    // Windows PowerShell decodes redirected stdin with the OEM code page, so a
    // non-ASCII profile path must cross the pipe encoded, and its JSON cmdlet
    // would cost every launch a module import.
    const request = fields
      .map((field) => Buffer.from(field, "utf16le").toString("base64"))
      .join(" ");
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

/**
 * Secure `paths` and `file` in one launch. `prepare-directory` protects the
 * directories and an existing file, `create-file` protects the directories and
 * creates `file` empty, and `verify-directory` changes nothing. Each ends by
 * asserting what `verifyWindowsState` asserts, so a caller need not verify again.
 */
export function secureWindowsPaths(
  paths: string[],
  mode: "prepare-directory" | "create-file" | "verify-directory",
  file = "",
): void {
  if (runWindowsVerification([mode, file, ...paths]) !== "ok")
    throw new Error(
      "Windows bridge ACL or process ownership verification failed. Run stop, then start this session",
    );
}

/** Verify a session's state directories and its token file in one launch. */
export function verifyWindowsState(directories: string[], file: string): void {
  secureWindowsPaths(directories, "verify-directory", file);
}

/**
 * Whether `pid` is this user's AXI bridge listening on loopback `port`. False
 * means the pid now belongs to something else, so its state record is stale.
 * Throws when ownership cannot be determined.
 */
export function isWindowsBridgeProcess(pid: number, port: number): boolean {
  const verdict = runWindowsVerification([
    "verify-process",
    String(pid),
    String(port),
  ]);
  if (verdict !== "bridge" && verdict !== "other")
    throw new Error(
      "Windows bridge ACL or process ownership verification failed. Run stop, then start this session",
    );
  return verdict === "bridge";
}
