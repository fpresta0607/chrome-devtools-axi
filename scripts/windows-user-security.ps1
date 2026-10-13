[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne 'fpresta0607/chrome-devtools-axi') {
    throw 'This proof may run only on the fork GitHub-hosted Windows runner.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The hosted runner must be elevated to create temporary standard users.'
}

$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$node = (Get-Command node.exe).Source
$fixture = Join-Path $PSScriptRoot 'windows-user-security-fixture.mjs'
$publicRoot = [IO.Path]::GetFullPath($env:PUBLIC)
$proofRoot = Join-Path $publicRoot ('axi-user-proof-' + [guid]::NewGuid().ToString('N'))
$users = @()
$processes = @()
$isProofPassed = $false

function Wait-ProofProcess($Process, [int]$TimeoutMilliseconds) {
    if (-not $Process.WaitForExit($TimeoutMilliseconds)) {
        throw "Proof process $($Process.Id) timed out."
    }
    $Process.Refresh()
    if ($Process.ExitCode -ne 0) {
        throw "Proof process $($Process.Id) exited with code $($Process.ExitCode)."
    }
}

try {
    & icacls.exe $repository /grant '*S-1-5-32-545:(OI)(CI)RX' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant proof users read access to the checkout.' }
    New-Item -ItemType Directory -Path $proofRoot | Out-Null
    $rootAcl = Get-Acl -LiteralPath $proofRoot
    $rootAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($identity.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),
        'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $proofRoot -AclObject $rootAcl

    $credentials = @{}
    foreach ($role in @('owner', 'alternate')) {
        $username = 'axi' + $role.Substring(0, 3) + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $password = ConvertTo-SecureString ('aA1!' + [Convert]::ToHexString(
            [Security.Cryptography.RandomNumberGenerator]::GetBytes(32))) -AsPlainText -Force
        $user = New-LocalUser -Name $username -Password $password -AccountNeverExpires
        $users += $user
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
        $credentials[$role] = [PSCredential]::new("$env:COMPUTERNAME\$username", $password)
        $outputDirectory = Join-Path $proofRoot ($role + '-output')
        New-Item -ItemType Directory -Path $outputDirectory | Out-Null
        $outputAcl = Get-Acl -LiteralPath $outputDirectory
        $outputAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $user.SID, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        Set-Acl -LiteralPath $outputDirectory -AclObject $outputAcl
    }
    $ownerHome = Join-Path $proofRoot 'owner-home'
    New-Item -ItemType Directory -Path $ownerHome | Out-Null
    $homeAcl = Get-Acl -LiteralPath $ownerHome
    $homeAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $users[0].SID, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $ownerHome -AclObject $homeAcl
    Set-Content -LiteralPath (Join-Path $ownerHome 'readable-control') -Value 'control' -NoNewline

    foreach ($role in @('owner', 'alternate')) {
        $userIndex = if ($role -eq 'owner') { 0 } else { 1 }
        $arguments = @($fixture, $role, $repository, $proofRoot, $users[$userIndex].SID.Value)
        $quotedArguments = $arguments | ForEach-Object { '"' + $_ + '"' }
        $process = Start-Process -FilePath $node -ArgumentList $quotedArguments -Credential $credentials[$role] `
            -LoadUserProfile -WorkingDirectory $proofRoot -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $proofRoot "$role.stdout") `
            -RedirectStandardError (Join-Path $proofRoot "$role.stderr")
        $processes += $process
        Write-Host "$role proof pid=$($process.Id) sid=$($users[$userIndex].SID.Value)"
        if ($role -eq 'owner') {
            $readyFile = Join-Path $proofRoot 'owner-output\ready.json'
            $deadline = [DateTime]::UtcNow.AddSeconds(60)
            while (-not (Test-Path -LiteralPath $readyFile)) {
                if ($process.HasExited) { throw 'Owner fixture exited before readiness.' }
                if ([DateTime]::UtcNow -ge $deadline) { throw 'Owner fixture readiness timed out.' }
                Start-Sleep -Milliseconds 200
            }
        } else {
            Wait-ProofProcess $process 60000
        }
    }
    Set-Content -LiteralPath (Join-Path $proofRoot 'finish') -Value 'finish'
    Wait-ProofProcess $processes[0] 15000
    $result = Get-Content -LiteralPath (Join-Path $proofRoot 'alternate-output\result.json') -Raw | ConvertFrom-Json
    if ($result.secretReadsDenied -ne 2 -or $result.observations.Count -ne 16) {
        throw 'The alternate-user proof did not complete every assertion.'
    }
    $result | ConvertTo-Json -Depth 5
    $isProofPassed = $true
} finally {
    $cleanupErrors = @()
    $childrenFile = Join-Path $proofRoot 'owner-output\children.json'
    $childProcessIds = @()
    if (Test-Path -LiteralPath $childrenFile) {
        $childProcessIds = @(Get-Content -LiteralPath $childrenFile -Raw | ConvertFrom-Json)
    }
    $fixtureProcessIds = @($processes | ForEach-Object { $_.Id })
    $childProcessIds = @(foreach ($childProcessId in $childProcessIds) {
        $childProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $childProcessId"
        if ($childProcess -and $childProcess.ParentProcessId -in $fixtureProcessIds) {
            $childProcessId
        }
    })
    $ownedProcessIds = @($processes | Where-Object { -not $_.HasExited } | ForEach-Object { $_.Id }) + $childProcessIds
    $descendantProcessIds = @()
    $parents = $ownedProcessIds
    for ($depth = 0; $depth -lt 8 -and $parents.Count -gt 0; $depth++) {
        $children = @(foreach ($parentId in $parents) {
            Get-CimInstance Win32_Process -Filter "ParentProcessId = $parentId" |
                Select-Object -ExpandProperty ProcessId
        })
        $descendantProcessIds += $children
        $parents = $children
    }
    foreach ($process in $processes) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue -ErrorVariable +cleanupErrors
            if (-not $process.WaitForExit(5000)) { $cleanupErrors += "Process $($process.Id) survived cleanup." }
        }
        $process.Dispose()
    }
    foreach ($processId in ($childProcessIds + $descendantProcessIds | Select-Object -Unique)) {
        if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue -ErrorVariable +cleanupErrors
        }
    }
    foreach ($role in @('owner', 'alternate')) {
        $stdout = Join-Path $proofRoot "$role.stdout"
        if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout }
        $stderr = Join-Path $proofRoot "$role.stderr"
        if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr }
    }
    foreach ($user in $users) {
        Get-CimInstance Win32_UserProfile -Filter "SID = '$($user.SID.Value)'" |
            Remove-CimInstance -ErrorAction SilentlyContinue -ErrorVariable +cleanupErrors
        Remove-LocalUser -SID $user.SID -ErrorAction SilentlyContinue -ErrorVariable +cleanupErrors
    }
    if (Test-Path -LiteralPath $proofRoot) {
        $resolvedProofRoot = (Resolve-Path -LiteralPath $proofRoot).Path
        if (-not $resolvedProofRoot.StartsWith($publicRoot.TrimEnd('\') + '\axi-user-proof-',
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing cleanup outside the isolated proof directory.'
        }
        # A failed owner fixture may leave owner-only ACLs that the runner must reclaim.
        & takeown.exe /F $resolvedProofRoot /R /D Y | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not reclaim the isolated proof directory.' }
        & icacls.exe $resolvedProofRoot /grant "*$($identity.User.Value):(OI)(CI)F" /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not grant cleanup access to the isolated proof directory.' }
        Remove-Item -LiteralPath $resolvedProofRoot -Recurse -Force
    }
    if ($cleanupErrors.Count -gt 0) { throw "Proof cleanup had $($cleanupErrors.Count) failures." }
}
if ($isProofPassed) {
    Write-Host 'PASS: two standard Windows users, two protected sessions, owner CLI, all bridge routes, and cleanup.'
}
