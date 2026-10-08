param([Parameter(Mandatory = $true)][string]$Vault)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
public static class VaultInterruptTest {
    public static bool StartAndKill(Process process, string directory) {
        Directory.GetFiles(directory, "*.vault-tmp-*");
        if (!process.Start()) throw new Exception("Cannot start vault");
        var watch = Stopwatch.StartNew();
        while (!process.HasExited && watch.Elapsed.TotalSeconds < 15) {
            if (Directory.GetFiles(directory, "*.vault-tmp-*").Length == 0) continue;
            process.Kill();
            process.WaitForExit();
            return true;
        }
        return false;
    }
}
'@
$Vault = (Resolve-Path $Vault).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ('vault-process-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work) | Out-Null
function Assert-True([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "FAIL: $Label" }
    Write-Output "PASS: $Label"
}
try {
    $key = Join-Path $work 'demo.key'
    & $Vault keygen --output $key
    Assert-True ($LASTEXITCODE -eq 0 -and (Get-Item $key).Length -eq 32) 'executable key generation'
    $acl = Get-Acl $key
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $allowed = @('S-1-3-4', 'S-1-5-18', $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)
    $unexpected = @($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $allowed })
    Assert-True ($acl.AreAccessRulesProtected -and $unexpected.Count -eq 0) 'key file has restricted, non-inherited Windows ACL'
    $inputFile = Join-Path $work 'large.bin'
    $stream = [IO.File]::Create($inputFile)
    $stream.SetLength(1024L * 1024 * 1024)
    $stream.Dispose()
    $cipher = Join-Path $work 'cancelled.enc'
    $process = New-Object Diagnostics.Process
    $process.StartInfo.FileName = $Vault
    $process.StartInfo.Arguments = 'encrypt "{0}" --output "{1}" --key-file "{2}"' -f $inputFile, $cipher, $key
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    Assert-True ([VaultInterruptTest]::StartAndKill($process, $work)) 'hard-kill during private temporary-output creation'
    Assert-True (-not (Test-Path $cipher)) 'forced termination never publishes partial output'
    Assert-True ((Get-Item $inputFile).Length -eq 1024L * 1024 * 1024) 'forced termination preserves original input'
    Write-Output 'Note: forced termination may leave restricted temporary files; cleanup occurs in this disposable test directory.'
} finally {
    if ($process -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}