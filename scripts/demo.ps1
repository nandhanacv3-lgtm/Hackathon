$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$vault = Join-Path $root 'build-clang\vault.exe'
if (-not (Test-Path $vault)) { throw 'Build first: .\scripts\build.ps1 -Test' }
$work = Join-Path $root ('demo-output\run-' + [guid]::NewGuid().ToString('N'))
$folder = Join-Path $work 'documents'
[IO.Directory]::CreateDirectory((Join-Path $folder 'empty')) | Out-Null
[IO.File]::WriteAllText((Join-Path $folder 'report.txt'), 'LocalVault demo: documents stay local.')
[byte[]]$binary = 0..255
[IO.File]::WriteAllBytes((Join-Path $folder 'binary.bin'), $binary)
[IO.File]::WriteAllBytes((Join-Path $folder 'empty.bin'), [byte[]]@())
$key = Join-Path $work 'demo.key'
$badKey = Join-Path $work 'wrong.key'
function Invoke-Vault([string[]]$Arguments) {
    & $vault @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Demo command failed.' }
}
Invoke-Vault @('keygen', '--output', $key)
Invoke-Vault @('keygen', '--output', $badKey)
$source = Join-Path $folder 'report.txt'
$encrypted = Join-Path $work 'report.enc'
$restored = Join-Path $work 'report-restored.txt'
Invoke-Vault @('encrypt', $source, '--output', $encrypted, '--key-file', $key)
Invoke-Vault @('decrypt', $encrypted, '--output', $restored, '--key-file', $key)
if ((Get-FileHash $source).Hash -ne (Get-FileHash $restored).Hash) { throw 'File hashes differ.' }
Write-Output 'PASS: original and restored file hashes match.'
& $vault decrypt $encrypted --output (Join-Path $work 'must-not-exist.txt') --key-file $badKey
if ($LASTEXITCODE -eq 0 -or (Test-Path (Join-Path $work 'must-not-exist.txt'))) { throw 'Wrong-key protection failed.' }
Write-Output 'PASS: wrong key rejected; no plaintext published.'
& $vault encrypt $source --output $encrypted --key-file $key
if ($LASTEXITCODE -eq 0) { throw 'Overwrite protection failed.' }
Write-Output 'PASS: existing encrypted file protected.'
$archive = Join-Path $work 'documents.enc'
$restoredFolder = Join-Path $work 'documents-restored'
Invoke-Vault @('encrypt-folder', $folder, '--output', $archive, '--key-file', $key)
Invoke-Vault @('decrypt-folder', $archive, '--output', $restoredFolder, '--key-file', $key)
foreach ($file in Get-ChildItem $folder -File) {
    if ((Get-FileHash $file.FullName).Hash -ne (Get-FileHash (Join-Path $restoredFolder $file.Name)).Hash) { throw 'Folder hashes differ.' }
}
if (-not (Test-Path (Join-Path $restoredFolder 'empty') -PathType Container)) { throw 'Empty directory not restored.' }
Write-Output 'PASS: folder files and empty directory restored.'
Write-Output "Demo artifacts: $work"
Write-Output 'The generated demo keys are disposable. Do not use them for real confidential documents.'