param([switch]$Test)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$build = Join-Path $root 'build-clang'
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) { throw 'Install CMake 3.20 or newer and add it to PATH.' }
$toolchain = Get-ChildItem (Join-Path $root '.dist') -Directory -Filter 'llvm-mingw-*' -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName 'bin\clang.exe') } | Sort-Object Name -Descending | Select-Object -First 1
if ($toolchain) {
    $bin = Join-Path $toolchain.FullName 'bin'
    $env:PATH = "$bin;$env:PATH"
    $compiler = Join-Path $bin 'clang.exe'
    $make = Join-Path $bin 'mingw32-make.exe'
} else {
    $clang = Get-Command clang -ErrorAction SilentlyContinue
    $gcc = Get-Command gcc -ErrorAction SilentlyContinue
    $makeCommand = Get-Command mingw32-make -ErrorAction SilentlyContinue
    if (-not $makeCommand -or (-not $clang -and -not $gcc)) {
        throw 'Install LLVM-MinGW or MinGW-w64. See README.md. This script expects a MinGW Windows toolchain.'
    }
    $compiler = if ($clang) { $clang.Source } else { $gcc.Source }
    $make = $makeCommand.Source
}
& cmake -S $root -B $build -G 'MinGW Makefiles' "-DCMAKE_C_COMPILER=$compiler" "-DCMAKE_MAKE_PROGRAM=$make" '-DCMAKE_BUILD_TYPE=Release'
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
& cmake --build $build --target vault vault_tests -j 4
if ($LASTEXITCODE -ne 0) { throw 'C compilation failed.' }
if ($Test) {
    & ctest --test-dir $build --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Automated tests failed.' }
}
Write-Output "Ready: $build\vault.exe"