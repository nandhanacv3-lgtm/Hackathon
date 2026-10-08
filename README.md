# LocalVault

A C11 command-line prototype for offline file and folder encryption. Uses
mbedTLS 3.6.5 for AES-256-GCM, random generation, and PBKDF2-HMAC-SHA256;
miniz 3.0.2 for ZIP archives. Dependency downloads are version- and SHA-256-pinned.

## Quick start on this Windows machine

Open a PowerShell terminal in this workspace:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1 -Test
.\build-clang\vault.exe --help
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\demo.ps1
```

The portable LLVM-MinGW compiler is already under `.dist/`; the build script
finds it automatically. CMake is installed. Internet is needed to obtain
dependencies on a first build, but encryption, decryption, tests, and the demo
run offline after building. Cached dependencies support subsequent offline builds.
The executable uses the Windows Universal C Runtime and statically linked crypto/archive libraries.

## Setup on another machine

Install CMake 3.20+ and a Windows MinGW-w64 C toolchain. For example, download
the official LLVM-MinGW **UCRT x86_64** ZIP from
<https://github.com/mstorsjo/llvm-mingw/releases>, unpack it into `.dist/`,
and run the build script above. Keep the extracted folder name `llvm-mingw-*`.
Alternatively, add its `bin` folder and `mingw32-make.exe` to PATH.

With Visual Studio Build Tools, use a Developer PowerShell:

```powershell
cmake -S . -B build-msvc
cmake --build build-msvc --config Release --target vault vault_tests
ctest --test-dir build-msvc -C Release --output-on-failure
```

Linux/macOS source paths are provided but have not been validated here:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target vault vault_tests -j 4
ctest --test-dir build --output-on-failure
```

mbedTLS's build may also need Python 3 for configuration/generation. Python is
not used by the application or its tests. Windows builds/tests were verified
with the portable LLVM-MinGW toolchain, not MSVC or Unix.

## Password mode

Create a small disposable file, then run:

```powershell
.\build-clang\vault.exe encrypt .\sample.txt --output .\sample.txt.enc
.\build-clang\vault.exe decrypt .\sample.txt.enc --output .\sample-restored.txt
Get-FileHash .\sample.txt, .\sample-restored.txt
```

Type the password directly in the terminal. Characters are not echoed.
Encryption asks for confirmation and requires at least 12 UTF-8 bytes; use a
long, unique passphrase, not merely the minimum. Passwords are not accepted in
arguments, environment variables, or redirected stdin. Password keys use a
fresh random 16-byte salt and 600,000 PBKDF2-HMAC-SHA256 iterations.

Wrong password: decryption fails with a nonzero exit code and does not publish
output. Test this using an unused destination. No password recovery is possible.

## Key-file mode

```powershell
.\build-clang\vault.exe keygen --output .\personal.key
.\build-clang\vault.exe encrypt .\sample.txt --output .\sample.enc --key-file .\personal.key
.\build-clang\vault.exe decrypt .\sample.enc --output .\restored.txt --key-file .\personal.key
```

Keys are exactly 32 random bytes, not textual passwords. New keys and temporary
files receive restricted Windows ACLs (owner rights and SYSTEM), or mode 0600
on Unix. Keep a protected backup somewhere separate from encrypted files.
Possession of the key allows decryption; losing it makes recovery impossible.
Do not publish or commit key files. Key-file rotation/re-encryption is manual.

## Folder mode

```powershell
.\build-clang\vault.exe encrypt-folder .\documents --output .\documents.enc --key-file .\personal.key
.\build-clang\vault.exe decrypt-folder .\documents.enc --output .\documents-restored --key-file .\personal.key
```

Without `--key-file`, these commands also prompt for a password. Encrypting a
folder archives its contents, including nested files and empty directories.
The archive itself is encrypted, hiding internal filenames. Contents and names
are preserved, not original ACLs, ownership, timestamps, or alternate data streams.
Do not change source files during an operation.

The encrypted output must be outside the source folder, and its parent must
already exist. Folder extraction requires a **new destination**; `--force` is
never allowed for folder extraction. Traversal/absolute/drive paths, Windows
reserved names, unsafe links and filesystem reparse points are rejected.
Limits: 10,000 entries, depth 32, 500-byte relative archive paths, 240-byte
components, and 4 GiB total uncompressed file data. ZIP overhead must also fit
the 4 GiB encrypted-payload limit. Standard Windows path limits still apply.

## Overwrite and failure behavior

- Existing output files are protected unless you explicitly add `--force`.
- Input/output aliases and attempts to overwrite the key file are rejected.
- New key files and destination folders cannot be overwritten.
- Authentication failure does not replace existing output, even with `--force`.
- Outputs are written privately next to the destination, then published by rename.
- Originals are never deleted by the tool.
- Graceful interruption removes unpublished temporary files/staging directories.
- Hard kills, crashes, or power loss can leave private `.vault-tmp-*` files/folders.

Exit codes: 0 success, 1 operation failure, 2 invalid arguments/protected output,
130 detected interruption. Check `$LASTEXITCODE` immediately after a command.

## Automated testing

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1 -Test
ctest --test-dir build-clang --output-on-failure
ctest --test-dir build-clang -V
```

Expected result: **2/2 CTest groups pass on Windows**.

| Test group | Checks |
| --- | --- |
| `vault_security_and_roundtrips` | Empty/1/15/16/17-byte and multi-buffer binary files; password key derivation and wrong passwords; CLI round-trips; wrong keys; modified header/salt/ciphertext/tag; truncation; invalid key sizes; Unicode paths; overwrite/alias protection; folders/empty folders; authenticated hostile ZIP paths and symlink attributes; simulated graceful cancellation and cleanup |
| `vault_process_and_acl` | Real executable key generation; restricted Windows key ACL; hard termination during a 1 GiB encryption; no partial final output; original preserved |

Fixtures are disposable. The C suite removes them on success; failed runs leave
their unique `vault-test.vault-tmp-*` folder in the build directory for inspection.
The process suite uses a disposable system-temp directory and deletes it afterward.
It needs enough storage for a 1 GiB test input. Do not run tests on valuable files.

The graceful-cancellation C test injects the interruption flag deterministically;
it does not claim to test OS console signal delivery. Wrong-password automated
tests exercise actual PBKDF2/GCM, not an automated interactive password prompt.

### Manual console checks

1. Encrypt using password mode: confirm typed characters stay hidden.
2. Enter different confirmation: expect failure and no output.
3. Decrypt with a wrong password: expect failure and no new output.
4. Decrypt with the correct password: compare SHA-256 using `Get-FileHash`.
5. Encrypt a large disposable file and press Ctrl+C while it is running.
   Expect nonzero exit, preserved input, no new final output, and temporary cleanup.
6. Repeat with an existing output plus `--force`; interrupt before completion.
   Compare the old output's hash before/after: it should be unchanged.
7. After a hard kill, inspect and remove only this run's leftover private temporary
   paths after confirming no Vault process is using them. Deletion is not secure erasure.

Password prompting and real Ctrl+C console handling require manual checks in
your terminal. Do not use real confidential data for these tests.

## Demo sequence

Run `scripts/demo.ps1` using the Quick start command. It creates its own unique
directory under `demo-output/` and demonstrates:

1. Random key generation.
2. File encryption/decryption with matching SHA-256 hashes.
3. Wrong-key rejection without publishing plaintext.
4. Refusal to overwrite an existing encrypted file.
5. Folder restoration, including binary/empty files and an empty directory.

Expected failure messages in steps 3 and 4 are intentional. For a presentation,
follow the scripted demo with password mode to show the hidden prompt, then
show `ctest` results. All demo keys/data are disposable.

## Version 1 file format

All integers are unsigned big-endian. The entire 56-byte header is authenticated
as GCM additional authenticated data.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | Magic: `LVAULT\r\n` |
| 8 | 1 | Format version: 1 |
| 9 | 1 | Cipher: 1 = AES-256-GCM |
| 10 | 1 | Key mode: 1 = PBKDF2-SHA256; 2 = raw key file |
| 11 | 1 | Payload: 0 = file; 1 = ZIP folder |
| 12 | 4 | KDF iterations; 0 for key-file mode |
| 16 | 16 | Fresh random salt |
| 32 | 12 | Fresh random GCM nonce |
| 44 | 8 | Plaintext payload length, at most 4 GiB |
| 52 | 4 | Reserved: zero |
| 56 | variable | Ciphertext, same length as plaintext |
| end - 16 | 16 | Authentication tag |

Decryption validates the exact file length, supported version/algorithm/mode,
reserved bytes, bounded KDF iterations (600,000 to 2,000,000), and tag. Fresh
96-bit random nonces make collisions unlikely, not mathematically impossible;
do not use this prototype for extreme-volume encryption under a single key.

## Security limits

This is a hackathon prototype, **not audited production security software**.
Review dependency security advisories and update pinned versions before real use.
Protect the machine and use trusted, local NTFS output directories on Windows.
Restricted ACLs cannot be guaranteed on filesystems that do not enforce them.
Treat destination parents as trusted: this is not hardened against a malicious
local user racing path changes. Unix directory publication has a check/rename
race and is not certified for hostile multi-user environments.

Decryption writes unauthenticated plaintext to a restricted temporary file, never
to the final destination; folder packing also uses a private plaintext ZIP.
Folder decryption needs private plaintext archive and staging storage. Allow
ample free disk space. Normal cleanup unlinks temporary data but does not securely
erase it. Root/admin access, malware, disk recovery, swap, crash dumps, sudden
power loss, and compromised endpoints are outside the protection offered here.
Use full-disk encryption as an additional layer when plaintext remnants matter.

## Source layout

- `src/main.c`: argument parsing and operation orchestration.
- `src/crypto.c`: authenticated file format, key derivation, streaming AES-GCM.
- `src/platform.c`: hidden prompts, Unicode Windows paths, private output, traversal.
- `src/archive.c`: miniz packing and constrained extraction.
- `tests/test_vault.c`: C security/round-trip checks.
- `tests/process-tests.ps1`: Windows process/permission checks.
- `scripts/build.ps1`, `scripts/demo.ps1`: repeatable build and presentation demo.