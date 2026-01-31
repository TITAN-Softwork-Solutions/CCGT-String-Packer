# CCGT (Post-build string encryptor)

[![Discord](https://img.shields.io/discord/1240608336005828668?label=TITAN%20Softworks&logo=discord&color=5865F2&style=flat)](https://titansoftwork.com)

CCGT is a **post-build string protection tool** for **Windows x64 Binaries**.

It scans a compiled executable for eligible strings, encrypts them & writes a compact metadata table into a dedicated PE section (`.ccgtr`). At runtime, a lightweight header-only runtime (`ccgt_runtime.h`) decrypts those protected regions back into plaintext **before the program’s code uses them**.

This approach is designed to reduce the exposure of sensitive strings in static analysis workflows (e.g., `strings.exe`, YARA, bulk IOC extraction, and casual RE).

---

## Contents

* [What CCGT Is](#what-ccgt-is)
* [How It Works](#how-it-works)
* [Getting Started](#getting-started)

  * [1) Build the CLI tool](#1-build-the-cli-tool)
  * [2) Integrate runtime into a target project](#2-integrate-runtime-into-a-target-project)
  * [3) Patch the target binary](#3-patch-the-target-binary)
  * [4) Verify](#4-verify)
* [CLI Usage](#cli-usage)
* [Troubleshooting](#troubleshooting)

---

## What CCGT Is

**CCGT** is a two-part system:

1. **CCGT CLI (post-build patcher)**
   A command-line tool that:

   * scans an EXE for candidate strings
   * encrypts those bytes directly inside the file
   * writes a metadata table (regions + key material) into a dedicated section

2. **CCGT Runtime (in-binary decrypt shim)**
   A header-only runtime (`ccgt_runtime.h`) that:

   * defines the metadata section (`.ccgtr`)
   * runs automatically during process initialization
   * decrypts encrypted regions in-memory using the metadata

### Primary use cases

* Protecting sensitive identifiers embedded as string literals:

  * API endpoints, URLs, tokens, keys, auth strings
  * internal routes, feature flags, debug markers
  * error messages revealing architecture or detection logic
* Making static triage harder:

  * `strings.exe`, `floss`, naive regex harvesting
  * simple signature rules targeting plain `.rdata` strings

---

## How It Works

### Build-time (patch step)

1. **Scan the PE file**

   * locate candidate ASCII strings and their file offsets
   * validate length and null termination

2. **Verify candidates are safe to patch**

   * must belong to `.rdata` or `.data`
   * must not overlap PE directories (imports, resources, IAT, relocations, etc.)
   * must not be inside the `.ccgtr` meta section
   * must be within file bounds and outside headers

3. **Encrypt in-place**

   * algorithm: **ChaCha20-Poly1305 (AEAD)**
   * key: per-binary master key (32 bytes)
   * nonce: derived per region from `(seed, RVA)`
   * AAD: region metadata `(RVA, length, seed)`
   * result:

     * the original bytes at each string location are replaced with ciphertext bytes
     * a per-region Poly1305 authentication tag is generated

4. **Write metadata**

   * regions list: `{ RVA, length, seed, tag }` for each encrypted block
   * key material: stored as `frag ^ mask` components in `.ccgtr`
   * a signed SHA-256 hash of the on-disk file (signature field zeroed, Authenticode certificate table excluded) is generated and stored in `.ccgtr`
   * metadata is written into the `.ccgtr` section embedded into the target binary

### Runtime (decrypt step)

On process start (before `main()`), the runtime:

1. Locates its own module base.
2. Reads `.ccgtr` metadata (`g_meta`).
3. Reconstructs the master key from `frag ^ mask`.
4. For each region:

   * computes address from `base + RVA`
   * flips protection to RW via `VirtualProtect`
   * verifies and decrypts using ChaCha20-Poly1305

     * authentication covers ciphertext and region metadata
   * verifies a signed SHA-256 hash of the on-disk file before decryption
   * if authentication fails, the region is left encrypted
   * restores original protection

Result: string call sites remain valid and the program runs normally, but the on-disk binary no longer contains plaintext strings. Unauthorized file patching (outside the Authenticode certificate table) is detected at runtime.

---

## Getting Started

### 1) Build the CLI tool

* Toolchain: **MSVC**
* Language: **C++20**
* Platform: **x64**

Build `ccgt` as a normal console app.

### 2) Integrate runtime into a target project

In the project you want to protect:

1. Add `/include/*h` to your include path (all header files)
2. Include `/include/ccgt_runtime.h` it in one translation unit (recommended: your main file)

Example:

```cpp
#include "ccgt_runtime.h"
#include <iostream>

int main() {
    std::cout << "Hello from protected binary\n";
    return 0;
}
```

This causes the protected binary to contain a `.ccgtr` section with `g_meta`.

### 3) Patch the target binary

From the output directory containing your built executable:

```powershell
.\ccgt.exe .\<ExeToProtect>.exe
```

If you see `signing key not configured`, generate keys once and rebuild:

```powershell
.\ccgt.exe --gen-keys
```

### 4) Verify

Check that `.ccgtr` exists:

```powershell
dumpbin /headers .\prototype.exe
dumpbin /section:.ccgtr .\prototype.exe
```

Confirm plaintext strings are reduced:

```powershell
strings.exe .\prototype.exe | findstr /i "example.com"
```

---

## CLI Usage

```
usage:
  ccgt <binary.exe> [--scan] [--dry-run] [-v] [--min N] [--max N] [--no-backup]

notes:
  - default action is to PATCH (encrypt strings + write meta)
  - --scan prints findings only
```

### Options

* `--scan`
  Scan only, print candidate strings and offsets. No patching occurs.

* `--dry-run`
  Perform all checks and plan encryption, but do not write changes.

* `-v` / `--verbose`
  Print detailed logs (skips, decisions, region selections).

* `--min N` / `--max N`
  Clamp eligible string lengths.

* `--no-backup`
  Disable `.bak` creation.

---

## Troubleshooting

### "missing metadata section (.ccgtr / ccgt)"

Your target binary does no contain the `.ccgtr` section.

Fix:

* Ensure all header files from `/include/` are included in your project
* Ensure `/include/ccgt_runtime.h` in at least one translation unit that is linked
* Ensure the compiler/linker didn’t discard it

### "metadata section too small for Meta"

The `.ccgtr` section exists but is not large enough.

Fix:

* Do not shrink meta capacity
* Ensure `Meta` is allocated exactly as provided in the runtime header

### Patched binary crashes

Likely causes:

* encrypting bytes that are not safe to modify
* accidental overlap with structured PE regions
* runtime decrypt not running early enough

Fix:

* run with `--verbose` and inspect skip reasons
* tighten selection rules: require null termination, raise `min_len`
* validate runtime auto-init is linked (CRT initialization section present)

---

## Disclaimer

CCGT is intended for legitimate protection and defensive hardening. It is not a guarantee against reverse engineering or runtime analysis. It is designed to raise the cost of static extraction and reduce accidental exposure of sensitive strings in deployed binaries.
