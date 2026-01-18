# CCGT (Post-build string encryptor)

CCGT is a **post-build string protection tool** for **Windows x64 Binaries**.

It scans a compiled executable for eligible strings, encrypts them & writes a compact metadata table into a dedicated PE section (`.ccgtr`). At runtime, a lightweight header-only runtime (`ccgt_runtime.h`) decrypts those protected regions back into plaintext **before the program’s code uses them**.

This approach is designed to reduce the exposure of sensitive strings in static analysis workflows (e.g., `strings.exe`, YARA, bulk IOC extraction, and casual RE).

---

## Contents

* [What CCGT Is](#what-ccgt-is)
* [How It Works](#how-it-works)
* [Project Layout](#project-layout)
* [Getting Started](#getting-started)

  * [1) Build the CLI tool](#1-build-the-cli-tool)
  * [2) Integrate runtime into a target project](#2-integrate-runtime-into-a-target-project)
  * [3) Patch the target binary](#3-patch-the-target-binary)
  * [4) Verify](#4-verify)
* [CLI Usage](#cli-usage)
* [What Gets Encrypted](#what-gets-encrypted)
* [Security & Robustness Notes](#security--robustness-notes)
* [Operational Guidance](#operational-guidance)
* [Troubleshooting](#troubleshooting)
* [Limitations](#limitations)
* [How It’s Made](#how-its-made)
* [License](#license)

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

   * algorithm: **ChaCha20**
   * key: per-binary master key (32 bytes)
   * nonce: derived per region from `(seed, RVA)`
   * result: the original bytes at each string location are replaced with ciphertext bytes

4. **Write metadata**

   * regions list: `{ RVA, length, seed }` for each encrypted block
   * key material: stored as `frag ^ mask` components in `.ccgtr`
   * metadata is written into the `.ccgtr` section embedded into the target binary

### Runtime (decrypt step)

On process start (before `main()`), the runtime:

1. Locates its own module base.
2. Reads `.ccgtr` metadata (`g_meta`).
3. Reconstructs the master key from `frag ^ mask`.
4. For each region:

   * computes address from `base + RVA`
   * flips protection to RW via `VirtualProtect`
   * decrypts with ChaCha20 using matching nonce derivation
   * restores original protection

Result: string call sites remain valid and the program runs normally, but the on-disk binary no longer contains plaintext strings.

---

## Getting Started

### 1) Build the CLI tool

* Toolchain: **MSVC**
* Language: **C++20**
* Platform: **x64**

Build `ccgt` as a normal console app.

### 2) Integrate runtime into a target project

In the project you want to protect:

1. Add `ccgt_runtime.h` to your include path
2. Include it in exactly one translation unit (recommended: your main file)

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

Your target binary does not contain the `.ccgtr` section.

Fix:

* Ensure `ccgt_runtime.h` is included by the target project
* Ensure it’s included in at least one translation unit that is linked
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
