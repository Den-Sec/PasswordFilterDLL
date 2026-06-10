<div align="center">

# 🛡️ PasswordFilterDLL

**An LSA password filter for Active Directory, written in C++.**
Block compromised, weak, and predictable passwords at the moment they are set - inside `LSASS`, before the change is ever accepted.

[![CI](https://github.com/Den-Sec/PasswordFilterDLL/actions/workflows/ci.yml/badge.svg)](https://github.com/Den-Sec/PasswordFilterDLL/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Den-Sec/PasswordFilterDLL?sort=semver)](https://github.com/Den-Sec/PasswordFilterDLL/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6?logo=windows&logoColor=white)

</div>

---

A password filter is a DLL that Windows loads into **`LSASS`** - the security authority on
every Domain Controller - and consults *before* each password set or change. This one
rejects passwords that are **known-breached**, **too weak**, or **predictable**, with a
design that treats LSASS with the respect it deserves: the logic is a pure, unit-tested
library, and the part that runs in LSASS is a thin, fail-safe shim that never logs a
password and never takes the domain down on a bug.

## ✨ Features

| | |
|---|---|
| 🔓 **Breached-password blocking, offline** | Checks every password against the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) "Pwned Passwords" corpus (~1.3B hashes) using a compact **Bloom filter** (~2 GB at a 0.1% false-positive rate). **No hash ever leaves the host.** |
| 🔑 **Custom complexity rules** | Length, character classes, keyboard walks (`qwerty`, `asdf`), ascending/descending sequences, excessive repeats, and account-name / full-name containment. |
| 🚫 **Company blacklist** | Exact-match banned passwords plus brand/term substring matching, from simple text files. |
| 📋 **Event logging** | Every rejection is written to the Windows Event Log with **metadata only** (account, operation, rule) - never the password. |
| 🏢 **GPO-friendly deployment** | Registry-driven config with an **ADMX/ADML** template, plus install / uninstall / test PowerShell scripts. |
| 🧩 **Fail-safe by design** | Any internal error allows the change and logs a warning - it never crashes LSASS or locks the domain out. |

## 🧠 Architecture

The decision logic and the LSASS-resident code are deliberately separated. Everything that
decides "accept or reject" lives in a pure C++17 library with **no Windows dependency**, so
it is unit-tested off-host (and on Linux CI). The DLL that LSASS loads is a thin, auditable
shim.

```
                          ┌───────────────────────────────────────────────┐
   LSASS  (on each DC)    │  PasswordFilterDLL   ·  src/dll  (Windows-only) │
   ───────────────────►   │   • SEH + C++ guards, fail-open                 │
   PasswordFilter(...)    │   • UNICODE_STRING viewed in place (no copy)    │
                          │   • Event Log  (metadata only)                  │
                          └───────────────────┬───────────────────────────┘
                                              │   no windows.h below this line
                          ┌───────────────────▼───────────────────────────┐
                          │  pwfilter_core   ·  src/core  (pure C++17)      │
                          │   complexity · blacklist · breach (Bloom) · sha1│
                          └───────────────────────────────────────────────┘
```

**Why this split?** A password filter runs in the most privileged process on a Domain
Controller; a single bug can lock out the whole company or bugcheck the box. Keeping the
logic in a portable, fully-tested library means the risky LSASS-resident code carries no
business logic - it only marshals arguments, applies the verdict, and logs.

## 🔐 How breach checking works

The HIBP corpus is ~1.3 billion SHA-1 hashes - tens of GB raw. Instead of shipping that to
every DC, an offline builder distills it into a **Bloom filter**: a probabilistic set that
answers "have I seen this hash?" in a few memory probes.

- **~2 GB** at a 0.1% false-positive rate, memory-mapped read-only - lookups are microseconds.
- **No false negatives:** a breached password is *never* accepted. A (rare) false positive
  only asks the user to pick a different password.
- **No runtime network access.** The dataset is the same one behind HIBP's
  [k-anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords); the offline lookup
  doesn't even send a hash prefix over the wire. An optional admin tool
  (`src/tools/pwhibp_check.py`) demonstrates the online k-anonymity model, out of LSASS.
- Probing reuses the password's own SHA-1 digest as two 64-bit lanes
  (Kirsch-Mitzenmacher double hashing) - **no extra hash dependency**. The on-disk format is
  verified bit-for-bit between the C++ reader and the Python builder by a cross-language CI
  test.

## 🚀 Quick start

**Build** (Visual Studio "Desktop development with C++" + Windows SDK, CMake ≥ 3.21):

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The pure `pwfilter_core` library and its tests also build on any C++17 compiler (no Windows
headers required) - that portability is what makes the policy logic testable.

**Deploy** (lab Domain Controller only - this runs in LSASS):

```powershell
# 1. Build the offline breach artifact once (Python only) from the HIBP dump:
python scripts\build_bloom.py pwnedpasswords.txt -o breach.bloom --count 1300000000

# 2. Install on a test DC (copies the DLL, sets policy, registers with LSA - merge-safe):
.\deploy\Install-PasswordFilter.ps1 -DllSource .\PasswordFilterDLL.dll
#    place breach.bloom in %ProgramData%\PasswordFilter\, then REBOOT

# 3. Exercise it and read the Event Log:
.\deploy\Test-PasswordFilter.ps1 -SamAccountName test.user

# Rollback:
.\deploy\Uninstall-PasswordFilter.ps1
```

Full guides: [DEPLOYMENT](docs/DEPLOYMENT.md) · [CONFIG](docs/CONFIG.md) · [ARCHITECTURE](docs/ARCHITECTURE.md) · [SECURITY](SECURITY.md).

## 🗺️ Capability → code

| Capability | Where |
|------------|-------|
| LSA password filter for Active Directory, in C++ | `src/dll/dllmain.cpp` (3 LSA exports) + `src/core/` |
| Compromised passwords, offline breach-list (HIBP) | `src/core/breach_bloom.cpp`, `src/core/bloom.cpp`, `scripts/build_bloom.py` |
| HIBP k-anonymity model | `src/tools/pwhibp_check.py` (online range query); offline corpus is the same dataset |
| Custom complexity rules | `src/core/complexity.cpp` |
| Company blacklist | `src/core/blacklist.cpp` + `blacklist.txt` / `company_terms.txt` |
| Event logging (metadata only) | `src/dll/eventlog.cpp` + `src/dll/messages.mc` |
| GPO-friendly deployment | `deploy/*.ps1` + `deploy/PasswordFilter.admx` / `.adml` |

## 🧪 Validation & status

- **`v0.1.0`** - core, LSASS shim, offline Bloom pipeline, and deployment tooling are all in place.
- **Windows CI** (`windows-latest`) builds the x64 DLL and runs the full unit-test suite
  (SHA-1 NIST vectors, Bloom round-trips, complexity, blacklist, policy, breach, and
  cross-language format parity) on every push, with warnings-as-errors.
- **Memory-safety CI** (`ubuntu-latest`, Clang) builds the portable core and runs the same
  suite under **AddressSanitizer + UndefinedBehaviorSanitizer** - so "memory-safe" (the #1
  requirement for code that runs in LSASS) is an automated gate, not just a claim. This also
  proves the core is compiler-portable (MSVC + Clang).
- The filter logic has been validated working on a real Windows host.

## 🔏 Security & code signing

This is a defensive tool. See **[SECURITY.md](SECURITY.md)** for the threat model, the
LSASS-safety rules, and DSRM recovery steps.

> **Code signing.** On hosts with **LSA Protection (RunAsPPL)** enabled, LSASS runs as a
> protected process and refuses *unsigned* notification packages (error 577) - there the
> DLL must be **code-signed**. On hosts without LSA Protection, an unsigned build loads and
> runs. See [SECURITY.md](SECURITY.md#code-signing-and-lsa-protection-runasppl).

Always validate on a non-production lab Domain Controller before any real rollout.

## 📂 Layout

| Path | What |
|------|------|
| `src/core/` | Pure C++17 validation logic (no `windows.h`) - the testable heart |
| `src/dll/` | The LSASS-resident shim (the three LSA exports) |
| `tests/` | GoogleTest suite over `pwfilter_core`, run via CTest |
| `scripts/build_bloom.py` | Offline builder: HIBP dump → Bloom artifact |
| `src/tools/pwhibp_check.py` | Admin tool: online HIBP k-anonymity check (out of LSASS) |
| `deploy/` | Install/uninstall/test scripts + ADMX template (GPO) |
| `docs/` | Architecture, deployment, and configuration guides |

## 🧾 License

[MIT](LICENSE) © Dennis Sepede ([Den-Sec](https://github.com/Den-Sec))
