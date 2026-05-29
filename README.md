# PasswordFilterDLL

[![CI](https://github.com/Den-Sec/PasswordFilterDLL/actions/workflows/ci.yml/badge.svg)](https://github.com/Den-Sec/PasswordFilterDLL/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An **LSA password filter for Active Directory**, written in C++. It runs inside `LSASS`
on a Domain Controller and is consulted *before* every password set/change, rejecting
passwords that fail policy:

- **Compromised passwords** - checked against the *offline* Have I Been Pwned "Pwned
  Passwords" corpus (the same k-anonymity dataset HIBP exposes online), using a compact
  Bloom filter so **no hash ever leaves the host** at runtime.
- **Custom complexity rules** - length, character classes, keyboard walks (`qwerty`,
  `123456`), sequences and repeats, and identity terms (account/full name).
- **Company blacklist** - configurable banned terms and exact-match lists.
- **Event logging** - every rejection is recorded to the Windows Event Log with metadata
  only (account, rule violated, timestamp). **The password is never logged, anywhere.**
- **GPO-friendly deployment** - registry-driven configuration (ADMX template), x64,
  with install/rollback scripts.

> ⚠️ **Project status: under active development.** The build, test and CI scaffolding is in
> place; the validation engine, LSASS shim and deployment tooling are being implemented in
> phases (see [Roadmap](#roadmap)). Do not deploy to a production Domain Controller.

## Why this design

A password filter runs in the most privileged process on a Domain Controller. A single
bug can lock every user out or crash `LSASS` and bugcheck the machine. Two principles
drive the architecture:

1. **The validation logic is pure, portable C++ with no Windows dependency** (`pwfilter_core`).
   It is unit-tested off-host (and in CI) so the code that decides "accept/reject" never
   needs `LSASS` to be exercised. The `LSASS`-resident DLL is a thin, auditable shim.
2. **Fail-safe by default.** On any *internal* error (missing data file, unexpected
   exception) the filter **allows** the change and logs the fault, rather than risking a
   domain-wide lockout. It rejects **only** on an explicit policy match.

```
                         ┌─────────────────────────────────────────┐
   LSASS (on the DC)     │  PasswordFilterDLL  (thin shim)          │
   ───────────────────►  │   • SEH + secure zeroing                 │
   PasswordFilter(...)   │   • UNICODE_STRING  ─► std::wstring_view  │
                         │   • Event Log (metadata only)            │
                         └───────────────┬─────────────────────────┘
                                         │  (no windows.h below this line)
                         ┌───────────────▼─────────────────────────┐
                         │  pwfilter_core   (pure, unit-tested)     │
                         │   complexity · blacklist · breach(bloom) │
                         └──────────────────────────────────────────┘
```

## Build

The DLL is built and tested in CI (GitHub Actions, `windows-latest`, MSVC v143 + Windows
SDK). To build locally you need the Visual Studio "Desktop development with C++" workload
(or Build Tools) with the Windows 10/11 SDK, plus CMake ≥ 3.21.

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The pure `pwfilter_core` library and its tests also build on any C++17 compiler (no
Windows headers required), which is what makes the policy logic portable and testable.

## Layout

| Path | What |
|------|------|
| `src/core/` | Pure C++17 validation logic (no `windows.h`) - the testable heart |
| `src/dll/`  | The `LSASS`-resident shim (the three LSA exports) |
| `tests/`    | GoogleTest suite over `pwfilter_core` (run via CTest) |
| `scripts/build_bloom.py` | Offline builder: HIBP dump → Bloom artifact |
| `deploy/`   | Install/uninstall scripts + ADMX template (GPO) |
| `docs/`     | Architecture, deployment and configuration guides |

## Roadmap

- [x] **F0** - CMake + CI scaffolding, three targets, smoke test
- [x] **F1** - Core: portable SHA-1, Bloom filter, secure zeroing, UTF-16→UTF-8
- [x] **F2** - Core: complexity rules, blacklist, policy evaluator
- [ ] **F3** - Core: breach checker (SHA-1 → Bloom)
- [ ] **F4** - Python Bloom builder + sample data + cross-language format test
- [ ] **F5** - LSASS shim: fail-safe `dllmain`, registry/file config, Event Log
- [ ] **F6** - Deployment scripts, ADMX, full documentation
- [ ] **F7** - Optional online HIBP k-anonymity checker (admin tool, out of LSASS)

## Security

This is a defensive tool. See [SECURITY.md](SECURITY.md) for the threat model, the
`LSASS`-safety rules it follows, and recovery steps (DSRM) should a filter ever need to be
removed. Test only in a lab VM with a non-production Domain Controller.

## License

[MIT](LICENSE) © Dennis Sepede ([Den-Sec](https://github.com/Den-Sec))
