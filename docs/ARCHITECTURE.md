# Architecture

## The LSA password-filter contract

Windows lets you register a DLL as an LSA *notification package*. Once registered (under
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`) and after a reboot,
LSASS loads it on every Domain Controller and calls three exported functions
([Microsoft docs](https://learn.microsoft.com/windows/win32/secmgmt/password-filters)):

| Export | When | Return | Our behavior |
|--------|------|--------|--------------|
| `InitializeChangeNotify` | once, at load | `BOOLEAN` (TRUE = active) | load config, mmap the Bloom, register the Event Log source |
| `PasswordFilter` | **before** a set/change | `BOOLEAN` (TRUE = accept) | evaluate policy; the heart of the tool |
| `PasswordChangeNotify` | **after** a change | `NTSTATUS` | no-op (cannot reject); returns `STATUS_SUCCESS` |

If **any** registered package returns FALSE from `PasswordFilter`, the password is
rejected. `SetOperation` is TRUE for an administrative reset, FALSE for a user change.

## Two layers: core vs shim

```
                         ┌──────────────────────────────────────────────┐
   LSASS (on each DC)    │  PasswordFilterDLL  (src/dll, Windows-only)    │
   ───────────────────►  │   dllmain     SEH + try/catch, fail-open       │
   PasswordFilter(...)   │   config_win  registry + files + mmap Bloom    │
                         │   eventlog    metadata-only Event Log          │
                         └───────────────┬──────────────────────────────┘
                                         │   UNICODE_STRING viewed in place
                                         │   (no heap copy of the password)
                         ┌───────────────▼──────────────────────────────┐
                         │  pwfilter_core  (src/core, pure C++17)         │
                         │   policy      Validator: rule order            │
                         │   complexity  length, classes, walks, identity │
                         │   blacklist   exact-match set                  │
                         │   breach_bloom SHA-1 -> Bloom membership        │
                         │   sha1 · bloom · utf · secure                   │
                         └──────────────────────────────────────────────┘
```

**`pwfilter_core`** contains every decision. It has no `windows.h` dependency, so it builds
and is unit-tested on any C++17 compiler (and could run on Linux CI). This is what makes a
filter that lives in LSASS testable: the risky part (LSASS) holds no logic.

**The DLL shim** is deliberately thin and auditable: marshal arguments, call the core,
apply the verdict, log metadata.

## Evaluation order

`Validator::Evaluate` runs cheapest-to-costliest and returns the **first** violated rule,
so the expensive breach lookup only runs for passwords that already passed everything else:

1. length (`MinLength` / `MaxLength`)
2. character classes (`RequiredClasses`)
3. excessive repeats (`MaxRepeatRun`)
4. sequences (`RejectSequences`)
5. keyboard walks (`RejectKeyboardPatterns`)
6. contains account name (`RejectContainsAccountName`)
7. contains full-name token (`RejectContainsFullName`)
8. company/brand terms (`company_terms.txt`)
9. exact blacklist (`blacklist.txt`)
10. offline breach corpus (`breach.bloom`)

## Breach lookup: Bloom filter

The breached-password corpus (HIBP "Pwned Passwords", ~1.3 billion SHA-1 hashes) is stored
as a **Bloom filter** so the whole set fits in ~2 GB at a ~0.1% false-positive rate instead
of the ~38 GB raw dump, and a lookup is a handful of memory probes with **no runtime
network access**.

- The offline builder (`scripts/build_bloom.py`) ingests the HIBP dump and writes a
  `breach.bloom` file in the documented `PWBLOOM1` format.
- At runtime the DLL memory-maps that file read-only and queries it. Probing uses
  Kirsch-Mitzenmacher double hashing, taking two 64-bit lanes directly from the password's
  SHA-1 digest - no separate hash function is needed because the digest is already
  uniformly distributed.
- The on-disk format is verified bit-for-bit between the Python builder and the C++ reader
  by a cross-language CI test.

See [DEPLOYMENT.md](DEPLOYMENT.md) for building the artifact and [CONFIG.md](CONFIG.md) for
every tunable.

## Threat model in brief

The asset is the domain's password quality; the adversary is a user (or admin) choosing a
weak or known-breached password. The filter is an enforcement point, not a secret store -
it holds no credentials, only a membership structure over public breach hashes. Its own
risk is operational (LSASS stability, lockouts), addressed by the fail-open design in
[SECURITY.md](../SECURITY.md).
