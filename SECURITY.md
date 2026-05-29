# Security

PasswordFilterDLL is a defensive tool that runs **inside LSASS** on a Domain Controller -
the most privileged process on the box. This document states the threat model, the safety
rules the code follows, how to recover if a filter ever misbehaves, and how to report
issues.

## Safety model

A password filter sits on the critical path of every password change for the whole domain.
Two failure modes matter most: **crashing LSASS** (which bugchecks the machine and can
cause a boot loop on a DC) and **wrongly rejecting passwords** (which can lock users out).
The design mitigates both:

- **Fail open on internal error.** Every callback wraps its work in *both* a structured
  (`__try/__except`) and a C++ (`try/catch`) handler. Any unexpected fault - access
  violation, allocation failure, a corrupt data file - results in the change being
  **allowed** and a warning logged, never an unhandled exception escaping into LSASS. The
  filter rejects **only** on an explicit policy match. (`FailOpenOnError`, default on.)
- **No plaintext, anywhere.** The password is read in place from LSA's `UNICODE_STRING`
  as a read-only view; it is never copied onto our heap and never written to disk or logs.
  The only derived copies are short-lived: the UTF-8 bytes hashed for the breach check and
  the normalized key for the blacklist lookup, each held in a buffer that is wiped with
  `SecureZero` before it is released. The Event Log records **metadata only** (account
  name, operation, the rule that failed, counts).
- **Correct `UNICODE_STRING` handling.** `Length` is a count of **bytes** and the buffer is
  **not** NUL-terminated; treating it as a C string is the classic bug in this API. The
  shim always uses the length.
- **Fast path.** All data (the Bloom filter, blacklist, company terms) is loaded once at
  initialization. Per-password work is a handful of in-memory checks plus one SHA-1 and a
  Bloom lookup over a memory-mapped, read-only region.
- **Small, auditable shim.** All decision logic lives in `pwfilter_core`, a pure,
  unit-tested C++ library with no Windows dependency. The LSASS-resident code only
  marshals arguments, applies the verdict, and logs.

## False positives (breach Bloom)

The breach check uses a Bloom filter. A false positive means a password that is **not**
breached is treated as if it were and gets rejected - the user simply picks another. There
are **no false negatives**: a breached password is never accepted. The default sizing
targets a ~0.1% false-positive rate.

## Recovery: removing a misbehaving filter

If a filter ever has to be removed urgently (for example it is wrongly rejecting all
changes, or you suspect it of instability):

1. **Detach cleanly:** run `deploy/Uninstall-PasswordFilter.ps1` (removes the package from
   `Notification Packages`, merge-safe) and reboot.
2. **If the DC will not boot** (a filter crashing LSASS): boot into **Directory Services
   Restore Mode (DSRM)** or another recovery environment, load the SYSTEM hive, and remove
   `PasswordFilterDLL` from
   `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`, then reboot.

Because the filter fails open by default, an internal bug degrades to "no filtering," not
"no logins" - but always validate in a lab first.

## Testing

Test **only** on a non-production lab Domain Controller (or a standalone test box). Never
register an unproven filter on a production DC. `pwfilter_core` is unit-tested off-host and
in CI; the LSASS integration is validated in a lab VM (see `docs/DEPLOYMENT.md`).

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue: open a GitHub
security advisory on the repository, or contact the maintainer via the address on the
[Den-Sec](https://github.com/Den-Sec) profile. Include reproduction steps and affected
versions. Coordinated disclosure is appreciated.
