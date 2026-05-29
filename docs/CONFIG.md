# Configuration

All settings live under `HKLM\SOFTWARE\Den-Sec\PasswordFilter` (set them via the installer,
`deploy/policy.example.reg`, or the ADMX template). Large data lives in files under the
data directory. **Everything is read once when LSASS loads the filter**, so changes take
effect on the next reboot.

## Registry values

| Value | Type | Default | Meaning |
|-------|------|---------|---------|
| `MinLength` | DWORD | 12 | Reject passwords shorter than this. |
| `MaxLength` | DWORD | 256 | Reject passwords longer than this. |
| `RequiredClasses` | DWORD | 3 | Minimum distinct character classes of {lower, upper, digit, symbol}; `0` disables. |
| `RejectKeyboardPatterns` | DWORD | 1 | Reject US-QWERTY keyboard walks (`qwer`, `asdf`). |
| `RejectSequences` | DWORD | 1 | Reject ascending/descending runs (`abcd`, `1234`). |
| `SequenceMinRun` | DWORD | 4 | Minimum run length counted as a sequence. |
| `KeyboardMinRun` | DWORD | 4 | Minimum run length counted as a keyboard walk. |
| `MaxRepeatRun` | DWORD | 4 | Reject a run of identical characters longer than this (`aaaaa`); `0` disables. |
| `RejectContainsAccountName` | DWORD | 1 | Reject if the password contains the sAMAccountName. |
| `RejectContainsFullName` | DWORD | 1 | Reject if it contains a token of the display name. |
| `MinIdentityToken` | DWORD | 3 | Ignore account/name fragments shorter than this when matching. |
| `CheckBreach` | DWORD | 1 | Check against the offline breach Bloom filter. |
| `BlacklistCaseInsensitive` | DWORD | 1 | Match the blacklist case-insensitively. |
| `FailOpenOnError` | DWORD | 1 | On an internal error, allow the change (recommended) rather than block. |
| `DataDir` | SZ | `%ProgramData%\PasswordFilter` | Folder holding the data files below. |
| `BloomFile` | SZ | `breach.bloom` | Bloom filename (absolute path, or relative to `DataDir`). |
| `BlacklistFile` | SZ | `blacklist.txt` | Blacklist filename (absolute, or relative to `DataDir`). |
| `CompanyTermsFile` | SZ | `company_terms.txt` | Company-terms filename (absolute, or relative to `DataDir`). |

## Data files (UTF-8)

All three are optional - a missing file is treated as empty, and a missing/invalid
`breach.bloom` simply disables breach checking (logged as a warning). Lines starting with
`#` are comments; blank lines are ignored.

- **`breach.bloom`** - the breach corpus, built offline by `scripts/build_bloom.py` (see
  [DEPLOYMENT.md](DEPLOYMENT.md)). Format documented in `src/core/include/pwfilter/bloom.hpp`.
- **`blacklist.txt`** - one banned password per line, matched as a whole password (exact),
  case-insensitive by default. Example: `deploy/blacklist.example.txt`.
- **`company_terms.txt`** - one term per line, matched as a **substring** (case-insensitive),
  for brand/product names. Example: `deploy/company_terms.example.txt`.

## Notes

- Character classes are ASCII-based; any non-ASCII character counts toward the "symbol"
  class, so accented passwords still earn a class.
- The breach check hashes the **UTF-8** encoding of the password with SHA-1, matching the
  HIBP corpus. Passwords above ~1024 characters are not breach-checked (they fail open for
  that single check; they are extremely strong regardless).
- To disable a whole category, set its DWORD to `0` (or `RequiredClasses`/`MaxRepeatRun`
  to `0`). To disable breach checking, set `CheckBreach=0` or remove `breach.bloom`.
