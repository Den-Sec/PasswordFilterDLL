# Deployment

> **Test in a lab first.** Register the filter on a non-production Domain Controller (or a
> standalone test box) and validate before touching production. A password filter runs in
> LSASS; treat rollout like a kernel change.

## 1. Obtain the DLL

Either download `PasswordFilterDLL.dll` from the CI build artifact / a GitHub Release, or
build it yourself (Visual Studio "Desktop development with C++" + Windows SDK, CMake ≥ 3.21):

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
# -> build\src\dll\Release\PasswordFilterDLL.dll
```

It must be the **x64** build (LSASS is 64-bit). Verify the exports if you like:
`dumpbin /exports PasswordFilterDLL.dll` should list `InitializeChangeNotify`,
`PasswordFilter`, `PasswordChangeNotify`.

## 2. Build the breach Bloom artifact (offline)

The breach corpus is not redistributed; build it once from the HIBP dump and copy the
result to each DC.

1. Download the HIBP "Pwned Passwords" SHA-1 dump (ordered by hash) with the official
   [`haveibeenpwned-downloader`](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader).
   Verify the current size on the HIBP download page (tens of GB).
2. Build the Bloom filter (needs only Python 3; ~2 GB of RAM and output for the full set):

   ```powershell
   python scripts\build_bloom.py pwnedpasswords.txt -o breach.bloom --count 1300000000 --fp 0.001
   ```

   Pass the actual line count via `--count` to skip the counting pass. Use `--plain` if
   your input is a plaintext wordlist instead of the `HASH:count` dump.
3. Copy `breach.bloom` to the data directory on each DC (default
   `%ProgramData%\PasswordFilter\`).

The artifact is large; rebuild and redistribute it periodically as HIBP grows.

## 3. Install on a Domain Controller

From an elevated PowerShell, with `PasswordFilterDLL.dll` and the `deploy\` scripts present:

```powershell
.\Install-PasswordFilter.ps1 -DllSource .\PasswordFilterDLL.dll
```

This copies the DLL to `System32`, writes default policy under
`HKLM\SOFTWARE\Den-Sec\PasswordFilter`, registers the Event Log source, and adds the
package to `Notification Packages` **without disturbing the packages already there**
(rassfm, scecli, ...). Then place `breach.bloom` (and edit `blacklist.txt` /
`company_terms.txt`) in the data directory.

**A reboot is required** for LSASS to load the filter. There is no way to load a
notification package without restarting LSASS (i.e. the machine).

## 4. Validate (lab)

After the reboot, on the lab DC:

```powershell
.\Test-PasswordFilter.ps1 -SamAccountName test.user
```

It tries several resets (weak/breached/strong) and prints the resulting
`Den-Sec PasswordFilter` events from the Application log. Confirm: weak/breached rejected,
strong accepted, and that **no password text** appears in any event.

## 5. Domain-wide rollout

- Password changes are enforced by whichever DC handles them, so the filter must be on
  **every** DC to be effective. Roll out one DC at a time, validating between each.
- Configure policy centrally with the ADMX template (`deploy\PasswordFilter.admx` +
  `en-US\PasswordFilter.adml`); copy them to the domain Central Store. Distribute the DLL
  and `breach.bloom` with your usual mechanism (GPO startup script, SCCM/Intune, etc.).
- Each DC still needs the reboot to pick up the package.

## 6. Rollback

```powershell
.\Uninstall-PasswordFilter.ps1   # merge-safe removal from Notification Packages
```

Reboot to unload the DLL from LSASS, then delete `System32\PasswordFilterDLL.dll` if you
are done with it. If a DC ever fails to boot because of a filter, remove the package from
the registry under **DSRM**/recovery (see [SECURITY.md](../SECURITY.md#recovery-removing-a-misbehaving-filter)).

## Upgrading

Copy the new DLL over `System32\PasswordFilterDLL.dll` (it is in use by LSASS, so the
replace takes effect on the next reboot) and reboot. Policy in the registry is preserved;
the installer never overwrites tuned values.
