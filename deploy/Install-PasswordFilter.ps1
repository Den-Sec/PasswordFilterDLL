<#
.SYNOPSIS
    Installs PasswordFilterDLL as an LSA notification package on this machine.

.DESCRIPTION
    Copies the DLL into System32, registers default policy in the registry, registers the
    Windows Event Log source, and adds the package to the LSA "Notification Packages"
    value (MERGE-SAFE: existing packages such as rassfm/scecli are preserved). A REBOOT is
    required for LSASS to load the filter.

    Run this on a TEST Domain Controller in a lab first. Never test on production.
    Deploy to EVERY Domain Controller (each DC enforces password changes locally).

.PARAMETER DllSource
    Path to PasswordFilterDLL.dll (defaults to the script directory).

.PARAMETER DataDir
    Directory for breach.bloom / blacklist.txt / company_terms.txt
    (default: %ProgramData%\PasswordFilter).

.PARAMETER NoReboot
    Skip the reboot prompt (you must reboot manually before the filter is active).

.EXAMPLE
    .\Install-PasswordFilter.ps1 -DllSource .\PasswordFilterDLL.dll
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$DllSource = (Join-Path $PSScriptRoot 'PasswordFilterDLL.dll'),
    [string]$DataDir   = (Join-Path $env:ProgramData 'PasswordFilter'),
    [switch]$NoReboot
)

$ErrorActionPreference = 'Stop'
$PackageName = 'PasswordFilterDLL'                       # name WITHOUT .dll, for LSA
$DllDest     = Join-Path $env:WINDIR "System32\$PackageName.dll"
$LsaKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$CfgKey      = 'HKLM:\SOFTWARE\Den-Sec\PasswordFilter'
$SrcKey      = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Den-Sec PasswordFilter'

if (-not (Test-Path -LiteralPath $DllSource)) {
    throw "DLL not found: $DllSource"
}

Write-Host "[1/5] Copying DLL to $DllDest"
Copy-Item -LiteralPath $DllSource -Destination $DllDest -Force

Write-Host "[2/5] Preparing data directory $DataDir"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
foreach ($pair in @(
        @{ Example = 'blacklist.example.txt';      Target = 'blacklist.txt' },
        @{ Example = 'company_terms.example.txt';   Target = 'company_terms.txt' })) {
    $ex = Join-Path $PSScriptRoot $pair.Example
    $tg = Join-Path $DataDir      $pair.Target
    if ((Test-Path -LiteralPath $ex) -and -not (Test-Path -LiteralPath $tg)) {
        Copy-Item -LiteralPath $ex -Destination $tg
    }
}
Write-Host "    NOTE: build breach.bloom with scripts/build_bloom.py and place it in $DataDir"

Write-Host "[3/5] Writing default policy to $CfgKey"
New-Item -Path $CfgKey -Force | Out-Null
$defaults = [ordered]@{
    MinLength                 = 12
    MaxLength                 = 256
    RequiredClasses           = 3
    RejectKeyboardPatterns    = 1
    RejectSequences           = 1
    SequenceMinRun            = 4
    KeyboardMinRun            = 4
    MaxRepeatRun              = 4
    RejectContainsAccountName = 1
    RejectContainsFullName    = 1
    MinIdentityToken          = 3
    CheckBreach               = 1
    FailOpenOnError           = 1
    BlacklistCaseInsensitive  = 1
}
foreach ($name in $defaults.Keys) {
    # Only set if missing, so re-running the installer never clobbers tuned values.
    if ($null -eq (Get-ItemProperty -Path $CfgKey -Name $name -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $CfgKey -Name $name -Value $defaults[$name] -PropertyType DWord -Force | Out-Null
    }
}
New-ItemProperty -Path $CfgKey -Name 'DataDir' -Value $DataDir -PropertyType String -Force | Out-Null

Write-Host "[4/5] Registering Event Log source"
New-Item -Path $SrcKey -Force | Out-Null
New-ItemProperty -Path $SrcKey -Name 'EventMessageFile' -Value $DllDest -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $SrcKey -Name 'TypesSupported' -Value 7 -PropertyType DWord -Force | Out-Null

Write-Host "[5/5] Registering with LSA Notification Packages (merge-safe)"
$current = (Get-ItemProperty -Path $LsaKey -Name 'Notification Packages' -ErrorAction SilentlyContinue).'Notification Packages'
if ($null -eq $current) { $current = @() }
if ($current -notcontains $PackageName) {
    $updated = @($current) + $PackageName
    Set-ItemProperty -Path $LsaKey -Name 'Notification Packages' -Value $updated -Type MultiString
    Write-Host "    Added '$PackageName'. Packages now: $($updated -join ', ')"
} else {
    Write-Host "    '$PackageName' already registered. Packages: $($current -join ', ')"
}

Write-Host ""
Write-Host "Install complete. A REBOOT is required for LSASS to load the filter." -ForegroundColor Yellow
if (-not $NoReboot) {
    $answer = Read-Host "Reboot now? (y/N)"
    if ($answer -eq 'y') { Restart-Computer -Force }
}
