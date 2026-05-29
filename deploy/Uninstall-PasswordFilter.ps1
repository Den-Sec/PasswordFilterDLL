<#
.SYNOPSIS
    Removes PasswordFilterDLL from the LSA notification packages on this machine.

.DESCRIPTION
    Removes the package from the "Notification Packages" value (MERGE-SAFE: every other
    package is preserved), removes the Event Log source and the policy registry key. The
    DLL file stays in System32 because LSASS still has it loaded; delete it AFTER a reboot.

.PARAMETER KeepConfig
    Leave HKLM\SOFTWARE\Den-Sec\PasswordFilter in place (only detach from LSA).

.EXAMPLE
    .\Uninstall-PasswordFilter.ps1
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$KeepConfig
)

$ErrorActionPreference = 'Stop'
$PackageName = 'PasswordFilterDLL'
$DllDest     = Join-Path $env:WINDIR "System32\$PackageName.dll"
$LsaKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$CfgKey      = 'HKLM:\SOFTWARE\Den-Sec\PasswordFilter'
$SrcKey      = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Den-Sec PasswordFilter'

Write-Host "[1/3] Removing from LSA Notification Packages (merge-safe)"
$current = (Get-ItemProperty -Path $LsaKey -Name 'Notification Packages' -ErrorAction SilentlyContinue).'Notification Packages'
if ($null -ne $current -and ($current -contains $PackageName)) {
    $updated = @($current | Where-Object { $_ -ne $PackageName })
    Set-ItemProperty -Path $LsaKey -Name 'Notification Packages' -Value $updated -Type MultiString
    Write-Host "    Removed '$PackageName'. Packages now: $($updated -join ', ')"
} else {
    Write-Host "    '$PackageName' was not registered."
}

Write-Host "[2/3] Removing Event Log source"
Remove-Item -Path $SrcKey -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[3/3] Removing policy registry key"
if ($KeepConfig) {
    Write-Host "    Skipped (-KeepConfig)."
} else {
    Remove-Item -Path $CfgKey -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Detached from LSA. REBOOT to unload the DLL from LSASS." -ForegroundColor Yellow
Write-Host "After the reboot, delete the file if you no longer need it: $DllDest"
