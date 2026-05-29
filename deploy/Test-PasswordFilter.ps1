<#
.SYNOPSIS
    Lab helper: exercises the installed password filter against a test account and shows
    the resulting Event Log entries.

.DESCRIPTION
    Attempts several administrative password resets on a TEST account and reports which
    were accepted or rejected, then prints recent "Den-Sec PasswordFilter" events. An
    admin reset exercises the SetOperation=TRUE path; a user-initiated change exercises
    SetOperation=FALSE.

    LAB ONLY. Run against a throwaway account on a non-production test Domain Controller.

.PARAMETER SamAccountName
    The test account to reset passwords on.

.EXAMPLE
    .\Test-PasswordFilter.ps1 -SamAccountName test.user
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SamAccountName
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

# (password, expectation) - expectations are for the DEFAULT policy.
$cases = @(
    @{ Pw = 'password';              Expect = 'REJECT (breached/blacklist)' },
    @{ Pw = 'Summer2025';            Expect = 'REJECT (likely breached/weak)' },
    @{ Pw = 'Ab1!xy';               Expect = 'REJECT (too short)' },
    @{ Pw = 'Qwerty12345!';          Expect = 'REJECT (keyboard/sequence)' },
    @{ Pw = 'Wm7!Kp4@Zb9#Vt2$';      Expect = 'ACCEPT (strong, not breached)' }
)

Write-Host "Testing password resets on '$SamAccountName' (admin set => SetOperation=TRUE)`n"
foreach ($c in $cases) {
    $secure = ConvertTo-SecureString $c.Pw -AsPlainText -Force
    try {
        Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $secure -ErrorAction Stop
        $result = 'ACCEPTED'
    } catch {
        $result = 'REJECTED'
    }
    $masked = ('*' * $c.Pw.Length)
    Write-Host ("  [{0,-8}] len={1,-3} expected: {2}" -f $result, $c.Pw.Length, $c.Expect)
}

Write-Host "`nRecent 'Den-Sec PasswordFilter' events:`n"
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Den-Sec PasswordFilter' } -MaxEvents 15 |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Format-List
} catch {
    Write-Warning "No events found yet (is the filter installed and the machine rebooted?)."
}

Write-Host "Reminder: no password is ever written to the Event Log - only metadata." -ForegroundColor Green
