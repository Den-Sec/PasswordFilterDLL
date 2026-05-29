// PasswordFilterDLL - LSA password filter for Active Directory (defensive).
// https://github.com/Den-Sec/PasswordFilterDLL
//
// This DLL is registered as an LSA "Notification Package" and loaded INSIDE LSASS on a
// Domain Controller. LSA calls the three exported routines below. See:
// https://learn.microsoft.com/windows/win32/secmgmt/password-filters
//
// F0 SKELETON: correct export signatures only. The fail-safe shim (SEH, UNICODE_STRING
// marshalling, secure zeroing, Event Log) and the policy engine are wired in later phases.
// At this stage the filter accepts every password (no-op), so it is safe-by-default.

#include <windows.h>
#include <ntsecapi.h>  // PUNICODE_STRING and the password-notification routine contracts

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Loaded by LSASS. Disable per-thread DLL notifications: this DLL is long-lived
        // and does nothing on thread attach/detach, so skipping them is a small win.
        // (Real initialization happens in InitializeChangeNotify.)
    }
    return TRUE;
}

// Called once when LSA loads the notification package. Returning TRUE enables the package.
extern "C" BOOLEAN NTAPI InitializeChangeNotify(void) {
    return TRUE;
}

// Called BEFORE a password is set/changed. Return TRUE to accept, FALSE to reject.
// SetOperation is TRUE for an administrative set/reset, FALSE for a user-initiated change.
extern "C" BOOLEAN NTAPI PasswordFilter(
    PUNICODE_STRING /*AccountName*/,
    PUNICODE_STRING /*FullName*/,
    PUNICODE_STRING /*Password*/,
    BOOLEAN /*SetOperation*/) {
    return TRUE;  // F0: accept all. Policy evaluation arrives in F2-F5.
}

// Called AFTER a password has changed. Notification only - cannot reject. Return success.
extern "C" NTSTATUS NTAPI PasswordChangeNotify(
    PUNICODE_STRING /*UserName*/,
    ULONG /*RelativeId*/,
    PUNICODE_STRING /*NewPassword*/) {
    return 0;  // STATUS_SUCCESS
}
