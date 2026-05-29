// PasswordFilterDLL - LSA password filter for Active Directory (defensive).
// https://github.com/Den-Sec/PasswordFilterDLL
//
// Registered as an LSA "Notification Package" and loaded INSIDE LSASS on a Domain
// Controller. LSA calls the three exported routines below. Contract:
// https://learn.microsoft.com/windows/win32/secmgmt/password-filters
//
// Safety model (this code runs in the most privileged process on the DC):
//   * FAIL-OPEN on internal error. An unhandled fault here can crash LSASS and bugcheck
//     the machine, or lock every user out. So any unexpected error (SEH fault or C++
//     exception) is caught and the change is ALLOWED, with a warning logged. The filter
//     rejects ONLY on an explicit policy match.
//   * NO plaintext anywhere. The password is read in place from LSA's buffer (never copied
//     into our own heap); the only derived copies live in the core (UTF-8 for hashing,
//     normalized for blacklist) and are wiped there. Nothing is ever written to disk/logs.
//   * The validation logic lives in pwfilter_core; this file is a thin, auditable shim.

#include <windows.h>
#include <ntsecapi.h>

#include "config_win.hpp"
#include "eventlog.hpp"
#include "pwfilter/policy.hpp"
#include "pwfilter/result.hpp"

namespace {

pwfilter::FilterContext* g_ctx = nullptr;
pwfilter::EventLog g_log;

// View an LSA UNICODE_STRING as char16_t WITHOUT copying. Length is in BYTES and the
// buffer is NOT NUL-terminated - the classic gotcha; we honor it by using the length.
std::u16string_view View(PUNICODE_STRING s) noexcept {
    if (s == nullptr || s->Buffer == nullptr || s->Length == 0) {
        return {};
    }
    return std::u16string_view(reinterpret_cast<const char16_t*>(s->Buffer),
                               s->Length / sizeof(WCHAR));
}

// Copy an account/user name into a NUL-terminated buffer for logging (never secret).
void CopyName(wchar_t* dst, std::size_t cch, PUNICODE_STRING s) noexcept {
    if (cch == 0) {
        return;
    }
    if (s == nullptr || s->Buffer == nullptr || s->Length == 0) {
        dst[0] = L'\0';
        return;
    }
    std::size_t n = s->Length / sizeof(WCHAR);
    if (n >= cch) {
        n = cch - 1;
    }
    for (std::size_t i = 0; i < n; ++i) {
        dst[i] = s->Buffer[i];
    }
    dst[n] = L'\0';
}

// Real init work (has C++ objects, so it lives outside the SEH frame below).
void InitWorker() {
    try {
        g_log.Init();
        g_ctx = pwfilter::FilterContext::Create();
        if (g_ctx != nullptr) {
            g_log.ReportInitialized(g_ctx->breach_enabled(), g_ctx->blacklist_count());
            if (!g_ctx->breach_enabled() && g_ctx->bloom_error()[0] != L'\0') {
                g_log.ReportBloomUnavailable(g_ctx->bloom_error());
            }
        }
    } catch (...) {
        // Leave g_ctx as-is (possibly null -> fail-open). Never propagate out of LSASS.
    }
}

// Real evaluation (has C++ objects/try-catch, so it lives outside the SEH frame).
BOOLEAN DoFilter(PUNICODE_STRING account, PUNICODE_STRING full, PUNICODE_STRING password,
                 BOOLEAN set_operation) {
    try {
        if (g_ctx == nullptr) {
            return TRUE;  // not initialized -> fail open
        }
        if (password == nullptr || (password->Buffer == nullptr && password->Length != 0)) {
            return TRUE;  // malformed input -> fail open
        }

        const pwfilter::ValidationResult r =
            g_ctx->validator().Evaluate(View(password), View(account), View(full));
        if (r.allowed) {
            return TRUE;
        }

        wchar_t account_buf[256];
        CopyName(account_buf, 256, account);
        g_log.ReportRejected(account_buf, set_operation != FALSE, r.rule);
        return FALSE;
    } catch (...) {
        g_log.ReportInternalError(L"exception", L"");
        return TRUE;  // fail open on any C++ exception (e.g. allocation failure)
    }
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);  // we do no per-thread work
    } else if (reason == DLL_PROCESS_DETACH) {
        delete g_ctx;  // unmaps the Bloom view
        g_ctx = nullptr;
        g_log.Shutdown();
    }
    return TRUE;
}

// Called once when LSA loads the package.
extern "C" BOOLEAN NTAPI InitializeChangeNotify(void) {
    __try {
        InitWorker();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Even on a fault, report success so the package stays loaded and fails open.
    }
    return TRUE;
}

// Called BEFORE a password is set/changed. TRUE accepts, FALSE rejects. SetOperation is
// TRUE for an administrative reset, FALSE for a user-initiated change.
extern "C" BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName,
                                        PUNICODE_STRING Password, BOOLEAN SetOperation) {
    __try {
        return DoFilter(AccountName, FullName, Password, SetOperation);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_log.ReportInternalError(L"structured exception", L"");
        return TRUE;  // fail open on any structured exception (e.g. access violation)
    }
}

// Called AFTER a password has changed. Notification only - cannot reject.
extern "C" NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING /*UserName*/, ULONG /*RelativeId*/,
                                               PUNICODE_STRING /*NewPassword*/) {
    return 0;  // STATUS_SUCCESS
}
