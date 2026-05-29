#pragma once

#include <windows.h>

#include "pwfilter/result.hpp"

namespace pwfilter {

// Thin wrapper over the Windows Event Log. Logs METADATA ONLY - never any part of the
// password. Win32-only and allocation-free, so it is safe to call even from the SEH
// fail-open handler. If the source is registered with this DLL as its EventMessageFile
// (done by the installer), Event Viewer renders friendly text; otherwise it still shows
// the raw insertion strings.
class EventLog {
 public:
    void Init() noexcept;      // RegisterEventSource
    void Shutdown() noexcept;  // DeregisterEventSource

    void ReportInitialized(bool breach_enabled, unsigned long blacklist_count) noexcept;
    void ReportRejected(const wchar_t* account, bool set_operation, RuleId rule) noexcept;
    void ReportInternalError(const wchar_t* where, const wchar_t* account) noexcept;
    void ReportBloomUnavailable(const wchar_t* detail) noexcept;

 private:
    HANDLE source_ = nullptr;
};

// Wide, password-free rule name for event insertion strings.
const wchar_t* RuleNameW(RuleId rule) noexcept;

}  // namespace pwfilter
