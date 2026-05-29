#include "eventlog.hpp"

// When mc.exe is available the build generates a real message catalog (nice text in Event
// Viewer). Otherwise we fall back to plain numeric event IDs - events still carry the
// metadata as raw insertion strings, just without a formatted description.
#if defined(PWFILTER_HAVE_MC) && PWFILTER_HAVE_MC
#include "messages.h"
#else
#define MSG_PASSWORD_REJECTED 1u
#define MSG_FILTER_INITIALIZED 2u
#define MSG_INTERNAL_ERROR 3u
#define MSG_BLOOM_UNAVAILABLE 4u
#endif

namespace pwfilter {
namespace {

// Minimal unsigned-to-wide formatter, so we avoid pulling in the CRT/user32 just to print
// a count from inside LSASS. buf must hold at least 11 wchar_t.
void UlongToW(unsigned long v, wchar_t* buf) noexcept {
    wchar_t tmp[11];
    int i = 0;
    if (v == 0) {
        buf[0] = L'0';
        buf[1] = L'\0';
        return;
    }
    while (v != 0 && i < 10) {
        tmp[i++] = static_cast<wchar_t>(L'0' + (v % 10));
        v /= 10;
    }
    int j = 0;
    while (i > 0) {
        buf[j++] = tmp[--i];
    }
    buf[j] = L'\0';
}

}  // namespace

const wchar_t* RuleNameW(RuleId rule) noexcept {
    switch (rule) {
        case RuleId::Ok: return L"Ok";
        case RuleId::TooShort: return L"TooShort";
        case RuleId::TooLong: return L"TooLong";
        case RuleId::NotEnoughClasses: return L"NotEnoughClasses";
        case RuleId::RepeatRun: return L"RepeatRun";
        case RuleId::Sequence: return L"Sequence";
        case RuleId::KeyboardPattern: return L"KeyboardPattern";
        case RuleId::ContainsAccountName: return L"ContainsAccountName";
        case RuleId::ContainsFullName: return L"ContainsFullName";
        case RuleId::CompanyTerm: return L"CompanyTerm";
        case RuleId::Blacklisted: return L"Blacklisted";
        case RuleId::Breached: return L"Breached";
        case RuleId::InternalError: return L"InternalError";
    }
    return L"Unknown";
}

void EventLog::Init() noexcept {
    source_ = RegisterEventSourceW(nullptr, L"Den-Sec PasswordFilter");
}

void EventLog::Shutdown() noexcept {
    if (source_ != nullptr) {
        DeregisterEventSource(source_);
        source_ = nullptr;
    }
}

void EventLog::ReportInitialized(bool breach_enabled, unsigned long blacklist_count) noexcept {
    if (source_ == nullptr) {
        return;
    }
    wchar_t count_buf[11];
    UlongToW(blacklist_count, count_buf);
    const wchar_t* strings[2] = {breach_enabled ? L"enabled" : L"disabled", count_buf};
    ReportEventW(source_, EVENTLOG_INFORMATION_TYPE, 0, MSG_FILTER_INITIALIZED, nullptr, 2,
                 0, strings, nullptr);
}

void EventLog::ReportRejected(const wchar_t* account, bool set_operation, RuleId rule) noexcept {
    if (source_ == nullptr) {
        return;
    }
    const wchar_t* strings[3] = {account != nullptr ? account : L"",
                                 set_operation ? L"admin set" : L"user change",
                                 RuleNameW(rule)};
    ReportEventW(source_, EVENTLOG_INFORMATION_TYPE, 0, MSG_PASSWORD_REJECTED, nullptr, 3,
                 0, strings, nullptr);
}

void EventLog::ReportInternalError(const wchar_t* where, const wchar_t* account) noexcept {
    if (source_ == nullptr) {
        return;
    }
    const wchar_t* strings[2] = {where != nullptr ? where : L"",
                                 account != nullptr ? account : L""};
    ReportEventW(source_, EVENTLOG_WARNING_TYPE, 0, MSG_INTERNAL_ERROR, nullptr, 2, 0,
                 strings, nullptr);
}

void EventLog::ReportBloomUnavailable(const wchar_t* detail) noexcept {
    if (source_ == nullptr) {
        return;
    }
    const wchar_t* strings[1] = {detail != nullptr ? detail : L""};
    ReportEventW(source_, EVENTLOG_WARNING_TYPE, 0, MSG_BLOOM_UNAVAILABLE, nullptr, 1, 0,
                 strings, nullptr);
}

}  // namespace pwfilter
