#pragma once

namespace pwfilter {

// Why a password was accepted or rejected. The first failing rule (in evaluation order)
// is reported. These names are stable and used as Event Log keywords - they must never
// carry any part of the password itself.
enum class RuleId {
    Ok,                   // accepted
    TooShort,
    TooLong,
    NotEnoughClasses,     // fewer character classes than required
    RepeatRun,            // too many identical characters in a row (aaaa...)
    Sequence,             // ascending/descending run (abcd, 1234, dcba)
    KeyboardPattern,      // keyboard walk (qwerty, asdf)
    ContainsAccountName,  // contains the account (sAMAccountName)
    ContainsFullName,     // contains a token of the user's full name
    CompanyTerm,          // contains a configured company/brand term
    Blacklisted,          // exact match against the banned-password list
    Breached,             // found in the offline HIBP breach corpus
    InternalError         // an error occurred; see fail-open policy
};

// Stable, password-free keyword for logging/diagnostics, e.g. "Breached".
const char* RuleName(RuleId id) noexcept;

// The verdict for a single password.
struct ValidationResult {
    bool allowed;
    RuleId rule;

    static ValidationResult Allow() noexcept { return {true, RuleId::Ok}; }
    static ValidationResult Reject(RuleId r) noexcept { return {false, r}; }
};

}  // namespace pwfilter
