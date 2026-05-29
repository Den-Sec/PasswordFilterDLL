#include "pwfilter/result.hpp"

namespace pwfilter {

const char* RuleName(RuleId id) noexcept {
    switch (id) {
        case RuleId::Ok: return "Ok";
        case RuleId::TooShort: return "TooShort";
        case RuleId::TooLong: return "TooLong";
        case RuleId::NotEnoughClasses: return "NotEnoughClasses";
        case RuleId::RepeatRun: return "RepeatRun";
        case RuleId::Sequence: return "Sequence";
        case RuleId::KeyboardPattern: return "KeyboardPattern";
        case RuleId::ContainsAccountName: return "ContainsAccountName";
        case RuleId::ContainsFullName: return "ContainsFullName";
        case RuleId::CompanyTerm: return "CompanyTerm";
        case RuleId::Blacklisted: return "Blacklisted";
        case RuleId::Breached: return "Breached";
        case RuleId::InternalError: return "InternalError";
    }
    return "Unknown";
}

}  // namespace pwfilter
