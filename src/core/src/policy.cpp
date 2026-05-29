#include "pwfilter/policy.hpp"

#include <utility>

#include "pwfilter/blacklist.hpp"
#include "pwfilter/breach.hpp"
#include "pwfilter/complexity.hpp"

namespace pwfilter {

Validator::Validator(PolicyConfig cfg, const Blacklist* blacklist,
                     const IBreachChecker* breach) noexcept
    : cfg_(std::move(cfg)), blacklist_(blacklist), breach_(breach) {}

ValidationResult Validator::Evaluate(std::u16string_view password,
                                     std::u16string_view account_name,
                                     std::u16string_view full_name) const {
    // 1. Length.
    if (password.size() < cfg_.min_length) {
        return ValidationResult::Reject(RuleId::TooShort);
    }
    if (password.size() > cfg_.max_length) {
        return ValidationResult::Reject(RuleId::TooLong);
    }

    // 2. Character-class diversity.
    if (cfg_.required_classes > 0 && CountCharClasses(password) < cfg_.required_classes) {
        return ValidationResult::Reject(RuleId::NotEnoughClasses);
    }

    // 3. Excessive repeats (aaaa...).
    if (cfg_.max_repeat_run > 0 && HasExcessiveRepeat(password, cfg_.max_repeat_run)) {
        return ValidationResult::Reject(RuleId::RepeatRun);
    }

    // 4. Sequential runs (abcd, 1234).
    if (cfg_.reject_sequences && HasSequentialRun(password, cfg_.sequence_min_run)) {
        return ValidationResult::Reject(RuleId::Sequence);
    }

    // 5. Keyboard walks (qwerty, asdf).
    if (cfg_.reject_keyboard_patterns && HasKeyboardWalk(password, cfg_.keyboard_min_run)) {
        return ValidationResult::Reject(RuleId::KeyboardPattern);
    }

    // 6. Contains the account name.
    if (cfg_.reject_contains_account && !account_name.empty() &&
        ContainsAccount(password, account_name, cfg_.min_identity_token)) {
        return ValidationResult::Reject(RuleId::ContainsAccountName);
    }

    // 7. Contains a token of the user's full name.
    if (cfg_.reject_contains_fullname && !full_name.empty() &&
        ContainsFullNameToken(password, full_name, cfg_.min_identity_token)) {
        return ValidationResult::Reject(RuleId::ContainsFullName);
    }

    // 8. Contains a configured company/brand term.
    for (const std::u16string& term : cfg_.company_terms) {
        if (!term.empty() && ContainsIgnoreCase(password, term)) {
            return ValidationResult::Reject(RuleId::CompanyTerm);
        }
    }

    // 9. Exact blacklist.
    if (blacklist_ != nullptr && blacklist_->Contains(password)) {
        return ValidationResult::Reject(RuleId::Blacklisted);
    }

    // 10. Offline breach corpus (the only potentially expensive check; runs last).
    if (cfg_.check_breach && breach_ != nullptr && breach_->IsBreached(password)) {
        return ValidationResult::Reject(RuleId::Breached);
    }

    return ValidationResult::Allow();
}

}  // namespace pwfilter
