#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "pwfilter/result.hpp"

namespace pwfilter {

class Blacklist;
class IBreachChecker;

// All configurable knobs. Defaults are deliberately strict-but-sane (NIST SP 800-63B
// leans on length + breach checks rather than forced rotation/complexity, which is why
// breach checking is the centerpiece and complexity is tunable).
struct PolicyConfig {
    std::size_t min_length = 12;
    std::size_t max_length = 256;
    int required_classes = 3;  // of {lower, upper, digit, symbol}; 0 disables

    bool reject_keyboard_patterns = true;
    bool reject_sequences = true;
    std::size_t sequence_min_run = 4;
    std::size_t keyboard_min_run = 4;
    std::size_t max_repeat_run = 4;  // reject runs strictly longer than this; 0 disables

    bool reject_contains_account = true;
    bool reject_contains_fullname = true;
    std::size_t min_identity_token = 3;  // ignore account/name fragments shorter than this

    std::vector<std::u16string> company_terms;  // substring match, case-insensitive

    bool check_breach = true;
    bool fail_open_on_error = true;  // consumed by the DLL shim's error handling
};

// Stateless evaluator (other than its immutable config and the two borrowed services).
// Both `blacklist` and `breach` may be null; the corresponding checks are skipped.
// Evaluation runs cheapest-to-costliest and returns the FIRST violated rule, so the
// breach lookup only happens for passwords that already passed every local rule.
class Validator {
 public:
    Validator(PolicyConfig cfg, const Blacklist* blacklist, const IBreachChecker* breach) noexcept;

    ValidationResult Evaluate(std::u16string_view password,
                              std::u16string_view account_name = {},
                              std::u16string_view full_name = {}) const;

    const PolicyConfig& config() const noexcept { return cfg_; }

 private:
    PolicyConfig cfg_;
    const Blacklist* blacklist_;
    const IBreachChecker* breach_;
};

}  // namespace pwfilter
