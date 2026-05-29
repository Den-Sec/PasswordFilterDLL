#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

#include "pwfilter/blacklist.hpp"
#include "pwfilter/bloom.hpp"
#include "pwfilter/breach_bloom.hpp"
#include "pwfilter/policy.hpp"

namespace pwfilter {

// Loaded, ready-to-use filter state. Built once at InitializeChangeNotify, then borrowed
// read-only by every PasswordFilter call. NON-MOVABLE: the Validator stores pointers into
// this object, so it must keep a stable address - allocate with Create(), free with delete.
//
// Degrades gracefully: a missing/invalid Bloom file disables breach checking (the rest of
// the policy still applies); a missing blacklist/company-terms file is treated as empty.
class FilterContext {
 public:
    // Builds the context from registry + data files. Returns nullptr only on allocation
    // failure; otherwise always returns a usable (possibly degraded) context.
    static FilterContext* Create() noexcept;

    ~FilterContext();
    FilterContext(const FilterContext&) = delete;
    FilterContext& operator=(const FilterContext&) = delete;

    const Validator& validator() const noexcept { return *validator_; }
    bool breach_enabled() const noexcept { return checker_ != nullptr; }
    unsigned long blacklist_count() const noexcept;
    const wchar_t* bloom_error() const noexcept { return bloom_error_; }

 private:
    FilterContext() = default;
    void MapBloom(const wchar_t* path) noexcept;

    PolicyConfig cfg_;
    std::unique_ptr<Blacklist> blacklist_;
    std::unique_ptr<Validator> validator_;

    // Memory-mapped Bloom image (read-only, kept for the process lifetime).
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
    const std::uint8_t* view_ = nullptr;
    std::size_t view_size_ = 0;
    std::optional<BloomFilter> bloom_;
    std::unique_ptr<BloomBreachChecker> checker_;
    wchar_t bloom_error_[64] = L"";
};

}  // namespace pwfilter
