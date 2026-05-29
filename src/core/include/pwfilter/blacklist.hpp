#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_set>

namespace pwfilter {

// Exact-match banned-password list (the company blacklist file): O(1) average lookup.
// Case-insensitivity (ASCII) is applied by normalizing both stored entries and the query
// to lowercase. The transient normalized query is wiped after lookup so a copy of the
// plaintext password does not linger on the heap.
class Blacklist {
 public:
    explicit Blacklist(bool case_insensitive = true);

    void Add(std::u16string_view entry);
    bool Contains(std::u16string_view password) const;

    std::size_t size() const noexcept { return set_.size(); }
    bool empty() const noexcept { return set_.empty(); }
    bool case_insensitive() const noexcept { return ci_; }

 private:
    std::u16string Normalize(std::u16string_view s) const;

    bool ci_;
    std::unordered_set<std::u16string> set_;
};

}  // namespace pwfilter
