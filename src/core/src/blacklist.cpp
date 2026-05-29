#include "pwfilter/blacklist.hpp"

#include "pwfilter/secure.hpp"

namespace pwfilter {
namespace {

char16_t LowerAscii(char16_t c) noexcept {
    if (c >= u'A' && c <= u'Z') {
        return static_cast<char16_t>(c + 32);
    }
    return c;
}

}  // namespace

Blacklist::Blacklist(bool case_insensitive) : ci_(case_insensitive) {}

std::u16string Blacklist::Normalize(std::u16string_view s) const {
    std::u16string r(s);
    if (ci_) {
        for (char16_t& c : r) {
            c = LowerAscii(c);
        }
    }
    return r;
}

void Blacklist::Add(std::u16string_view entry) {
    if (entry.empty()) {
        return;
    }
    set_.insert(Normalize(entry));
}

bool Blacklist::Contains(std::u16string_view password) const {
    if (set_.empty()) {
        return false;
    }
    std::u16string key = Normalize(password);
    const bool found = set_.find(key) != set_.end();
    // The query is a (lowercased) copy of the live password; do not leave it on the heap.
    SecureZero(key.data(), key.size() * sizeof(char16_t));
    return found;
}

}  // namespace pwfilter
