#include "pwfilter/breach_bloom.hpp"

#include <cstdint>

#include "pwfilter/secure.hpp"
#include "pwfilter/sha1.hpp"
#include "pwfilter/utf.hpp"

namespace pwfilter {

bool BloomBreachChecker::IsBreached(std::u16string_view password) const {
    // Up to ~1024 chars (4 bytes each worst case). The Validator's length rule rejects
    // longer passwords before reaching here; if one slips through an exotic config and
    // overflows, we fail open (treat as not-breached) rather than guess.
    constexpr std::size_t kMaxUtf8 = 4096;
    std::uint8_t utf8[kMaxUtf8];
    ScopedZero guard(utf8, sizeof(utf8));  // wipe the plaintext-derived bytes on every exit

    const std::size_t n = Utf16ToUtf8(password, utf8, sizeof(utf8));
    if (n == static_cast<std::size_t>(-1)) {
        return false;  // too long to encode within the buffer -> fail open
    }

    const Sha1Digest digest = Sha1Hash(utf8, n);
    return filter_.MaybeContains(digest);
}

}  // namespace pwfilter
