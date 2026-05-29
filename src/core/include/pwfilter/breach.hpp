#pragma once

#include <string_view>

namespace pwfilter {

// Abstraction over "is this password known to be breached?". The Validator depends only
// on this interface, so the policy logic can be tested with a fake and the real
// Bloom-backed implementation (BloomBreachChecker, added in F3) stays decoupled.
//
// Implementations receive the plaintext (UTF-16) and are responsible for hashing it
// (UTF-8 -> SHA-1) and wiping any derived copies. Implementations must be safe to call
// concurrently (the LSASS path is read-only over the loaded Bloom image).
class IBreachChecker {
 public:
    virtual ~IBreachChecker() = default;

    // Returns true if the password is present in the breach corpus. Should return false
    // (not throw) when it cannot decide, so the caller can fail open.
    virtual bool IsBreached(std::u16string_view password) const = 0;
};

}  // namespace pwfilter
