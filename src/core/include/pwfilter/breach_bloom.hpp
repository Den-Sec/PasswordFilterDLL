#pragma once

#include "pwfilter/bloom.hpp"
#include "pwfilter/breach.hpp"

namespace pwfilter {

// IBreachChecker backed by a loaded Bloom filter. Converts the plaintext to UTF-8, takes
// its SHA-1, and queries the filter - the same pipeline the offline builder used to insert
// the HIBP corpus. The UTF-8 buffer is a wiped stack buffer, so no heap copy of the live
// password is created here.
//
// Borrows the BloomFilter (which in turn borrows the mmap'd image); both must outlive this
// checker. Querying is read-only and safe to call concurrently.
class BloomBreachChecker : public IBreachChecker {
 public:
    explicit BloomBreachChecker(const BloomFilter& filter) noexcept : filter_(filter) {}

    bool IsBreached(std::u16string_view password) const override;

 private:
    const BloomFilter& filter_;
};

}  // namespace pwfilter
