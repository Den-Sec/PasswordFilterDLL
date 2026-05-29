#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace pwfilter {

// A 160-bit SHA-1 digest (20 bytes, big-endian as produced by the algorithm).
struct Sha1Digest {
    std::uint8_t bytes[20];

    bool operator==(const Sha1Digest& o) const noexcept;
    bool operator!=(const Sha1Digest& o) const noexcept { return !(*this == o); }
};

// Streaming SHA-1. Feed data with Update(), read the result once with Final().
// Self-contained and portable - no OpenSSL/BCrypt dependency - so the breach check is
// unit-testable off-host. SHA-1 is used here purely to match the HIBP corpus, not as a
// security primitive.
class Sha1 {
 public:
    Sha1() noexcept { Reset(); }

    void Reset() noexcept;
    void Update(const void* data, std::size_t len) noexcept;
    Sha1Digest Final() noexcept;  // finalizes; call Reset() to reuse

 private:
    void ProcessBlock(const std::uint8_t block[64]) noexcept;

    std::uint32_t h_[5];
    std::uint64_t total_bits_;
    std::uint8_t buffer_[64];
    std::size_t buffer_len_;
};

// One-shot convenience.
Sha1Digest Sha1Hash(const void* data, std::size_t len) noexcept;

// Uppercase 40-char hex (the form HIBP uses), e.g. "A9993E364706816ABA3E25717850C26C9CD0D89D".
std::string ToHex(const Sha1Digest& d);

}  // namespace pwfilter
