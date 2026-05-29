#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "pwfilter/sha1.hpp"

namespace pwfilter {

// Bloom filter over SHA-1 digests of breached passwords (the HIBP corpus).
//
// FILE FORMAT  ("PWBLOOM1") - all multi-byte integers are little-endian:
//   offset size field
//   0      8    magic   = "PWBLOOM1" (ASCII, no NUL)
//   8      4    version = 1                         (uint32)
//   12     4    k       = number of hash probes     (uint32)
//   16     8    m_bits  = number of bits            (uint64)
//   24     8    n_items = digests inserted (info)   (uint64)
//   32     4    scheme  = 1 (SHA1 LE-lane doubling) (uint32)
//   36     28   reserved (zero)
//   64     ..   bitset, ceil(m_bits/8) bytes; bit i = byte[i/8], mask (1 << (i % 8))
//
// PROBING (the Python builder in scripts/build_bloom.py replicates this exactly):
//   h1 = little-endian uint64 of digest bytes [0..8)
//   h2 = little-endian uint64 of digest bytes [8..16)
//   for i in 0..k-1:  idx = (h1 + i*h2) mod 2^64, then mod m_bits   // Kirsch-Mitzenmacher
// "Maybe present" iff all k bits are set. No false negatives; all-bits-set may be a
// false positive (which, for our use, harmlessly rejects a safe password).

inline constexpr char kBloomMagic[8] = {'P', 'W', 'B', 'L', 'O', 'O', 'M', '1'};
inline constexpr std::uint32_t kBloomVersion = 1;
inline constexpr std::uint32_t kBloomSchemeSha1Le = 1;
inline constexpr std::size_t kBloomHeaderSize = 64;

// Little-endian 64-bit load from 8 bytes.
inline std::uint64_t LoadLe64(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(p[0]) |
           (static_cast<std::uint64_t>(p[1]) << 8) |
           (static_cast<std::uint64_t>(p[2]) << 16) |
           (static_cast<std::uint64_t>(p[3]) << 24) |
           (static_cast<std::uint64_t>(p[4]) << 32) |
           (static_cast<std::uint64_t>(p[5]) << 40) |
           (static_cast<std::uint64_t>(p[6]) << 48) |
           (static_cast<std::uint64_t>(p[7]) << 56);
}

// Read-only Bloom filter over an in-memory image (e.g. an mmap'd file). Non-owning:
// the backing memory must outlive the BloomFilter. Querying is allocation-free and
// thread-safe (read-only), suitable for the LSASS hot path.
class BloomFilter {
 public:
    // Parse and validate an image. Returns nullopt if the header is malformed or its
    // declared size does not match `size`.
    static std::optional<BloomFilter> FromMemory(const std::uint8_t* data, std::size_t size);

    bool MaybeContains(const Sha1Digest& d) const noexcept;

    std::uint64_t bits() const noexcept { return m_; }
    std::uint32_t hashes() const noexcept { return k_; }
    std::uint64_t count() const noexcept { return n_; }

 private:
    BloomFilter() = default;

    const std::uint8_t* bitset_ = nullptr;  // points into the caller's image
    std::uint64_t m_ = 0;
    std::uint32_t k_ = 0;
    std::uint64_t n_ = 0;
};

// In-memory Bloom builder. The production artifact is built offline by the Python tool;
// this exists for unit tests and as a reference/optional C++ builder. Serialize()
// produces a byte-for-byte image in the format above.
class BloomBuilder {
 public:
    struct Params {
        std::uint64_t m_bits;  // rounded up to a multiple of 8
        std::uint32_t k;
    };

    // Compute optimal (m, k) from the expected item count and target false-positive rate
    // WITHOUT allocating the bitset:  m = -n*ln(p)/(ln2)^2 ,  k = round(m/n*ln2).
    // Exposed so the sizing math can be validated without building a multi-GB filter.
    static Params ComputeParams(std::uint64_t expected_items,
                                double false_positive_rate) noexcept;

    // Size the filter from the expected item count and target false-positive rate.
    BloomBuilder(std::uint64_t expected_items, double false_positive_rate);

    // Build with explicit parameters (useful for deterministic cross-language tests).
    static BloomBuilder WithParams(std::uint64_t m_bits, std::uint32_t k);

    void Add(const Sha1Digest& d) noexcept;

    std::vector<std::uint8_t> Serialize() const;

    std::uint64_t bits() const noexcept { return m_; }
    std::uint32_t hashes() const noexcept { return k_; }
    std::uint64_t added() const noexcept { return n_; }

 private:
    BloomBuilder(std::uint64_t m_bits, std::uint32_t k, int /*tag*/);

    std::vector<std::uint8_t> bitset_;
    std::uint64_t m_ = 0;
    std::uint32_t k_ = 0;
    std::uint64_t n_ = 0;
};

}  // namespace pwfilter
