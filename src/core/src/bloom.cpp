#include "pwfilter/bloom.hpp"

#include <cmath>
#include <cstring>

namespace pwfilter {
namespace {

std::uint64_t RoundUpTo8(std::uint64_t bits) noexcept {
    if (bits < 8) bits = 8;
    return (bits + 7u) & ~static_cast<std::uint64_t>(7u);
}

}  // namespace

BloomBuilder::Params BloomBuilder::ComputeParams(std::uint64_t n, double p) noexcept {
    if (n == 0) n = 1;
    if (!(p > 0.0 && p < 1.0)) p = 0.001;
    const double ln2 = std::log(2.0);

    const double m_real = -static_cast<double>(n) * std::log(p) / (ln2 * ln2);
    const std::uint64_t m = RoundUpTo8(static_cast<std::uint64_t>(std::ceil(m_real)));

    long k = std::lround((static_cast<double>(m) / static_cast<double>(n)) * ln2);
    if (k < 1) k = 1;
    if (k > 64) k = 64;  // 160-bit digest gives ample independent indices; cap pathology

    return Params{m, static_cast<std::uint32_t>(k)};
}

// ---- BloomFilter (reader) ---------------------------------------------------------

std::optional<BloomFilter> BloomFilter::FromMemory(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr || size < kBloomHeaderSize) {
        return std::nullopt;
    }
    if (std::memcmp(data, kBloomMagic, sizeof(kBloomMagic)) != 0) {
        return std::nullopt;
    }
    const auto get32 = [&](std::size_t off) -> std::uint32_t {
        return static_cast<std::uint32_t>(data[off]) |
               (static_cast<std::uint32_t>(data[off + 1]) << 8) |
               (static_cast<std::uint32_t>(data[off + 2]) << 16) |
               (static_cast<std::uint32_t>(data[off + 3]) << 24);
    };

    const std::uint32_t version = get32(8);
    const std::uint32_t k = get32(12);
    const std::uint64_t m = LoadLe64(data + 16);
    const std::uint64_t n = LoadLe64(data + 24);
    const std::uint32_t scheme = get32(32);

    if (version != kBloomVersion) return std::nullopt;
    if (scheme != kBloomSchemeSha1Le) return std::nullopt;
    if (m == 0 || (m % 8) != 0) return std::nullopt;
    if (k == 0) return std::nullopt;

    const std::uint64_t bitset_bytes = m / 8;
    if (static_cast<std::uint64_t>(size) != static_cast<std::uint64_t>(kBloomHeaderSize) + bitset_bytes) {
        return std::nullopt;
    }

    BloomFilter bf;
    bf.bitset_ = data + kBloomHeaderSize;
    bf.m_ = m;
    bf.k_ = k;
    bf.n_ = n;
    return bf;
}

bool BloomFilter::MaybeContains(const Sha1Digest& d) const noexcept {
    const std::uint64_t h1 = LoadLe64(d.bytes);
    const std::uint64_t h2 = LoadLe64(d.bytes + 8);
    for (std::uint32_t i = 0; i < k_; ++i) {
        const std::uint64_t idx = (h1 + static_cast<std::uint64_t>(i) * h2) % m_;
        if ((bitset_[static_cast<std::size_t>(idx >> 3)] &
             static_cast<std::uint8_t>(1u << (idx & 7u))) == 0) {
            return false;
        }
    }
    return true;
}

// ---- BloomBuilder -----------------------------------------------------------------

BloomBuilder::BloomBuilder(std::uint64_t expected_items, double false_positive_rate) {
    const Params p = ComputeParams(expected_items, false_positive_rate);
    m_ = p.m_bits;
    k_ = p.k;
    bitset_.assign(static_cast<std::size_t>(m_ / 8), 0u);
}

BloomBuilder::BloomBuilder(std::uint64_t m_bits, std::uint32_t k, int) {
    m_ = m_bits;
    k_ = k;
    bitset_.assign(static_cast<std::size_t>(m_ / 8), 0u);
}

BloomBuilder BloomBuilder::WithParams(std::uint64_t m_bits, std::uint32_t k) {
    const std::uint64_t m = RoundUpTo8(m_bits);
    return BloomBuilder(m, k < 1 ? 1u : k, 0);
}

void BloomBuilder::Add(const Sha1Digest& d) noexcept {
    const std::uint64_t h1 = LoadLe64(d.bytes);
    const std::uint64_t h2 = LoadLe64(d.bytes + 8);
    for (std::uint32_t i = 0; i < k_; ++i) {
        const std::uint64_t idx = (h1 + static_cast<std::uint64_t>(i) * h2) % m_;
        bitset_[static_cast<std::size_t>(idx >> 3)] |=
            static_cast<std::uint8_t>(1u << (idx & 7u));
    }
    ++n_;
}

std::vector<std::uint8_t> BloomBuilder::Serialize() const {
    std::vector<std::uint8_t> out(kBloomHeaderSize + bitset_.size(), 0u);
    std::memcpy(out.data(), kBloomMagic, sizeof(kBloomMagic));

    const auto put32 = [&](std::size_t off, std::uint32_t v) {
        out[off + 0] = static_cast<std::uint8_t>(v & 0xFF);
        out[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
        out[off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
        out[off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
    };
    const auto put64 = [&](std::size_t off, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            out[off + static_cast<std::size_t>(i)] =
                static_cast<std::uint8_t>((v >> (i * 8)) & 0xFFu);
        }
    };

    put32(8, kBloomVersion);
    put32(12, k_);
    put64(16, m_);
    put64(24, n_);
    put32(32, kBloomSchemeSha1Le);
    // bytes 36..63 are reserved and remain zero.

    if (!bitset_.empty()) {
        std::memcpy(out.data() + kBloomHeaderSize, bitset_.data(), bitset_.size());
    }
    return out;
}

}  // namespace pwfilter
