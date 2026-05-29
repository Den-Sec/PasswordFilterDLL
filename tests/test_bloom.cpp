#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "pwfilter/bloom.hpp"
#include "pwfilter/sha1.hpp"

using namespace pwfilter;

namespace {
Sha1Digest H(const std::string& s) {
    return Sha1Hash(s.data(), s.size());
}
}  // namespace

TEST(Bloom, InsertedAreAlwaysFound) {
    // No false negatives is the core guarantee.
    BloomBuilder b(1000, 0.001);
    const std::vector<std::string> words = {"password", "123456", "qwerty",
                                            "letmein", "dragon", "monkey"};
    for (const auto& w : words) b.Add(H(w));

    const auto img = b.Serialize();
    const auto bf = BloomFilter::FromMemory(img.data(), img.size());
    ASSERT_TRUE(bf.has_value());
    for (const auto& w : words) {
        EXPECT_TRUE(bf->MaybeContains(H(w))) << "missing: " << w;
    }
}

TEST(Bloom, AbsentItemsRarelyMatch) {
    // Heavily under-loaded filter -> false positives are vanishingly unlikely.
    BloomBuilder b(100000, 0.0001);
    for (int i = 0; i < 1000; ++i) b.Add(H("inserted-" + std::to_string(i)));

    const auto img = b.Serialize();
    const auto bf = BloomFilter::FromMemory(img.data(), img.size());
    ASSERT_TRUE(bf.has_value());

    int fp = 0;
    for (int i = 0; i < 5000; ++i) {
        if (bf->MaybeContains(H("absent-" + std::to_string(i)))) ++fp;
    }
    EXPECT_LE(fp, 5);  // expected ~0 at this sizing
}

TEST(Bloom, SerializeRoundTripsHeaderFields) {
    BloomBuilder b = BloomBuilder::WithParams(1024, 7);
    b.Add(H("x"));
    const auto img = b.Serialize();
    EXPECT_EQ(img.size(), kBloomHeaderSize + 1024u / 8u);

    const auto bf = BloomFilter::FromMemory(img.data(), img.size());
    ASSERT_TRUE(bf.has_value());
    EXPECT_EQ(bf->bits(), 1024u);
    EXPECT_EQ(bf->hashes(), 7u);
    EXPECT_EQ(bf->count(), 1u);
    EXPECT_TRUE(bf->MaybeContains(H("x")));
}

TEST(Bloom, SizingMatchesTheTextbookFormula) {
    // ~2 GB at 0.1% FP for the ~1.3B HIBP corpus, k ~= 10. Validate the math via
    // ComputeParams (no 2 GB allocation) so the README figure is grounded in code.
    const auto p = BloomBuilder::ComputeParams(1300000000ULL, 0.001);
    // m = -n ln p / (ln2)^2  ~= 1.869e10 bits ~= 2.18 GiB ; k = round(m/n ln2) ~= 10
    EXPECT_GE(p.m_bits, 18500000000ULL);
    EXPECT_LE(p.m_bits, 18900000000ULL);
    EXPECT_EQ(p.k, 10u);
    EXPECT_EQ(p.m_bits % 8, 0u);
}

TEST(Bloom, RejectsMalformedImages) {
    // Too small for a header.
    std::vector<std::uint8_t> tiny(10, 0);
    EXPECT_FALSE(BloomFilter::FromMemory(tiny.data(), tiny.size()).has_value());

    BloomBuilder b = BloomBuilder::WithParams(64, 3);
    auto img = b.Serialize();

    // Truncated bitset.
    EXPECT_FALSE(BloomFilter::FromMemory(img.data(), img.size() - 1).has_value());

    // Corrupt magic.
    auto bad = img;
    bad[0] = 'X';
    EXPECT_FALSE(BloomFilter::FromMemory(bad.data(), bad.size()).has_value());
}
