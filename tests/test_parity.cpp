// Cross-language format parity: the C++ reader must accept a Bloom artifact produced by
// the Python builder, and find the items the builder inserted. If the lane math, bit
// order, or header layout disagreed between the two implementations, the inserted sample
// passwords would not be found - so this is a strong end-to-end check of the file format.
//
// Guarded by PWFILTER_HAVE_PYTHON_BLOOM: when Python is unavailable at configure time the
// sample artifact is not built and this test compiles out. SAMPLE_BLOOM_PATH is injected
// by tests/CMakeLists.txt.
#include <gtest/gtest.h>

#if defined(PWFILTER_HAVE_PYTHON_BLOOM) && PWFILTER_HAVE_PYTHON_BLOOM

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "pwfilter/bloom.hpp"
#include "pwfilter/sha1.hpp"

using namespace pwfilter;

namespace {
std::vector<std::uint8_t> ReadFile(const char* path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f),
                                     std::istreambuf_iterator<char>());
}
Sha1Digest H(const std::string& s) {
    return Sha1Hash(s.data(), s.size());
}
}  // namespace

TEST(CrossLang, CppReadsPythonBuiltBloom) {
    const auto img = ReadFile(SAMPLE_BLOOM_PATH);
    ASSERT_GE(img.size(), kBloomHeaderSize) << "sample.bloom not found or empty";

    const auto bf = BloomFilter::FromMemory(img.data(), img.size());
    ASSERT_TRUE(bf.has_value()) << "Python-built bloom failed C++ header validation";

    // Every one of these is in data/sample_breach_plain.txt. Finding them proves the two
    // implementations agree bit-for-bit.
    for (const char* pw : {"password", "123456", "qwerty", "letmein", "iloveyou", "admin"}) {
        EXPECT_TRUE(bf->MaybeContains(H(pw))) << "missing: " << pw;
    }

    // A strong password not in the sample must (almost surely) be absent.
    EXPECT_FALSE(bf->MaybeContains(H("Wm7!Kp4@Zb9#")));
}

#endif  // PWFILTER_HAVE_PYTHON_BLOOM
