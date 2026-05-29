#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "pwfilter/bloom.hpp"
#include "pwfilter/breach_bloom.hpp"
#include "pwfilter/policy.hpp"
#include "pwfilter/sha1.hpp"

using namespace pwfilter;

namespace {
// Build a Bloom image over plaintext passwords (hashing their UTF-8 bytes, like the
// offline builder does).
std::vector<std::uint8_t> BuildBloom(const std::vector<std::string>& passwords,
                                     double fp = 0.001) {
    BloomBuilder b(passwords.empty() ? 1 : passwords.size() * 10, fp);
    for (const auto& p : passwords) {
        b.Add(Sha1Hash(p.data(), p.size()));
    }
    return b.Serialize();
}
}  // namespace

TEST(BreachChecker, FlagsBreachedAndClearsClean) {
    const auto img = BuildBloom({"password", "123456", "qwerty", "letmein"});
    const auto bf = BloomFilter::FromMemory(img.data(), img.size());
    ASSERT_TRUE(bf.has_value());
    const BloomBreachChecker c(*bf);

    EXPECT_TRUE(c.IsBreached(u"password"));
    EXPECT_TRUE(c.IsBreached(u"123456"));
    EXPECT_TRUE(c.IsBreached(u"qwerty"));
    EXPECT_FALSE(c.IsBreached(u"Wm7!Kp4@Zb9#"));  // never inserted
}

TEST(BreachChecker, HashesViaUtf8ForNonAscii) {
    // The corpus stores SHA-1(UTF-8(password)). Insert "cafe" with a trailing U+00E9
    // expressed as explicit UTF-8 bytes, then query the UTF-16 form.
    const std::string cafe_utf8 = "caf\xC3\xA9";  // "café"
    const auto img = BuildBloom({cafe_utf8});
    const auto bf = BloomFilter::FromMemory(img.data(), img.size());
    ASSERT_TRUE(bf.has_value());
    const BloomBreachChecker c(*bf);

    std::u16string cafe_utf16 = u"caf";
    cafe_utf16.push_back(0x00E9);
    EXPECT_TRUE(c.IsBreached(cafe_utf16));
    EXPECT_FALSE(c.IsBreached(u"cafe"));  // ASCII 'e', different bytes
}

TEST(BreachChecker, PlugsIntoTheValidator) {
    const auto img = BuildBloom({"CorrectHorse9!"});  // passes all local rules
    const auto bf = BloomFilter::FromMemory(img.data(), img.size());
    ASSERT_TRUE(bf.has_value());
    const BloomBreachChecker c(*bf);

    Validator v(PolicyConfig{}, nullptr, &c);
    const auto rejected = v.Evaluate(u"CorrectHorse9!");
    EXPECT_FALSE(rejected.allowed);
    EXPECT_EQ(rejected.rule, RuleId::Breached);

    EXPECT_TRUE(v.Evaluate(u"Wm7!Kp4@Zb9#").allowed);  // strong + not breached
}
