#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include "pwfilter/utf.hpp"

using pwfilter::Utf16ToUtf8;

namespace {
std::string Bytes(std::initializer_list<int> b) {
    std::string s;
    for (int x : b) s.push_back(static_cast<char>(static_cast<unsigned char>(x)));
    return s;
}
}  // namespace

TEST(Utf, AsciiPassthrough) {
    EXPECT_EQ(Utf16ToUtf8(u"abc123"), "abc123");
    EXPECT_EQ(Utf16ToUtf8(u""), "");
}

TEST(Utf, TwoAndThreeByteSequences) {
    std::u16string in;
    in.push_back(0x00E9);  // é  -> C3 A9
    in.push_back(0x20AC);  // €  -> E2 82 AC
    EXPECT_EQ(Utf16ToUtf8(in), Bytes({0xC3, 0xA9, 0xE2, 0x82, 0xAC}));
}

TEST(Utf, SurrogatePairDecoded) {
    std::u16string in;
    in.push_back(0xD83D);  // U+1F600 grinning face -> F0 9F 98 80
    in.push_back(0xDE00);
    EXPECT_EQ(Utf16ToUtf8(in), Bytes({0xF0, 0x9F, 0x98, 0x80}));
}

TEST(Utf, LoneSurrogatesBecomeReplacement) {
    std::u16string high;
    high.push_back(0xD83D);  // lone high -> U+FFFD = EF BF BD
    EXPECT_EQ(Utf16ToUtf8(high), Bytes({0xEF, 0xBF, 0xBD}));

    std::u16string low;
    low.push_back(0xDC00);  // lone low -> U+FFFD
    EXPECT_EQ(Utf16ToUtf8(low), Bytes({0xEF, 0xBF, 0xBD}));
}

TEST(Utf, BoundedWriteSucceeds) {
    std::uint8_t buf[8];
    const std::size_t n = Utf16ToUtf8(u"hello", buf, sizeof(buf));
    ASSERT_EQ(n, 5u);
    EXPECT_EQ(std::string(reinterpret_cast<char*>(buf), n), "hello");
}

TEST(Utf, BoundedWriteReportsOverflow) {
    std::uint8_t small[3];
    EXPECT_EQ(Utf16ToUtf8(u"hello", small, sizeof(small)), static_cast<std::size_t>(-1));
}

TEST(Utf, BoundedAndAllocatingAgree) {
    std::u16string in;
    in.push_back(0x0041);  // A
    in.push_back(0x00E9);  // é
    in.push_back(0xD83D);  // emoji pair
    in.push_back(0xDE00);
    const std::string expected = Utf16ToUtf8(in);
    std::uint8_t buf[32];
    const std::size_t n = Utf16ToUtf8(in, buf, sizeof(buf));
    ASSERT_NE(n, static_cast<std::size_t>(-1));
    EXPECT_EQ(std::string(reinterpret_cast<char*>(buf), n), expected);
}
