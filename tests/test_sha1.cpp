#include <gtest/gtest.h>

#include <string>

#include "pwfilter/sha1.hpp"

using pwfilter::Sha1;
using pwfilter::Sha1Hash;
using pwfilter::ToHex;

namespace {
std::string HexOf(const std::string& s) {
    return ToHex(Sha1Hash(s.data(), s.size()));
}
}  // namespace

TEST(Sha1, NistVectors) {
    EXPECT_EQ(HexOf(""), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
    EXPECT_EQ(HexOf("abc"), "A9993E364706816ABA3E25717850C26C9CD0D89D");
    EXPECT_EQ(HexOf("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
              "84983E441C3BD26EBAAE4AA1F95129E5E54670F1");
    EXPECT_EQ(HexOf("The quick brown fox jumps over the lazy dog"),
              "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12");
}

TEST(Sha1, KnownPasswordHashes) {
    // These are the canonical HIBP SHA-1 values; the breach check relies on them.
    EXPECT_EQ(HexOf("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    EXPECT_EQ(HexOf("123456"), "7C4A8D09CA3762AF61E59520943DC26494F8941B");
}

TEST(Sha1, MillionA) {
    const std::string a(1000000, 'a');
    EXPECT_EQ(ToHex(Sha1Hash(a.data(), a.size())),
              "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F");
}

TEST(Sha1, StreamingMatchesOneShot) {
    const std::string msg = "The quick brown fox jumps over the lazy dog";
    Sha1 s;
    s.Update(msg.data(), 10);
    s.Update(msg.data() + 10, msg.size() - 10);
    EXPECT_EQ(ToHex(s.Final()), ToHex(Sha1Hash(msg.data(), msg.size())));
}

TEST(Sha1, EqualityOperators) {
    EXPECT_EQ(Sha1Hash("abc", 3), Sha1Hash("abc", 3));
    EXPECT_NE(Sha1Hash("abc", 3), Sha1Hash("abd", 3));
}
