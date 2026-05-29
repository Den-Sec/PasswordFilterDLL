#include <gtest/gtest.h>

#include <cstring>

#include "pwfilter/secure.hpp"

TEST(Secure, ZeroesBuffer) {
    unsigned char buf[16];
    std::memset(buf, 0xAB, sizeof(buf));
    pwfilter::SecureZero(buf, sizeof(buf));
    for (unsigned char c : buf) {
        EXPECT_EQ(c, 0u);
    }
}

TEST(Secure, NullAndZeroLengthAreNoops) {
    pwfilter::SecureZero(nullptr, 0);
    unsigned char b = 5;
    pwfilter::SecureZero(&b, 0);
    EXPECT_EQ(b, 5u);
}

TEST(Secure, ScopedZeroWipesOnScopeExit) {
    unsigned char buf[8];
    std::memset(buf, 0xFF, sizeof(buf));
    {
        pwfilter::ScopedZero guard(buf, sizeof(buf));
        EXPECT_EQ(buf[0], 0xFFu);  // still set inside the scope
    }
    for (unsigned char c : buf) {
        EXPECT_EQ(c, 0u);
    }
}
