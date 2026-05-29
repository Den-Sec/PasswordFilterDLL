#include <gtest/gtest.h>

#include "pwfilter/complexity.hpp"

using namespace pwfilter;

TEST(Complexity, CountsCharacterClasses) {
    EXPECT_EQ(CountCharClasses(u"abcd"), 1);          // lower
    EXPECT_EQ(CountCharClasses(u"abcD"), 2);          // lower+upper
    EXPECT_EQ(CountCharClasses(u"abcD1"), 3);         // +digit
    EXPECT_EQ(CountCharClasses(u"abcD1!"), 4);        // +symbol
    EXPECT_EQ(CountCharClasses(u"caffè"), 2);         // non-ASCII 'è' counts as symbol/other
}

TEST(Complexity, DetectsExcessiveRepeat) {
    EXPECT_FALSE(HasExcessiveRepeat(u"aaaa", 4));     // exactly 4 allowed
    EXPECT_TRUE(HasExcessiveRepeat(u"aaaaa", 4));     // 5 in a row
    EXPECT_FALSE(HasExcessiveRepeat(u"aabbaa", 4));
    EXPECT_TRUE(HasExcessiveRepeat(u"Xbbbbb1", 4));
}

TEST(Complexity, DetectsSequences) {
    EXPECT_TRUE(HasSequentialRun(u"abcd", 4));
    EXPECT_TRUE(HasSequentialRun(u"1234", 4));
    EXPECT_TRUE(HasSequentialRun(u"dcba", 4));        // descending
    EXPECT_TRUE(HasSequentialRun(u"zzz4321zzz", 4));
    EXPECT_FALSE(HasSequentialRun(u"acbd", 4));
    EXPECT_FALSE(HasSequentialRun(u"abc", 4));        // shorter than min_run
}

TEST(Complexity, DetectsKeyboardWalks) {
    EXPECT_TRUE(HasKeyboardWalk(u"qwer", 4));
    EXPECT_TRUE(HasKeyboardWalk(u"asdf", 4));
    EXPECT_TRUE(HasKeyboardWalk(u"QWERTY", 4));       // case-insensitive
    EXPECT_TRUE(HasKeyboardWalk(u"rewq", 4));         // backwards
    EXPECT_TRUE(HasKeyboardWalk(u"x12345x", 4));
    EXPECT_FALSE(HasKeyboardWalk(u"qazx", 4));        // not a horizontal walk
    EXPECT_FALSE(HasKeyboardWalk(u"hello", 4));
}

TEST(Complexity, CaseInsensitiveSubstring) {
    EXPECT_TRUE(ContainsIgnoreCase(u"Summer2025!", u"summer"));
    EXPECT_TRUE(ContainsIgnoreCase(u"xSECURITIXy", u"securitix"));
    EXPECT_FALSE(ContainsIgnoreCase(u"abc", u"abcd"));    // needle longer
    EXPECT_FALSE(ContainsIgnoreCase(u"abc", u""));        // empty needle
}

TEST(Complexity, ContainsAccountRespectsMinLength) {
    EXPECT_TRUE(ContainsAccount(u"mrossi2025!", u"mrossi", 3));
    EXPECT_TRUE(ContainsAccount(u"xxMROSSIxx", u"mrossi", 3));
    EXPECT_FALSE(ContainsAccount(u"ab12cdef", u"ab", 3));  // account too short to consider
}

TEST(Complexity, SplitsNameTokens) {
    auto t = SplitNameTokens(u"Mario Rossi", 3);
    ASSERT_EQ(t.size(), 2u);
    EXPECT_EQ(t[0], u"Mario");
    EXPECT_EQ(t[1], u"Rossi");

    auto t2 = SplitNameTokens(u"Jo Di Pietro", 3);  // "Jo","Di" dropped (<3)
    ASSERT_EQ(t2.size(), 1u);
    EXPECT_EQ(t2[0], u"Pietro");
}

TEST(Complexity, DetectsFullNameTokenInPassword) {
    EXPECT_TRUE(ContainsFullNameToken(u"Rossi#2025", u"Mario Rossi", 3));
    EXPECT_TRUE(ContainsFullNameToken(u"xmarioX", u"Mario Rossi", 3));
    EXPECT_FALSE(ContainsFullNameToken(u"unrelated99", u"Mario Rossi", 3));
}
