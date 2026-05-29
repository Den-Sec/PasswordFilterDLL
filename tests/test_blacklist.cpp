#include <gtest/gtest.h>

#include "pwfilter/blacklist.hpp"

using pwfilter::Blacklist;

TEST(Blacklist, ExactMatchCaseInsensitiveByDefault) {
    Blacklist bl;  // case-insensitive
    bl.Add(u"Comes@2025");
    EXPECT_TRUE(bl.Contains(u"Comes@2025"));
    EXPECT_TRUE(bl.Contains(u"comes@2025"));
    EXPECT_TRUE(bl.Contains(u"COMES@2025"));
    EXPECT_FALSE(bl.Contains(u"Comes@2026"));
    EXPECT_FALSE(bl.Contains(u"xComes@2025"));  // exact match, not substring
}

TEST(Blacklist, CaseSensitiveMode) {
    Blacklist bl(false);
    bl.Add(u"Secret1!");
    EXPECT_TRUE(bl.Contains(u"Secret1!"));
    EXPECT_FALSE(bl.Contains(u"secret1!"));
}

TEST(Blacklist, EmptyDuplicatesAndSize) {
    Blacklist bl;
    EXPECT_TRUE(bl.empty());
    EXPECT_FALSE(bl.Contains(u"anything"));

    bl.Add(u"alpha");
    bl.Add(u"beta");
    bl.Add(u"ALPHA");  // duplicate under case-insensitive normalization
    EXPECT_EQ(bl.size(), 2u);

    bl.Add(u"");  // ignored
    EXPECT_EQ(bl.size(), 2u);
    EXPECT_FALSE(bl.empty());
}
