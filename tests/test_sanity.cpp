// F0 smoke test: proves the build/link/test pipeline (CMake + GoogleTest + CTest) works
// end-to-end before any real logic is added. Replaced/augmented by real suites in F1+.
#include <gtest/gtest.h>

#include <string>

#include "pwfilter/version.hpp"

TEST(Sanity, VersionMatchesProject) {
    EXPECT_EQ(std::string(pwfilter::Version()), "0.1.0");
}
