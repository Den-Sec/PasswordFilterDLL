# Unit tests for pwfilter_core, via GoogleTest (fetched at configure time).
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.15.2
)
# On Windows, make GoogleTest use the same dynamic CRT as our targets.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(pwfilter_tests
  test_sanity.cpp
  test_sha1.cpp
  test_utf.cpp
  test_secure.cpp
  test_bloom.cpp
  test_complexity.cpp
  test_blacklist.cpp
  test_policy.cpp
)
target_link_libraries(pwfilter_tests PRIVATE pwfilter_core pwfilter_flags GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(pwfilter_tests)
