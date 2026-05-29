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
  test_breach.cpp
  test_parity.cpp
)
target_link_libraries(pwfilter_tests PRIVATE pwfilter_core pwfilter_flags GTest::gtest_main)

# Cross-language parity: build a sample Bloom artifact with the Python builder, then have
# a C++ test read it back. Proves the on-disk format matches between the two languages.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  set(SAMPLE_BLOOM "${CMAKE_CURRENT_BINARY_DIR}/sample.bloom")
  set(SAMPLE_PLAIN "${CMAKE_SOURCE_DIR}/data/sample_breach_plain.txt")
  add_custom_command(
    OUTPUT "${SAMPLE_BLOOM}"
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/scripts/build_bloom.py"
            "${SAMPLE_PLAIN}" --plain -o "${SAMPLE_BLOOM}" --fp 0.001 --selftest
    DEPENDS "${SAMPLE_PLAIN}" "${CMAKE_SOURCE_DIR}/scripts/build_bloom.py"
    COMMENT "Building sample.bloom with the Python builder (cross-language parity)"
    VERBATIM)
  add_custom_target(sample_bloom DEPENDS "${SAMPLE_BLOOM}")
  add_dependencies(pwfilter_tests sample_bloom)
  target_compile_definitions(pwfilter_tests PRIVATE
    PWFILTER_HAVE_PYTHON_BLOOM=1
    SAMPLE_BLOOM_PATH="${SAMPLE_BLOOM}")
else()
  message(WARNING "Python3 not found - cross-language Bloom parity test will be skipped.")
  target_compile_definitions(pwfilter_tests PRIVATE PWFILTER_HAVE_PYTHON_BLOOM=0)
endif()

include(GoogleTest)
gtest_discover_tests(pwfilter_tests)
