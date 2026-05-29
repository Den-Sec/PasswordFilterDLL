# pwfilter_core - pure C++17 validation logic, no Windows dependency.
# Everything that decides whether a password is acceptable lives here so it can be
# unit-tested off-host (and on Linux CI) without loading anything into LSASS.
add_library(pwfilter_core STATIC
  src/version.cpp
  src/secure.cpp
  src/sha1.cpp
  src/utf.cpp
  src/bloom.cpp
  src/result.cpp
  src/complexity.cpp
  src/blacklist.cpp
  src/policy.cpp
)

target_include_directories(pwfilter_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(pwfilter_core PUBLIC cxx_std_17)
target_link_libraries(pwfilter_core PRIVATE pwfilter_flags)
