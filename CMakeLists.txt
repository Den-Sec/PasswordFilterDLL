# PasswordFilterDLL - LSA password filter for Active Directory (defensive)
# https://github.com/Den-Sec/PasswordFilterDLL
#
# Three targets:
#   pwfilter_core      - pure C++17 validation logic (NO windows.h) -> unit-testable anywhere
#   PasswordFilterDLL  - the LSASS-loaded DLL shim (Windows only) -> links pwfilter_core
#   pwfilter_tests     - GoogleTest suite over pwfilter_core
cmake_minimum_required(VERSION 3.21)

project(PasswordFilterDLL
  VERSION 0.1.0
  DESCRIPTION "LSA password filter for Active Directory: offline breach-list (HIBP), complexity rules, blacklist, event logging"
  HOMEPAGE_URL "https://github.com/Den-Sec/PasswordFilterDLL"
  LANGUAGES CXX)

option(PWFILTER_BUILD_TESTS "Build the unit test suite" ON)
option(PWFILTER_BUILD_DLL   "Build the LSA password filter DLL (Windows only)" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Place the import library next to nothing useful; keep the tree predictable.
if(MSVC)
  # /W4 high warnings, /permissive- strict conformance, /EHsc C++ exceptions.
  add_compile_options(/W4 /permissive- /EHsc)
  # Treat warnings as errors in CI-style builds; relax locally via -DPWFILTER_WERROR=OFF.
  option(PWFILTER_WERROR "Treat compiler warnings as errors" ON)
  if(PWFILTER_WERROR)
    add_compile_options(/WX)
  endif()
endif()

# Pure, portable validation core (no Windows dependency).
add_subdirectory(src/core)

# The LSASS-resident DLL is Windows-only.
if(WIN32 AND PWFILTER_BUILD_DLL)
  add_subdirectory(src/dll)
endif()

if(PWFILTER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
