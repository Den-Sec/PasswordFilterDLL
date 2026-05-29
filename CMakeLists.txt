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

# Strict warnings applied ONLY to our own targets (link pwfilter_flags), never to fetched
# dependencies (GoogleTest) or the Windows SDK headers - otherwise their warnings would
# break our warnings-as-errors build. Our headers are quote-included; system/dependency
# headers are angle-included and silenced via /external.
option(PWFILTER_WERROR "Treat compiler warnings as errors" ON)
add_library(pwfilter_flags INTERFACE)
if(MSVC)
  target_compile_options(pwfilter_flags INTERFACE
    /W4 /permissive- /utf-8 /external:anglebrackets /external:W0)
  if(PWFILTER_WERROR)
    target_compile_options(pwfilter_flags INTERFACE /WX)
  endif()
else()
  target_compile_options(pwfilter_flags INTERFACE -Wall -Wextra -Wpedantic)
  if(PWFILTER_WERROR)
    target_compile_options(pwfilter_flags INTERFACE -Werror)
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
