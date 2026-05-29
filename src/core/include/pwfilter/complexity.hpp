#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

namespace pwfilter {

// Character classes (ASCII). Non-ASCII code units are counted as kSymbol ("other"), so a
// password using accented letters still earns a class. This keeps classification
// dependency-free and predictable without pulling in full Unicode tables.
enum CharClass {
    kLower = 1,
    kUpper = 2,
    kDigit = 4,
    kSymbol = 8,
};

// Bitmask of classes present, and its population count.
int CharClassesPresent(std::u16string_view s) noexcept;
int CountCharClasses(std::u16string_view s) noexcept;

// True if any character repeats more than `max_run` times in a row (e.g. "aaaaa").
bool HasExcessiveRepeat(std::u16string_view s, std::size_t max_run) noexcept;

// True if there is an ascending or descending run by code-unit value of length
// >= `min_run` (e.g. "abcd", "1234", "dcba").
bool HasSequentialRun(std::u16string_view s, std::size_t min_run) noexcept;

// True if there is a horizontal US-QWERTY keyboard walk of length >= `min_run`
// (e.g. "qwer", "asdf", "12345"); case-insensitive, forwards or backwards.
bool HasKeyboardWalk(std::u16string_view s, std::size_t min_run) noexcept;

// Case-insensitive (ASCII) substring test. Empty needle -> false.
bool ContainsIgnoreCase(std::u16string_view haystack, std::u16string_view needle) noexcept;

// True if `password` contains `account` (case-insensitive), when account length >= min_len.
bool ContainsAccount(std::u16string_view password, std::u16string_view account,
                     std::size_t min_len) noexcept;

// Split `full_name` on whitespace/punctuation into tokens of length >= min_len (views into
// the input).
std::vector<std::u16string_view> SplitNameTokens(std::u16string_view full_name,
                                                 std::size_t min_len);

// True if `password` contains any full-name token of length >= min_token_len
// (case-insensitive).
bool ContainsFullNameToken(std::u16string_view password, std::u16string_view full_name,
                           std::size_t min_token_len) noexcept;

}  // namespace pwfilter
