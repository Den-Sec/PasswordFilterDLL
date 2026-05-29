#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace pwfilter {

// UTF-16 -> UTF-8. Windows passwords arrive as UTF-16 code units; HIBP hashes the UTF-8
// encoding of the password, so we convert before SHA-1. Surrogate pairs are decoded;
// lone/invalid surrogates become U+FFFD, so the output is always well-formed UTF-8.
//
// char16_t (not wchar_t) is used deliberately: wchar_t is 16-bit on Windows but 32-bit on
// Linux, whereas char16_t is UTF-16 everywhere, keeping the core portable and testable.

// Bounded form for sensitive paths: writes into a caller buffer (typically a stack buffer
// that will be wiped). Returns bytes written, or SIZE_MAX if `out_cap` is too small.
// Does not NUL-terminate.
std::size_t Utf16ToUtf8(std::u16string_view in, std::uint8_t* out, std::size_t out_cap) noexcept;

// Convenience form for tests/tools (allocates). Avoid for live plaintext.
std::string Utf16ToUtf8(std::u16string_view in);

// UTF-8 -> UTF-16, for reading UTF-8 config files (blacklist, company terms) into the
// core's char16_t world. Invalid sequences become U+FFFD. Allocates; intended for
// configuration data, not live passwords.
std::u16string Utf8ToUtf16(std::string_view in);

}  // namespace pwfilter
