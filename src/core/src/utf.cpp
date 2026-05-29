#include "pwfilter/utf.hpp"

namespace pwfilter {
namespace {

int Utf8Len(char32_t cp) noexcept {
    if (cp < 0x80u) return 1;
    if (cp < 0x800u) return 2;
    if (cp < 0x10000u) return 3;
    return 4;
}

void Utf8Encode(char32_t cp, std::uint8_t* p) noexcept {
    if (cp < 0x80u) {
        p[0] = static_cast<std::uint8_t>(cp);
    } else if (cp < 0x800u) {
        p[0] = static_cast<std::uint8_t>(0xC0 | (cp >> 6));
        p[1] = static_cast<std::uint8_t>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000u) {
        p[0] = static_cast<std::uint8_t>(0xE0 | (cp >> 12));
        p[1] = static_cast<std::uint8_t>(0x80 | ((cp >> 6) & 0x3F));
        p[2] = static_cast<std::uint8_t>(0x80 | (cp & 0x3F));
    } else {
        p[0] = static_cast<std::uint8_t>(0xF0 | (cp >> 18));
        p[1] = static_cast<std::uint8_t>(0x80 | ((cp >> 12) & 0x3F));
        p[2] = static_cast<std::uint8_t>(0x80 | ((cp >> 6) & 0x3F));
        p[3] = static_cast<std::uint8_t>(0x80 | (cp & 0x3F));
    }
}

// Decode UTF-16 to code points and feed each one's UTF-8 bytes to `emit`.
// `emit(bytes, len)` returns false to stop early (used for overflow).
template <class Emit>
bool ForEachUtf8(std::u16string_view in, Emit&& emit) {
    for (std::size_t i = 0; i < in.size(); ++i) {
        char32_t cp;
        const char16_t u = in[i];
        if (u >= 0xD800 && u <= 0xDBFF) {  // high surrogate
            if (i + 1 < in.size()) {
                const char16_t v = in[i + 1];
                if (v >= 0xDC00 && v <= 0xDFFF) {
                    cp = 0x10000u + ((static_cast<char32_t>(u - 0xD800) << 10) |
                                     static_cast<char32_t>(v - 0xDC00));
                    ++i;
                } else {
                    cp = 0xFFFD;  // unpaired high surrogate
                }
            } else {
                cp = 0xFFFD;  // truncated high surrogate at end
            }
        } else if (u >= 0xDC00 && u <= 0xDFFF) {  // lone low surrogate
            cp = 0xFFFD;
        } else {
            cp = u;
        }

        std::uint8_t b[4];
        const int len = Utf8Len(cp);
        Utf8Encode(cp, b);
        if (!emit(b, len)) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::size_t Utf16ToUtf8(std::u16string_view in, std::uint8_t* out, std::size_t out_cap) noexcept {
    std::size_t n = 0;
    const bool ok = ForEachUtf8(in, [&](const std::uint8_t* b, int len) noexcept {
        if (n + static_cast<std::size_t>(len) > out_cap) {
            return false;
        }
        for (int j = 0; j < len; ++j) {
            out[n++] = b[j];
        }
        return true;
    });
    return ok ? n : static_cast<std::size_t>(-1);
}

std::string Utf16ToUtf8(std::u16string_view in) {
    std::string s;
    s.reserve(in.size() * 3);
    ForEachUtf8(in, [&](const std::uint8_t* b, int len) {
        s.append(reinterpret_cast<const char*>(b), static_cast<std::size_t>(len));
        return true;
    });
    return s;
}

}  // namespace pwfilter
