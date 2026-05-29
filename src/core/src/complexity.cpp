#include "pwfilter/complexity.hpp"

namespace pwfilter {
namespace {

char16_t ToLowerAscii(char16_t c) noexcept {
    if (c >= u'A' && c <= u'Z') {
        return static_cast<char16_t>(c + 32);
    }
    return c;
}

// US-QWERTY rows used for keyboard-walk detection (lowercase). Returns true and sets
// (row, col) if `c` is on the keyboard, false otherwise.
bool KeyboardPos(char16_t c, int& row, int& col) noexcept {
    static const std::u16string_view kRows[] = {
        u"1234567890",
        u"qwertyuiop",
        u"asdfghjkl",
        u"zxcvbnm",
    };
    const char16_t lc = ToLowerAscii(c);
    for (int r = 0; r < 4; ++r) {
        const std::u16string_view row_str = kRows[r];
        for (std::size_t i = 0; i < row_str.size(); ++i) {
            if (row_str[i] == lc) {
                row = r;
                col = static_cast<int>(i);
                return true;
            }
        }
    }
    return false;
}

}  // namespace

int CharClassesPresent(std::u16string_view s) noexcept {
    int mask = 0;
    for (char16_t c : s) {
        if (c >= u'a' && c <= u'z') {
            mask |= kLower;
        } else if (c >= u'A' && c <= u'Z') {
            mask |= kUpper;
        } else if (c >= u'0' && c <= u'9') {
            mask |= kDigit;
        } else {
            mask |= kSymbol;  // ASCII punctuation/space and all non-ASCII
        }
    }
    return mask;
}

int CountCharClasses(std::u16string_view s) noexcept {
    int mask = CharClassesPresent(s);
    int count = 0;
    while (mask != 0) {
        count += (mask & 1);
        mask >>= 1;
    }
    return count;
}

bool HasExcessiveRepeat(std::u16string_view s, std::size_t max_run) noexcept {
    if (s.empty()) {
        return false;
    }
    std::size_t run = 1;
    for (std::size_t i = 1; i < s.size(); ++i) {
        if (s[i] == s[i - 1]) {
            ++run;
            if (run > max_run) {
                return true;
            }
        } else {
            run = 1;
        }
    }
    return false;
}

bool HasSequentialRun(std::u16string_view s, std::size_t min_run) noexcept {
    if (min_run < 2 || s.size() < min_run) {
        return false;
    }
    std::size_t up = 1;
    std::size_t down = 1;
    for (std::size_t i = 1; i < s.size(); ++i) {
        const int diff = static_cast<int>(s[i]) - static_cast<int>(s[i - 1]);
        if (diff == 1) {
            ++up;
            down = 1;
        } else if (diff == -1) {
            ++down;
            up = 1;
        } else {
            up = 1;
            down = 1;
        }
        if (up >= min_run || down >= min_run) {
            return true;
        }
    }
    return false;
}

bool HasKeyboardWalk(std::u16string_view s, std::size_t min_run) noexcept {
    if (min_run < 2 || s.size() < min_run) {
        return false;
    }
    std::size_t run = 1;
    int prev_row = -1;
    int prev_col = -1;
    bool prev_valid = false;
    for (char16_t c : s) {
        int row = 0;
        int col = 0;
        if (KeyboardPos(c, row, col)) {
            const int dc = col - prev_col;
            if (prev_valid && row == prev_row && (dc == 1 || dc == -1)) {
                ++run;
            } else {
                run = 1;
            }
            prev_row = row;
            prev_col = col;
            prev_valid = true;
        } else {
            run = 1;
            prev_valid = false;
        }
        if (run >= min_run) {
            return true;
        }
    }
    return false;
}

bool ContainsIgnoreCase(std::u16string_view haystack, std::u16string_view needle) noexcept {
    if (needle.empty() || needle.size() > haystack.size()) {
        return false;
    }
    const std::size_t last = haystack.size() - needle.size();
    for (std::size_t i = 0; i <= last; ++i) {
        std::size_t j = 0;
        for (; j < needle.size(); ++j) {
            if (ToLowerAscii(haystack[i + j]) != ToLowerAscii(needle[j])) {
                break;
            }
        }
        if (j == needle.size()) {
            return true;
        }
    }
    return false;
}

bool ContainsAccount(std::u16string_view password, std::u16string_view account,
                     std::size_t min_len) noexcept {
    if (account.size() < min_len) {
        return false;
    }
    return ContainsIgnoreCase(password, account);
}

std::vector<std::u16string_view> SplitNameTokens(std::u16string_view full_name,
                                                 std::size_t min_len) {
    const auto is_sep = [](char16_t c) noexcept {
        return c == u' ' || c == u'\t' || c == u'\n' || c == u'\r' || c == u',' ||
               c == u'.' || c == u'-' || c == u'_' || c == u';' || c == u'\'' ||
               c == u'\\' || c == u'/' || c == u'@';
    };
    std::vector<std::u16string_view> tokens;
    std::size_t start = 0;
    bool in_tok = false;
    for (std::size_t i = 0; i <= full_name.size(); ++i) {
        const bool sep = (i == full_name.size()) || is_sep(full_name[i]);
        if (!sep && !in_tok) {
            start = i;
            in_tok = true;
        } else if (sep && in_tok) {
            const std::size_t len = i - start;
            if (len >= min_len) {
                tokens.push_back(full_name.substr(start, len));
            }
            in_tok = false;
        }
    }
    return tokens;
}

bool ContainsFullNameToken(std::u16string_view password, std::u16string_view full_name,
                           std::size_t min_token_len) noexcept {
    // Manual split to keep this noexcept (no allocation): walk tokens in place.
    const auto is_sep = [](char16_t c) noexcept {
        return c == u' ' || c == u'\t' || c == u'\n' || c == u'\r' || c == u',' ||
               c == u'.' || c == u'-' || c == u'_' || c == u';' || c == u'\'' ||
               c == u'\\' || c == u'/' || c == u'@';
    };
    std::size_t start = 0;
    bool in_tok = false;
    for (std::size_t i = 0; i <= full_name.size(); ++i) {
        const bool sep = (i == full_name.size()) || is_sep(full_name[i]);
        if (!sep && !in_tok) {
            start = i;
            in_tok = true;
        } else if (sep && in_tok) {
            const std::size_t len = i - start;
            if (len >= min_token_len &&
                ContainsIgnoreCase(password, full_name.substr(start, len))) {
                return true;
            }
            in_tok = false;
        }
    }
    return false;
}

}  // namespace pwfilter
