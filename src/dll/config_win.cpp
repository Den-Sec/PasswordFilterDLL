#include "config_win.hpp"

#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "pwfilter/utf.hpp"

namespace pwfilter {
namespace {

constexpr const wchar_t* kRegPath = L"SOFTWARE\\Den-Sec\\PasswordFilter";
constexpr std::size_t kMaxConfigFile = 64u * 1024u * 1024u;  // 64 MB safety cap

DWORD RegDword(HKEY key, const wchar_t* name, DWORD def) noexcept {
    DWORD val = 0;
    DWORD size = sizeof(val);
    DWORD type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(&val), &size) ==
            ERROR_SUCCESS &&
        type == REG_DWORD) {
        return val;
    }
    return def;
}

bool RegString(HKEY key, const wchar_t* name, wchar_t* buf, DWORD cch) noexcept {
    DWORD size = cch * sizeof(wchar_t);
    DWORD type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) ==
            ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        DWORD chars = static_cast<DWORD>(size / sizeof(wchar_t));
        if (chars >= cch) {
            chars = cch - 1;
        }
        buf[chars] = L'\0';  // guarantee termination
        return true;
    }
    return false;
}

bool IsAbsolute(const wchar_t* p) noexcept {
    return (p[0] != L'\0' && p[1] == L':') || (p[0] == L'\\' && p[1] == L'\\');
}

void PathAppendSimple(wchar_t* buf, std::size_t cch, const wchar_t* part) noexcept {
    std::size_t len = static_cast<std::size_t>(lstrlenW(buf));
    if (len > 0 && buf[len - 1] != L'\\' && len + 1 < cch) {
        buf[len++] = L'\\';
        buf[len] = L'\0';
    }
    if (len < cch) {
        lstrcpynW(buf + len, part, static_cast<int>(cch - len));
    }
}

void ResolveDefaultDataDir(wchar_t* buf, std::size_t cch) noexcept {
    const DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, static_cast<DWORD>(cch));
    if (n == 0 || n >= cch) {
        lstrcpynW(buf, L"C:\\ProgramData", static_cast<int>(cch));
    }
    PathAppendSimple(buf, cch, L"PasswordFilter");
}

void JoinPath(wchar_t* dst, std::size_t cch, const wchar_t* dir, const wchar_t* file) noexcept {
    if (IsAbsolute(file)) {
        lstrcpynW(dst, file, static_cast<int>(cch));
        return;
    }
    lstrcpynW(dst, dir, static_cast<int>(cch));
    PathAppendSimple(dst, cch, file);
}

bool ReadWholeFile(const wchar_t* path, std::vector<char>& out) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 ||
        static_cast<unsigned long long>(size.QuadPart) > kMaxConfigFile) {
        CloseHandle(h);
        return false;
    }
    out.resize(static_cast<std::size_t>(size.QuadPart));
    BOOL ok = TRUE;
    DWORD read = 0;
    if (!out.empty()) {
        ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    }
    CloseHandle(h);
    return ok == TRUE && read == out.size();
}

// Invoke fn(std::u16string) for each non-empty, non-comment, trimmed line (UTF-8 decoded).
template <class Fn>
void ForEachConfigLine(const std::vector<char>& data, Fn&& fn) {
    std::size_t i = 0;
    const std::size_t n = data.size();
    if (n >= 3 && static_cast<unsigned char>(data[0]) == 0xEF &&
        static_cast<unsigned char>(data[1]) == 0xBB && static_cast<unsigned char>(data[2]) == 0xBF) {
        i = 3;  // skip UTF-8 BOM
    }
    std::size_t start = i;
    for (; i <= n; ++i) {
        if (i == n || data[i] == '\n') {
            std::size_t end = i;
            while (end > start && (data[end - 1] == '\r' || data[end - 1] == ' ' ||
                                   data[end - 1] == '\t')) {
                --end;
            }
            std::size_t s = start;
            while (s < end && (data[s] == ' ' || data[s] == '\t')) {
                ++s;
            }
            if (end > s && data[s] != '#') {
                fn(Utf8ToUtf16(std::string_view(data.data() + s, end - s)));
            }
            start = i + 1;
        }
    }
}

void LoadBlacklistFile(Blacklist& bl, const wchar_t* path) {
    std::vector<char> data;
    if (!ReadWholeFile(path, data)) {
        return;
    }
    ForEachConfigLine(data, [&](std::u16string line) { bl.Add(line); });
}

void LoadTermsFile(std::vector<std::u16string>& terms, const wchar_t* path) {
    std::vector<char> data;
    if (!ReadWholeFile(path, data)) {
        return;
    }
    ForEachConfigLine(data, [&](std::u16string line) { terms.push_back(std::move(line)); });
}

}  // namespace

void FilterContext::MapBloom(const wchar_t* path) noexcept {
    file_ = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) {
        lstrcpynW(bloom_error_, L"file not found", 63);
        return;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file_, &size) || size.QuadPart <= 0) {
        lstrcpynW(bloom_error_, L"empty file", 63);
        return;
    }
    mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (mapping_ == nullptr) {
        lstrcpynW(bloom_error_, L"mapping failed", 63);
        return;
    }
    void* v = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
    if (v == nullptr) {
        lstrcpynW(bloom_error_, L"map view failed", 63);
        return;
    }
    view_ = static_cast<const std::uint8_t*>(v);
    view_size_ = static_cast<std::size_t>(size.QuadPart);
}

unsigned long FilterContext::blacklist_count() const noexcept {
    return blacklist_ ? static_cast<unsigned long>(blacklist_->size()) : 0u;
}

FilterContext* FilterContext::Create() noexcept {
    FilterContext* ctx = new (std::nothrow) FilterContext();
    if (ctx == nullptr) {
        return nullptr;
    }

    wchar_t data_dir[MAX_PATH];
    ResolveDefaultDataDir(data_dir, MAX_PATH);

    wchar_t bloom_name[MAX_PATH];
    wchar_t blacklist_name[MAX_PATH];
    wchar_t terms_name[MAX_PATH];
    lstrcpynW(bloom_name, L"breach.bloom", MAX_PATH);
    lstrcpynW(blacklist_name, L"blacklist.txt", MAX_PATH);
    lstrcpynW(terms_name, L"company_terms.txt", MAX_PATH);

    bool case_insensitive = true;

    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        PolicyConfig& c = ctx->cfg_;
        c.min_length = RegDword(key, L"MinLength", static_cast<DWORD>(c.min_length));
        c.max_length = RegDword(key, L"MaxLength", static_cast<DWORD>(c.max_length));
        c.required_classes = static_cast<int>(RegDword(key, L"RequiredClasses",
                                                       static_cast<DWORD>(c.required_classes)));
        c.reject_keyboard_patterns = RegDword(key, L"RejectKeyboardPatterns", 1) != 0;
        c.reject_sequences = RegDword(key, L"RejectSequences", 1) != 0;
        c.sequence_min_run = RegDword(key, L"SequenceMinRun", static_cast<DWORD>(c.sequence_min_run));
        c.keyboard_min_run = RegDword(key, L"KeyboardMinRun", static_cast<DWORD>(c.keyboard_min_run));
        c.max_repeat_run = RegDword(key, L"MaxRepeatRun", static_cast<DWORD>(c.max_repeat_run));
        c.reject_contains_account = RegDword(key, L"RejectContainsAccountName", 1) != 0;
        c.reject_contains_fullname = RegDword(key, L"RejectContainsFullName", 1) != 0;
        c.min_identity_token = RegDword(key, L"MinIdentityToken", static_cast<DWORD>(c.min_identity_token));
        c.check_breach = RegDword(key, L"CheckBreach", 1) != 0;
        c.fail_open_on_error = RegDword(key, L"FailOpenOnError", 1) != 0;
        case_insensitive = RegDword(key, L"BlacklistCaseInsensitive", 1) != 0;

        wchar_t tmp[MAX_PATH];
        if (RegString(key, L"DataDir", tmp, MAX_PATH)) lstrcpynW(data_dir, tmp, MAX_PATH);
        if (RegString(key, L"BloomFile", tmp, MAX_PATH)) lstrcpynW(bloom_name, tmp, MAX_PATH);
        if (RegString(key, L"BlacklistFile", tmp, MAX_PATH)) lstrcpynW(blacklist_name, tmp, MAX_PATH);
        if (RegString(key, L"CompanyTermsFile", tmp, MAX_PATH)) lstrcpynW(terms_name, tmp, MAX_PATH);
        RegCloseKey(key);
    }

    ctx->blacklist_.reset(new (std::nothrow) Blacklist(case_insensitive));
    if (!ctx->blacklist_) {
        delete ctx;
        return nullptr;
    }

    wchar_t bloom_path[MAX_PATH];
    wchar_t blacklist_path[MAX_PATH];
    wchar_t terms_path[MAX_PATH];
    JoinPath(bloom_path, MAX_PATH, data_dir, bloom_name);
    JoinPath(blacklist_path, MAX_PATH, data_dir, blacklist_name);
    JoinPath(terms_path, MAX_PATH, data_dir, terms_name);

    LoadBlacklistFile(*ctx->blacklist_, blacklist_path);
    LoadTermsFile(ctx->cfg_.company_terms, terms_path);

    if (ctx->cfg_.check_breach) {
        ctx->MapBloom(bloom_path);
        if (ctx->view_ != nullptr) {
            ctx->bloom_ = BloomFilter::FromMemory(ctx->view_, ctx->view_size_);
            if (ctx->bloom_.has_value()) {
                ctx->checker_.reset(new (std::nothrow) BloomBreachChecker(*ctx->bloom_));
            } else {
                lstrcpynW(ctx->bloom_error_, L"invalid bloom format", 63);
            }
        }
    }

    ctx->validator_.reset(
        new (std::nothrow) Validator(ctx->cfg_, ctx->blacklist_.get(), ctx->checker_.get()));
    if (!ctx->validator_) {
        delete ctx;
        return nullptr;
    }
    return ctx;
}

FilterContext::~FilterContext() {
    if (view_ != nullptr) {
        UnmapViewOfFile(view_);
        view_ = nullptr;
    }
    if (mapping_ != nullptr) {
        CloseHandle(mapping_);
        mapping_ = nullptr;
    }
    if (file_ != INVALID_HANDLE_VALUE) {
        CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }
}

}  // namespace pwfilter
