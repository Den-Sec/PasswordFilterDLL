#include "pwfilter/sha1.hpp"

#include <cstring>

namespace pwfilter {

bool Sha1Digest::operator==(const Sha1Digest& o) const noexcept {
    return std::memcmp(bytes, o.bytes, sizeof(bytes)) == 0;
}

namespace {

inline std::uint32_t Rol32(std::uint32_t v, int bits) noexcept {
    return (v << bits) | (v >> (32 - bits));
}

}  // namespace

void Sha1::Reset() noexcept {
    h_[0] = 0x67452301u;
    h_[1] = 0xEFCDAB89u;
    h_[2] = 0x98BADCFEu;
    h_[3] = 0x10325476u;
    h_[4] = 0xC3D2E1F0u;
    total_bits_ = 0;
    buffer_len_ = 0;
}

void Sha1::ProcessBlock(const std::uint8_t block[64]) noexcept {
    std::uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = (std::uint32_t(block[i * 4]) << 24) |
               (std::uint32_t(block[i * 4 + 1]) << 16) |
               (std::uint32_t(block[i * 4 + 2]) << 8) |
               (std::uint32_t(block[i * 4 + 3]));
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = Rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
    for (int i = 0; i < 80; ++i) {
        std::uint32_t f = 0, k = 0;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        std::uint32_t tmp = Rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = Rol32(b, 30);
        b = a;
        a = tmp;
    }

    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
}

void Sha1::Update(const void* data, std::size_t len) noexcept {
    const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
    total_bits_ += static_cast<std::uint64_t>(len) * 8u;

    // Top up a partially filled block first.
    if (buffer_len_ > 0) {
        while (len > 0 && buffer_len_ < 64) {
            buffer_[buffer_len_++] = *p++;
            --len;
        }
        if (buffer_len_ == 64) {
            ProcessBlock(buffer_);
            buffer_len_ = 0;
        }
    }
    // Consume whole blocks directly from the input.
    while (len >= 64) {
        ProcessBlock(p);
        p += 64;
        len -= 64;
    }
    // Stash the remainder.
    while (len > 0) {
        buffer_[buffer_len_++] = *p++;
        --len;
    }
}

Sha1Digest Sha1::Final() noexcept {
    const std::uint64_t message_bits = total_bits_;

    // Append the mandatory 0x80 byte.
    buffer_[buffer_len_++] = 0x80;

    // If the 8-byte length won't fit in this block, finish it and start a fresh one.
    if (buffer_len_ > 56) {
        while (buffer_len_ < 64) {
            buffer_[buffer_len_++] = 0x00;
        }
        ProcessBlock(buffer_);
        buffer_len_ = 0;
    }
    while (buffer_len_ < 56) {
        buffer_[buffer_len_++] = 0x00;
    }
    // 64-bit big-endian message length in bits.
    for (int i = 7; i >= 0; --i) {
        buffer_[buffer_len_++] = static_cast<std::uint8_t>((message_bits >> (i * 8)) & 0xFFu);
    }
    ProcessBlock(buffer_);
    buffer_len_ = 0;

    Sha1Digest d;
    for (int i = 0; i < 5; ++i) {
        d.bytes[i * 4 + 0] = static_cast<std::uint8_t>((h_[i] >> 24) & 0xFFu);
        d.bytes[i * 4 + 1] = static_cast<std::uint8_t>((h_[i] >> 16) & 0xFFu);
        d.bytes[i * 4 + 2] = static_cast<std::uint8_t>((h_[i] >> 8) & 0xFFu);
        d.bytes[i * 4 + 3] = static_cast<std::uint8_t>(h_[i] & 0xFFu);
    }
    return d;
}

Sha1Digest Sha1Hash(const void* data, std::size_t len) noexcept {
    Sha1 s;
    s.Update(data, len);
    return s.Final();
}

std::string ToHex(const Sha1Digest& d) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string s(40, '0');
    for (int i = 0; i < 20; ++i) {
        s[i * 2 + 0] = kHex[(d.bytes[i] >> 4) & 0xF];
        s[i * 2 + 1] = kHex[d.bytes[i] & 0xF];
    }
    return s;
}

}  // namespace pwfilter
