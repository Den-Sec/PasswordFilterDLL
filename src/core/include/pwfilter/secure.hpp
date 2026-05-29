#pragma once

#include <cstddef>

namespace pwfilter {

// Overwrite `n` bytes at `p` with zeros in a way the compiler is not allowed to elide,
// even when the buffer is about to go out of scope. Used to wipe plaintext-password
// copies. Portable (no Windows dependency); the moral equivalent of SecureZeroMemory.
void SecureZero(void* p, std::size_t n) noexcept;

// RAII guard: zeroes a fixed region when it leaves scope, on every path (including
// exceptions). Attach it to a stack buffer holding a password copy:
//
//     wchar_t pw[257];
//     pwfilter::ScopedZero guard(pw, sizeof(pw));
//
// Non-owning: it only zeroes, it does not free.
class ScopedZero {
 public:
  ScopedZero(void* p, std::size_t n) noexcept : p_(p), n_(n) {}
  ~ScopedZero() { SecureZero(p_, n_); }

  ScopedZero(const ScopedZero&) = delete;
  ScopedZero& operator=(const ScopedZero&) = delete;

 private:
  void* p_;
  std::size_t n_;
};

}  // namespace pwfilter
