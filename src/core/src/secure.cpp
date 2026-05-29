#include "pwfilter/secure.hpp"

namespace pwfilter {

void SecureZero(void* p, std::size_t n) noexcept {
    if (p == nullptr || n == 0) {
        return;
    }
    // Writing through a volatile pointer has observable side effects the standard
    // forbids the optimizer from removing, so the wipe survives "dead store"
    // elimination even when the buffer dies immediately afterwards.
    volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
    while (n-- != 0) {
        *vp++ = 0;
    }
}

}  // namespace pwfilter
