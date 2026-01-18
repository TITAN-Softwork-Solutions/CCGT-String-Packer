#pragma once
#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace ccgt::crypto {

inline void secure_zero(void* p, size_t n) {
    if (!p || n == 0) return;
#if defined(_WIN32)
    SecureZeroMemory(p, n);
#else
    volatile uint8_t* v = reinterpret_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
#endif
}

inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    if (!a || !b) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

} // namespace ccgt::crypto