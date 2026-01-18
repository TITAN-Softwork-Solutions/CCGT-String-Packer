#include "ccgt_nonce.h"

namespace ccgt::crypto {

static inline uint64_t splitmix64(uint64_t& s) {
    s += 0x9E3779B97F4A7C15ULL;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

void derive_nonce96(uint8_t nonce12[12], uint64_t seed, uint32_t rva) {
    uint64_t x = seed ^ (uint64_t)rva * 0x9E3779B97F4A7C15ULL;
    const uint64_t a = splitmix64(x);
    const uint64_t b = splitmix64(x);

    for (int i = 0; i < 8; ++i) nonce12[i] = (uint8_t)(a >> (8 * i));
    for (int i = 0; i < 4; ++i) nonce12[8 + i] = (uint8_t)(b >> (8 * i));
}

} // namespace ccgt::crypto