#include "ccgt_chacha20.h"
#include "ccgt_endian.h"
#include "ccgt_secure.h"

namespace ccgt::crypto {

static inline uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

static inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

void chacha20_block(uint8_t out64[64], const uint8_t key32[32], uint32_t counter, const uint8_t nonce12[12]) {
    const uint32_t state[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        load32_le(key32 + 0),  load32_le(key32 + 4),  load32_le(key32 + 8),  load32_le(key32 + 12),
        load32_le(key32 + 16), load32_le(key32 + 20), load32_le(key32 + 24), load32_le(key32 + 28),
        counter,
        load32_le(nonce12 + 0), load32_le(nonce12 + 4), load32_le(nonce12 + 8)
    };

    uint32_t w[16];
    for (int i = 0; i < 16; ++i) w[i] = state[i];

    for (int i = 0; i < 10; ++i) {
        quarter_round(w[0], w[4], w[8], w[12]);
        quarter_round(w[1], w[5], w[9], w[13]);
        quarter_round(w[2], w[6], w[10], w[14]);
        quarter_round(w[3], w[7], w[11], w[15]);

        quarter_round(w[0], w[5], w[10], w[15]);
        quarter_round(w[1], w[6], w[11], w[12]);
        quarter_round(w[2], w[7], w[8], w[13]);
        quarter_round(w[3], w[4], w[9], w[14]);
    }

    for (int i = 0; i < 16; ++i) {
        const uint32_t v = w[i] + state[i];
        store32_le(out64 + i * 4, v);
    }

    secure_zero(w, sizeof(w));
}

void chacha20_xor_inplace(
    uint8_t* data, size_t len,
    const uint8_t key32[32],
    const uint8_t nonce12[12],
    uint32_t initial_counter
) {
    if (!data || len == 0) return;

    uint8_t block[CHACHA_BLOCK_LEN];
    uint32_t counter = initial_counter;
    size_t off = 0;

    while (off < len) {
        chacha20_block(block, key32, counter++, nonce12);
        const size_t n = ((len - off) < CHACHA_BLOCK_LEN) ? (len - off) : CHACHA_BLOCK_LEN;
        for (size_t i = 0; i < n; ++i) data[off + i] ^= block[i];
        off += n;
    }

    secure_zero(block, sizeof(block));
}

} // namespace ccgt::crypto