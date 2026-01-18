#pragma once
#include <cstdint>
#include <cstddef>

namespace ccgt::crypto {

static constexpr size_t CHACHA_KEY_LEN   = 32;
static constexpr size_t CHACHA_NONCE_LEN = 12;
static constexpr size_t CHACHA_BLOCK_LEN = 64;

void chacha20_block(
    uint8_t out64[64],
    const uint8_t key32[32],
    uint32_t counter,
    const uint8_t nonce12[12]
);

void chacha20_xor_inplace(
    uint8_t* data, size_t len,
    const uint8_t key32[32],
    const uint8_t nonce12[12],
    uint32_t initial_counter = 1
);

} // namespace ccgt::crypto