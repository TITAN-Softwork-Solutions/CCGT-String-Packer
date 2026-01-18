#pragma once
#include <cstdint>
#include <cstddef>

namespace ccgt::crypto {

static constexpr size_t AEAD_KEY_LEN   = 32;
static constexpr size_t AEAD_NONCE_LEN = 12;
static constexpr size_t AEAD_TAG_LEN   = 16;

void seal_chacha20_poly1305_inplace(
    uint8_t* data, size_t len,
    const uint8_t key32[AEAD_KEY_LEN],
    uint64_t seed, uint32_t rva,
    const uint8_t* aad, size_t aad_len,
    uint8_t out_tag16[AEAD_TAG_LEN]
);

bool open_chacha20_poly1305_inplace(
    uint8_t* data, size_t len,
    const uint8_t key32[AEAD_KEY_LEN],
    uint64_t seed, uint32_t rva,
    const uint8_t* aad, size_t aad_len,
    const uint8_t tag16[AEAD_TAG_LEN]
);

} // namespace ccgt::crypto