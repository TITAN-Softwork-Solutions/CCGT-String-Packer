#pragma once

#include <cstdint>
#include <cstddef>

namespace CCGT {

static constexpr uint32_t META_CAPACITY = 4096;
static constexpr size_t   MASTER_KEY_LEN = 32;
static constexpr size_t   TAG_LEN = 16;
static constexpr size_t   SIGNATURE_LEN = 64; // ECDSA P-256 signature (r||s)
static constexpr uint32_t SIG_ALG_ECDSA_P256 = 1;

#pragma pack(push, 1)
struct Region {
    uint32_t rva;   // RVA from image base
    uint32_t len;   // byte length
    uint64_t seed;  // per-region seed
    uint8_t  tag[TAG_LEN]; // Poly1305 tag
};

struct Meta {
    uint32_t count;        // number of valid regions
    uint32_t capacity;     // max regions (fixed)
    uint8_t  key_frag[MASTER_KEY_LEN]; // master_key[i] = frag[i] ^ mask[i]
    uint8_t  key_mask[MASTER_KEY_LEN];
    Region   regions[META_CAPACITY];
    uint32_t sig_alg;      // SIG_ALG_ECDSA_P256
    uint32_t sig_len;      // SIGNATURE_LEN
    uint8_t  signature[SIGNATURE_LEN];
};
#pragma pack(pop)

static_assert(sizeof(Region) == 32, "Region packing mismatch");
static_assert(offsetof(Meta, regions) % alignof(uint32_t) == 0, "Meta alignment unexpected");

} // namespace CCGT
