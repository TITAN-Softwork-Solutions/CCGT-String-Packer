#pragma once
#include <cstdint>
#include <cstddef>

namespace ccgt::crypto {

static constexpr size_t POLY1305_KEY_LEN = 32;
static constexpr size_t POLY1305_TAG_LEN = 16;

struct poly1305_state {
    uint64_t r0, r1, r2, r3, r4;
    uint64_t s1, s2, s3, s4;
    uint64_t h0, h1, h2, h3, h4;
    uint32_t pad0, pad1, pad2, pad3;

    uint8_t  buf[16];
    size_t   leftover;
    bool     finished;
};

void poly1305_init(poly1305_state& st, const uint8_t key32[32]);
void poly1305_update(poly1305_state& st, const uint8_t* m, size_t bytes);
void poly1305_finish(poly1305_state& st, uint8_t out_tag16[16]);
void poly1305_auth(uint8_t out_tag16[16], const uint8_t* m, size_t bytes, const uint8_t key32[32]);

} // namespace ccgt::crypto