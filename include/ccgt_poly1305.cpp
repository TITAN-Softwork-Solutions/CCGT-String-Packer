#include "ccgt_poly1305.h"
#include "ccgt_endian.h"
#include "ccgt_secure.h"

#include <cstring>

namespace ccgt::crypto {

static inline void poly1305_blocks(poly1305_state& st, const uint8_t* m, size_t bytes, bool full_blocks) {
    const uint64_t hibit = full_blocks ? (1ULL << 24) : 0ULL; // 2^128 in 26-bit limb form

    while (bytes >= 16) {
        uint64_t t0 = load32_le(m + 0);
        uint64_t t1 = load32_le(m + 4);
        uint64_t t2 = load32_le(m + 8);
        uint64_t t3 = load32_le(m + 12);

        st.h0 += (t0)&0x3ffffffULL;
        st.h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffffULL;
        st.h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffffULL;
        st.h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffffULL;
        st.h4 += ((t3 >> 8)) | hibit;

        // multiply (h * r) mod (2^130-5)
        uint64_t d0 = (st.h0 * st.r0) + (st.h1 * st.s4) + (st.h2 * st.s3) + (st.h3 * st.s2) + (st.h4 * st.s1);
        uint64_t d1 = (st.h0 * st.r1) + (st.h1 * st.r0) + (st.h2 * st.s4) + (st.h3 * st.s3) + (st.h4 * st.s2);
        uint64_t d2 = (st.h0 * st.r2) + (st.h1 * st.r1) + (st.h2 * st.r0) + (st.h3 * st.s4) + (st.h4 * st.s3);
        uint64_t d3 = (st.h0 * st.r3) + (st.h1 * st.r2) + (st.h2 * st.r1) + (st.h3 * st.r0) + (st.h4 * st.s4);
        uint64_t d4 = (st.h0 * st.r4) + (st.h1 * st.r3) + (st.h2 * st.r2) + (st.h3 * st.r1) + (st.h4 * st.r0);

        // carry propagate
        uint64_t c;

        c = (d0 >> 26); st.h0 = d0 & 0x3ffffffULL; d1 += c;
        c = (d1 >> 26); st.h1 = d1 & 0x3ffffffULL; d2 += c;
        c = (d2 >> 26); st.h2 = d2 & 0x3ffffffULL; d3 += c;
        c = (d3 >> 26); st.h3 = d3 & 0x3ffffffULL; d4 += c;
        c = (d4 >> 26); st.h4 = d4 & 0x3ffffffULL; st.h0 += c * 5;

        c = (st.h0 >> 26); st.h0 &= 0x3ffffffULL; st.h1 += c;

        m += 16;
        bytes -= 16;
    }
}

void poly1305_init(poly1305_state& st, const uint8_t key32[32]) {
    std::memset(&st, 0, sizeof(st));

    uint64_t t0 = load32_le(key32 + 0);
    uint64_t t1 = load32_le(key32 + 4);
    uint64_t t2 = load32_le(key32 + 8);
    uint64_t t3 = load32_le(key32 + 12);

    // r with clamp
    st.r0 = (t0) & 0x3ffffffULL;
    st.r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03ULL;
    st.r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffULL;
    st.r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffULL;
    st.r4 = ((t3 >> 8)) & 0x00fffffULL;

    st.s1 = st.r1 * 5;
    st.s2 = st.r2 * 5;
    st.s3 = st.r3 * 5;
    st.s4 = st.r4 * 5;

    // pad
    st.pad0 = load32_le(key32 + 16);
    st.pad1 = load32_le(key32 + 20);
    st.pad2 = load32_le(key32 + 24);
    st.pad3 = load32_le(key32 + 28);

    st.leftover = 0;
    st.finished = false;
}

void poly1305_update(poly1305_state& st, const uint8_t* m, size_t bytes) {
    if (!m || bytes == 0) return;

    if (st.leftover) {
        size_t want = 16 - st.leftover;
        if (want > bytes) want = bytes;
        std::memcpy(st.buf + st.leftover, m, want);
        st.leftover += want;
        m += want;
        bytes -= want;

        if (st.leftover < 16) return;

        poly1305_blocks(st, st.buf, 16, true);
        st.leftover = 0;
    }

    if (bytes >= 16) {
        size_t want = bytes & ~((size_t)0x0F);
        poly1305_blocks(st, m, want, true);
        m += want;
        bytes -= want;
    }

    if (bytes) {
        std::memcpy(st.buf, m, bytes);
        st.leftover = bytes;
    }
}

void poly1305_finish(poly1305_state& st, uint8_t out_tag16[16]) {
    if (!out_tag16) return;

    if (st.leftover) {
        // final partial block: pad with 1 then zeros to 16 bytes
        st.buf[st.leftover] = 1;
        for (size_t i = st.leftover + 1; i < 16; ++i) st.buf[i] = 0;
        poly1305_blocks(st, st.buf, 16, false);
    }

    // fully carry
    uint64_t c;
    c = st.h1 >> 26; st.h1 &= 0x3ffffffULL; st.h2 += c;
    c = st.h2 >> 26; st.h2 &= 0x3ffffffULL; st.h3 += c;
    c = st.h3 >> 26; st.h3 &= 0x3ffffffULL; st.h4 += c;
    c = st.h4 >> 26; st.h4 &= 0x3ffffffULL; st.h0 += c * 5;
    c = st.h0 >> 26; st.h0 &= 0x3ffffffULL; st.h1 += c;

    // compute h + -p
    uint64_t g0 = st.h0 + 5;
    c = g0 >> 26; g0 &= 0x3ffffffULL;
    uint64_t g1 = st.h1 + c;
    c = g1 >> 26; g1 &= 0x3ffffffULL;
    uint64_t g2 = st.h2 + c;
    c = g2 >> 26; g2 &= 0x3ffffffULL;
    uint64_t g3 = st.h3 + c;
    c = g3 >> 26; g3 &= 0x3ffffffULL;

    int64_t  g4s = (int64_t)st.h4 + (int64_t)c - (int64_t)(1ULL << 26);
    uint64_t g4 = (uint64_t)g4s;

    // select h if g4 underflowed (negative), else select g
    uint64_t mask = (uint64_t)(g4s >> 63) - 1ULL;
    uint64_t nmask = ~mask;

    st.h0 = (st.h0 & nmask) | (g0 & mask);
    st.h1 = (st.h1 & nmask) | (g1 & mask);
    st.h2 = (st.h2 & nmask) | (g2 & mask);
    st.h3 = (st.h3 & nmask) | (g3 & mask);
    st.h4 = (st.h4 & nmask) | (g4 & mask);

    // serialize
    uint64_t f0 = (st.h0) | (st.h1 << 26);
    uint64_t f1 = (st.h1 >> 6) | (st.h2 << 20);
    uint64_t f2 = (st.h2 >> 12) | (st.h3 << 14);
    uint64_t f3 = (st.h3 >> 18) | (st.h4 << 8);

    // add pad
    uint64_t t;
    t = f0 + st.pad0; store32_le(out_tag16 + 0, (uint32_t)t); t >>= 32;
    t = f1 + st.pad1 + t; store32_le(out_tag16 + 4, (uint32_t)t); t >>= 32;
    t = f2 + st.pad2 + t; store32_le(out_tag16 + 8, (uint32_t)t); t >>= 32;
    t = f3 + st.pad3 + t; store32_le(out_tag16 + 12, (uint32_t)t);

    secure_zero(st.buf, sizeof(st.buf));
    secure_zero(&st, sizeof(st));
}

void poly1305_auth(uint8_t out_tag16[16], const uint8_t* m, size_t bytes, const uint8_t key32[32]) {
    poly1305_state st{};
    poly1305_init(st, key32);
    poly1305_update(st, m, bytes);
    poly1305_finish(st, out_tag16);
}

} // namespace ccgt::crypto