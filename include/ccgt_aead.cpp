#include "ccgt_aead.h"
#include "ccgt_chacha20.h"
#include "ccgt_poly1305.h"
#include "ccgt_nonce.h"
#include "ccgt_endian.h"
#include "ccgt_secure.h"

#include <cstring>

namespace ccgt::crypto {

static inline void poly_update_padded(poly1305_state& st, const uint8_t* p, size_t n) {
    if (n == 0) return;
    poly1305_update(st, p, n);

    const size_t rem = (n % 16);
    if (rem) {
        uint8_t zeros[16] = {};
        poly1305_update(st, zeros, 16 - rem);
        secure_zero(zeros, sizeof(zeros));
    }
}

static inline void compute_tag_rfc8439(
    uint8_t out_tag16[16],
    const uint8_t poly_key32[32],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct,  size_t ct_len
) {
    poly1305_state st{};
    poly1305_init(st, poly_key32);

    // MAC = Poly1305(AAD || pad16(AAD) || CT || pad16(CT) || le64(aad_len) || le64(ct_len))
    if (aad && aad_len) poly1305_update(st, aad, aad_len);
    if (aad_len % 16) {
        uint8_t zeros[16] = {};
        poly1305_update(st, zeros, 16 - (aad_len % 16));
        secure_zero(zeros, sizeof(zeros));
    }

    if (ct && ct_len) poly1305_update(st, ct, ct_len);
    if (ct_len % 16) {
        uint8_t zeros[16] = {};
        poly1305_update(st, zeros, 16 - (ct_len % 16));
        secure_zero(zeros, sizeof(zeros));
    }

    uint8_t lens[16];
    store64_le(lens + 0, (uint64_t)aad_len);
    store64_le(lens + 8, (uint64_t)ct_len);
    poly1305_update(st, lens, sizeof(lens));
    secure_zero(lens, sizeof(lens));

    poly1305_finish(st, out_tag16);
}

void seal_chacha20_poly1305_inplace(
    uint8_t* data, size_t len,
    const uint8_t key32[32],
    uint64_t seed, uint32_t rva,
    const uint8_t* aad, size_t aad_len,
    uint8_t out_tag16[16]
) {
    if (!data || len == 0 || !key32 || !out_tag16) return;

    uint8_t nonce12[12];
    derive_nonce96(nonce12, seed, rva);

    // Poly1305 one-time key = ChaCha20(key, nonce, counter=0) first 32 bytes
    uint8_t block0[64];
    chacha20_block(block0, key32, 0, nonce12);

    uint8_t poly_key[32];
    std::memcpy(poly_key, block0, 32);

    // Encrypt in-place with counter=1
    chacha20_xor_inplace(data, len, key32, nonce12, 1);

    // Tag over (aad, ciphertext)
    compute_tag_rfc8439(out_tag16, poly_key, aad, aad_len, data, len);

    secure_zero(poly_key, sizeof(poly_key));
    secure_zero(block0, sizeof(block0));
    secure_zero(nonce12, sizeof(nonce12));
}

bool open_chacha20_poly1305_inplace(
    uint8_t* data, size_t len,
    const uint8_t key32[32],
    uint64_t seed, uint32_t rva,
    const uint8_t* aad, size_t aad_len,
    const uint8_t tag16[16]
) {
    if (!data || len == 0 || !key32 || !tag16) return false;

    uint8_t nonce12[12];
    derive_nonce96(nonce12, seed, rva);

    uint8_t block0[64];
    chacha20_block(block0, key32, 0, nonce12);

    uint8_t poly_key[32];
    std::memcpy(poly_key, block0, 32);

    uint8_t calc_tag[16];
    compute_tag_rfc8439(calc_tag, poly_key, aad, aad_len, data, len);

    const bool ok = ct_equal(calc_tag, tag16, 16);

    secure_zero(calc_tag, sizeof(calc_tag));

    if (!ok) {
        secure_zero(poly_key, sizeof(poly_key));
        secure_zero(block0, sizeof(block0));
        secure_zero(nonce12, sizeof(nonce12));
        return false;
    }

    // Decrypt after successful tag verification
    chacha20_xor_inplace(data, len, key32, nonce12, 1);

    secure_zero(poly_key, sizeof(poly_key));
    secure_zero(block0, sizeof(block0));
    secure_zero(nonce12, sizeof(nonce12));
    return true;
}

} // namespace ccgt::crypto