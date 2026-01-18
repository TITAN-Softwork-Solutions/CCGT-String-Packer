#pragma once
#include <cstdint>
#include <cstddef>

#include <windows.h>

namespace CCGT {
#pragma pack(push, 1)
    struct Region {
        uint32_t rva;   // RVA from image base
        uint32_t len;   // byte length
        uint64_t seed;  // per-region seed (written by ccgt)
    };

    struct Meta {
        uint32_t count;        // number of valid regions
        uint32_t capacity;     // max regions (fixed)
        uint8_t  key_frag[32]; // master_key[i] = frag[i] ^ mask[i]
        uint8_t  key_mask[32];
        Region   regions[4096];
    };
#pragma pack(pop)

#pragma section(".ccgtr", read, write)
    __declspec(allocate(".ccgtr")) inline Meta g_meta = {
        0, 4096,
        {}, {},
        {}
    };

    static inline uint32_t rotl32(uint32_t x, int r) {
        return (x << r) | (x >> (32 - r));
    }

    static inline uint32_t load32_le(const uint8_t* p) {
        return (uint32_t)p[0]
            | ((uint32_t)p[1] << 8)
            | ((uint32_t)p[2] << 16)
            | ((uint32_t)p[3] << 24);
    }

    static inline void store32_le(uint8_t* p, uint32_t v) {
        p[0] = (uint8_t)(v);
        p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16);
        p[3] = (uint8_t)(v >> 24);
    }

    static inline void reconstruct_key(uint8_t out_key32[32]) {
        for (int i = 0; i < 32; ++i) {
            out_key32[i] = g_meta.key_frag[i] ^ g_meta.key_mask[i];
        }
    }

    static inline void derive_nonce96(uint8_t nonce12[12], uint64_t seed, uint32_t rva) {
        uint64_t x = seed ^ (uint64_t)rva * 0x9E3779B97F4A7C15ULL;

        auto mix = [](uint64_t& s) -> uint64_t {
            s += 0x9E3779B97F4A7C15ULL;
            uint64_t z = s;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            return z ^ (z >> 31);
            };

        uint64_t a = mix(x);
        uint64_t b = mix(x);

        for (int i = 0; i < 8; ++i) nonce12[i] = (uint8_t)(a >> (8 * i));
        for (int i = 0; i < 4; ++i) nonce12[8 + i] = (uint8_t)(b >> (8 * i));
    }

    static inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }

    static inline void chacha20_block(
        uint8_t out64[64],
        const uint8_t key32[32],
        uint32_t counter,
        const uint8_t nonce12[12]
    ) {
        uint32_t state[16] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            load32_le(key32 + 0),  load32_le(key32 + 4),  load32_le(key32 + 8),  load32_le(key32 + 12),
            load32_le(key32 + 16), load32_le(key32 + 20), load32_le(key32 + 24), load32_le(key32 + 28),
            counter,
            load32_le(nonce12 + 0), load32_le(nonce12 + 4), load32_le(nonce12 + 8)
        };

        uint32_t working[16];
        for (int i = 0; i < 16; ++i) working[i] = state[i];

        for (int i = 0; i < 10; ++i) {
            quarter_round(working[0], working[4], working[8], working[12]);
            quarter_round(working[1], working[5], working[9], working[13]);
            quarter_round(working[2], working[6], working[10], working[14]);
            quarter_round(working[3], working[7], working[11], working[15]);

            quarter_round(working[0], working[5], working[10], working[15]);
            quarter_round(working[1], working[6], working[11], working[12]);
            quarter_round(working[2], working[7], working[8], working[13]);
            quarter_round(working[3], working[4], working[9], working[14]);
        }

        for (int i = 0; i < 16; ++i) {
            uint32_t v = working[i] + state[i];
            store32_le(out64 + i * 4, v);
        }
    }

    static inline void chacha20_xor(uint8_t* data, size_t len, const uint8_t key32[32], const uint8_t nonce12[12]) {
        uint8_t block[64];
        uint32_t counter = 1;

        size_t off = 0;
        while (off < len) {
            chacha20_block(block, key32, counter++, nonce12);
            size_t n = (len - off < 64) ? (len - off) : 64;

            for (size_t i = 0; i < n; ++i) {
                data[off + i] ^= block[i];
            }
            off += n;
        }

        SecureZeroMemory(block, sizeof(block));
    }

    static inline void init() {
        if (g_meta.count == 0 || g_meta.count > g_meta.capacity) {
            return;
        }

        uint8_t key32[32];
        reconstruct_key(key32);

        HMODULE mod = GetModuleHandleW(nullptr);
        auto* base = reinterpret_cast<uint8_t*>(mod);

        for (uint32_t i = 0; i < g_meta.count && i < g_meta.capacity; ++i) {
            const Region& r = g_meta.regions[i];
            if (!r.rva || !r.len) continue;

            uint8_t* ptr = base + r.rva;
            uint8_t nonce12[12];
            derive_nonce96(nonce12, r.seed, r.rva);

            DWORD oldProt = 0;
            if (!VirtualProtect(ptr, r.len, PAGE_READWRITE, &oldProt)) {
                SecureZeroMemory(nonce12, sizeof(nonce12));
                continue;
            }

            chacha20_xor(ptr, r.len, key32, nonce12);

            DWORD tmp = 0;
            VirtualProtect(ptr, r.len, oldProt, &tmp);
            SecureZeroMemory(nonce12, sizeof(nonce12));
        }

        SecureZeroMemory(key32, sizeof(key32));
    }

    using InitFn = void(*)();
#pragma section(".CRT$XCU", read)
    __declspec(allocate(".CRT$XCU")) inline InitFn g_auto_init = &init;
}

#if defined(_MSC_VER)

extern "C" __declspec(selectany) void* __ccgt_keep_gmeta = (void*)&CCGT::g_meta;
extern "C" __declspec(selectany) void* __ccgt_keep_init = (void*)&CCGT::g_auto_init;

#pragma comment(linker, "/include:__ccgt_keep_gmeta")
#pragma comment(linker, "/include:__ccgt_keep_init")
#pragma comment(linker, "/SECTION:.ccgtr,RW")

#endif