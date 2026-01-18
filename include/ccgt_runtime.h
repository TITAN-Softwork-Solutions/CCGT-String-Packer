#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

#include <windows.h>

#include "ccgt_aead.h"
#include "ccgt_secure.h"

namespace CCGT {

#pragma pack(push, 1)
    struct Region {
        uint32_t rva;   // RVA from image base
        uint32_t len;   // byte length
        uint64_t seed;  // per-region seed
        uint8_t  tag[16]; // Poly1305 tag
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

    static inline void reconstruct_key(uint8_t out_key32[32]) {
        for (int i = 0; i < 32; ++i) {
            out_key32[i] = g_meta.key_frag[i] ^ g_meta.key_mask[i];
        }
    }

    static inline void init() {
        if (g_meta.count == 0 || g_meta.count > g_meta.capacity) {
            return;
        }

        uint8_t key32[32];
        reconstruct_key(key32);

        HMODULE mod = nullptr;

        if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&g_meta),
            &mod))
        {
            mod = GetModuleHandleW(nullptr);
        }

        auto* base = reinterpret_cast<uint8_t*>(mod);

        for (uint32_t i = 0; i < g_meta.count && i < g_meta.capacity; ++i) {
            const Region& r = g_meta.regions[i];
            if (!r.rva || !r.len) continue;

            uint8_t* ptr = base + r.rva;

            DWORD oldProt = 0;
            if (!VirtualProtect(ptr, r.len, PAGE_READWRITE, &oldProt)) {
                continue;
            }

            uint8_t aad[16];
            
            std::memcpy(aad + 0, &r.rva, 4);
            std::memcpy(aad + 4, &r.len, 4);
            std::memcpy(aad + 8, &r.seed, 8);

            const bool ok = ccgt::crypto::open_chacha20_poly1305_inplace(
                ptr,
                static_cast<size_t>(r.len),
                key32,
                r.seed,
                r.rva,
                aad,
                sizeof(aad),
                r.tag
            );

            ccgt::crypto::secure_zero(aad, sizeof(aad));

            DWORD tmp = 0;
            VirtualProtect(ptr, r.len, oldProt, &tmp);

            (void)ok;
        }

        ccgt::crypto::secure_zero(key32, sizeof(key32));
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