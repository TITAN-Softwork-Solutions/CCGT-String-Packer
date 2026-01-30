#pragma once

#include <algorithm>
#include <cstring>
#include <vector>
#include <limits>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
#if defined(_MSC_VER)
#  pragma comment(lib, "bcrypt.lib")
#endif
#if defined(_MSC_VER)
#  include <intrin.h>
#endif

#include "ccgt_aead.h"
#include "ccgt_meta.h"
#include "ccgt_sig_pub.h"
#include "ccgt_secure.h"

namespace CCGT {

#pragma section(".ccgtr", read, write)
    __declspec(allocate(".ccgtr")) inline Meta g_meta = {
        0, CCGT::META_CAPACITY,
        {}, {},
        {},
        CCGT::SIG_ALG_ECDSA_P256,
        CCGT::SIGNATURE_LEN,
        {}
    };

    __declspec(noreturn) static inline void ccgt_fail_fast() {
#if defined(_MSC_VER)
        __fastfail(0);
#else
        RaiseFailFastException(nullptr, nullptr, 0);
#endif
    }

    static inline uint8_t* ccgt_module_base_or_fail() {
        HMODULE mod = nullptr;
        if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&g_meta),
            &mod))
        {
            mod = GetModuleHandleW(nullptr);
        }
        if (!mod) ccgt_fail_fast();
        return reinterpret_cast<uint8_t*>(mod);
    }

    static inline uint32_t ccgt_image_size_or_fail(const uint8_t* base) {
        if (!base) ccgt_fail_fast();
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) ccgt_fail_fast();
        if (dos->e_lfanew <= 0) ccgt_fail_fast();

        const auto* nt_any = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt_any->Signature != IMAGE_NT_SIGNATURE) ccgt_fail_fast();

        if (nt_any->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            const uint32_t sz = nt_any->OptionalHeader.SizeOfImage;
            if (sz == 0) ccgt_fail_fast();
            return sz;
        }
        if (nt_any->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt_any);
            const uint32_t sz = nt32->OptionalHeader.SizeOfImage;
            if (sz == 0) ccgt_fail_fast();
            return sz;
        }

        ccgt_fail_fast();
    }

    static inline bool ccgt_region_in_bounds(uint32_t rva, uint32_t len, uint32_t image_size) {
        if (len == 0 || image_size == 0) return false;
        if (rva >= image_size) return false;
        const uint64_t end = static_cast<uint64_t>(rva) + static_cast<uint64_t>(len);
        return end <= image_size;
    }

    static inline void ccgt_bcrypt_fail_if(NTSTATUS st) {
        if (st != 0) ccgt_fail_fast();
    }

    struct CcgtHashCtx {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        std::vector<uint8_t> obj;
        ~CcgtHashCtx() {
            if (hash) BCryptDestroyHash(hash);
            if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        }
    };

    static inline CcgtHashCtx ccgt_sha256_start_or_fail() {
        CcgtHashCtx ctx;
        ccgt_bcrypt_fail_if(BCryptOpenAlgorithmProvider(&ctx.alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0));

        ULONG obj_len = 0;
        ULONG cb = 0;
        ccgt_bcrypt_fail_if(
            BCryptGetProperty(ctx.alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0)
        );

        ctx.obj.resize(obj_len);
        ccgt_bcrypt_fail_if(
            BCryptCreateHash(ctx.alg, &ctx.hash, ctx.obj.data(), obj_len, nullptr, 0, 0)
        );
        return ctx;
    }

    static inline void ccgt_sha256_update_or_fail(CcgtHashCtx& ctx, const uint8_t* data, size_t len) {
        if (!data || len == 0) return;
        if (len > (std::numeric_limits<ULONG>::max)()) ccgt_fail_fast();
        ccgt_bcrypt_fail_if(
            BCryptHashData(ctx.hash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0)
        );
    }

    static inline void ccgt_sha256_finish_or_fail(CcgtHashCtx& ctx, uint8_t out32[32]) {
        ccgt_bcrypt_fail_if(BCryptFinishHash(ctx.hash, out32, 32, 0));
    }

    static inline bool ccgt_range_in_bounds_u64(uint64_t off, uint64_t len, uint64_t total) {
        if (off > total) return false;
        const uint64_t end = off + len;
        return end <= total;
    }

    static inline std::vector<uint8_t> ccgt_read_self_file_or_fail() {
        std::vector<wchar_t> path(260);
        for (;;) {
            DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
            if (len == 0) ccgt_fail_fast();
            if (len < path.size() - 1) {
                path.resize(len + 1);
                break;
            }
            if (path.size() >= 32768) ccgt_fail_fast();
            path.resize(path.size() * 2);
        }

        HANDLE h = CreateFileW(
            path.data(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (h == INVALID_HANDLE_VALUE) ccgt_fail_fast();

        LARGE_INTEGER sz = {};
        if (!GetFileSizeEx(h, &sz)) {
            CloseHandle(h);
            ccgt_fail_fast();
        }
        if (sz.QuadPart <= 0 || sz.QuadPart > static_cast<LONGLONG>(std::numeric_limits<size_t>::max()) ||
            sz.QuadPart > (1024ll * 1024ll * 1024ll)) {
            CloseHandle(h);
            ccgt_fail_fast();
        }

        const size_t size = static_cast<size_t>(sz.QuadPart);
        std::vector<uint8_t> buf(size);
        size_t off = 0;
        while (off < size) {
            const size_t left = size - off;
            const DWORD chunk = (left > (1024 * 1024)) ? (1024 * 1024) : static_cast<DWORD>(left);
            DWORD read = 0;
            if (!ReadFile(h, buf.data() + off, chunk, &read, nullptr) || read == 0) {
                CloseHandle(h);
                ccgt_fail_fast();
            }
            off += read;
        }

        CloseHandle(h);
        return buf;
    }

    struct CcgtPeFileView {
        const uint8_t* base = nullptr;
        size_t size = 0;
        const IMAGE_SECTION_HEADER* sect = nullptr;
        uint16_t nsec = 0;
    };

    static inline CcgtPeFileView ccgt_parse_pe_file_or_fail(const std::vector<uint8_t>& buf) {
        if (buf.size() < sizeof(IMAGE_DOS_HEADER)) ccgt_fail_fast();
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) ccgt_fail_fast();
        if (dos->e_lfanew <= 0) ccgt_fail_fast();

        const uint64_t nt_off = static_cast<uint64_t>(static_cast<uint32_t>(dos->e_lfanew));
        if (!ccgt_range_in_bounds_u64(nt_off, sizeof(IMAGE_NT_HEADERS64), buf.size())) ccgt_fail_fast();

        const auto* nt_any = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + nt_off);
        if (nt_any->Signature != IMAGE_NT_SIGNATURE) ccgt_fail_fast();

        size_t nt_size = 0;
        if (nt_any->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            nt_size = sizeof(IMAGE_NT_HEADERS64);
        }
        else if (nt_any->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            nt_size = sizeof(IMAGE_NT_HEADERS32);
        }
        else {
            ccgt_fail_fast();
        }

        const uint16_t nsec = nt_any->FileHeader.NumberOfSections;
        if (nsec == 0 || nsec > 96) ccgt_fail_fast();

        const uint64_t sec_off = nt_off + nt_size;
        const uint64_t sec_len = static_cast<uint64_t>(nsec) * sizeof(IMAGE_SECTION_HEADER);
        if (!ccgt_range_in_bounds_u64(sec_off, sec_len, buf.size())) ccgt_fail_fast();

        CcgtPeFileView view{};
        view.base = buf.data();
        view.size = buf.size();
        view.sect = reinterpret_cast<const IMAGE_SECTION_HEADER*>(buf.data() + sec_off);
        view.nsec = nsec;
        return view;
    }

    static inline bool ccgt_rva_to_fileoff(const CcgtPeFileView& pe, uint32_t rva, uint32_t len, uint32_t& out_off) {
        if (len == 0) return false;
        for (uint16_t i = 0; i < pe.nsec; ++i) {
            const auto& sh = pe.sect[i];
            const uint32_t va = sh.VirtualAddress;
            const uint32_t raw = sh.PointerToRawData;
            const uint32_t raw_sz = sh.SizeOfRawData;
            if (rva < va) continue;
            const uint32_t delta = rva - va;
            if (delta >= raw_sz) continue;
            if (len > (raw_sz - delta)) continue;
            const uint64_t off = static_cast<uint64_t>(raw) + delta;
            if (!ccgt_range_in_bounds_u64(off, len, pe.size)) continue;
            out_off = static_cast<uint32_t>(off);
            return true;
        }
        return false;
    }

    struct CcgtZeroRange {
        uint64_t off = 0;
        uint64_t len = 0;
    };

    static inline void ccgt_normalize_zero_ranges(std::vector<CcgtZeroRange>& ranges) {
        if (ranges.empty()) return;
        std::sort(ranges.begin(), ranges.end(), [](const CcgtZeroRange& a, const CcgtZeroRange& b) {
            return a.off < b.off;
        });

        std::vector<CcgtZeroRange> merged;
        merged.reserve(ranges.size());

        for (const auto& r : ranges) {
            if (r.len == 0) continue;
            if (merged.empty()) {
                merged.push_back(r);
                continue;
            }
            auto& last = merged.back();
            const uint64_t last_end = last.off + last.len;
            if (r.off > last_end) {
                merged.push_back(r);
                continue;
            }
            const uint64_t r_end = r.off + r.len;
            if (r_end > last_end) {
                last.len = r_end - last.off;
            }
        }

        ranges.swap(merged);
    }

    static inline void ccgt_hash_file_with_zeroed_ranges_or_fail(
        const std::vector<uint8_t>& buf,
        std::vector<CcgtZeroRange> ranges,
        uint8_t out_hash32[32]
    ) {
        ccgt_normalize_zero_ranges(ranges);

        CcgtHashCtx ctx = ccgt_sha256_start_or_fail();
        static constexpr size_t kZeroChunk = 4096;
        uint8_t zeros[kZeroChunk] = {};

        uint64_t pos = 0;
        for (const auto& r : ranges) {
            if (!ccgt_range_in_bounds_u64(r.off, r.len, buf.size())) ccgt_fail_fast();
            if (r.off > pos) {
                const uint64_t n = r.off - pos;
                ccgt_sha256_update_or_fail(ctx, buf.data() + pos, static_cast<size_t>(n));
            }
            uint64_t left = r.len;
            while (left) {
                const size_t chunk = (left > kZeroChunk) ? kZeroChunk : static_cast<size_t>(left);
                ccgt_sha256_update_or_fail(ctx, zeros, chunk);
                left -= chunk;
            }
            pos = r.off + r.len;
        }
        if (pos < buf.size()) {
            ccgt_sha256_update_or_fail(ctx, buf.data() + pos, buf.size() - static_cast<size_t>(pos));
        }
        ccgt_sha256_finish_or_fail(ctx, out_hash32);
    }

    static inline void ccgt_security_dir_range_or_fail(const std::vector<uint8_t>& buf, uint64_t& off, uint64_t& len) {
        off = 0;
        len = 0;

        if (buf.size() < sizeof(IMAGE_DOS_HEADER)) ccgt_fail_fast();
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) ccgt_fail_fast();
        if (dos->e_lfanew <= 0) ccgt_fail_fast();

        const uint64_t nt_off = static_cast<uint64_t>(static_cast<uint32_t>(dos->e_lfanew));
        if (!ccgt_range_in_bounds_u64(nt_off, sizeof(IMAGE_NT_HEADERS64), buf.size())) ccgt_fail_fast();

        const auto* nt_any = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + nt_off);
        if (nt_any->Signature != IMAGE_NT_SIGNATURE) ccgt_fail_fast();

        const IMAGE_DATA_DIRECTORY* dd = nullptr;
        if (nt_any->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            dd = nt_any->OptionalHeader.DataDirectory;
        }
        else if (nt_any->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt_any);
            dd = nt32->OptionalHeader.DataDirectory;
        }
        else {
            ccgt_fail_fast();
        }

        const uint32_t dir_off = dd[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        const uint32_t dir_len = dd[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        if (dir_off == 0 || dir_len == 0) return;

        off = dir_off;
        len = dir_len;
        if (!ccgt_range_in_bounds_u64(off, len, buf.size())) ccgt_fail_fast();
    }

    static inline void ccgt_hash_file_for_signature_or_fail(const std::vector<uint8_t>& buf, uint8_t out_hash32[32]) {
        const CcgtPeFileView pe = ccgt_parse_pe_file_or_fail(buf);

        const uint8_t* base = ccgt_module_base_or_fail();
        const uint64_t meta_rva64 = static_cast<uint64_t>(reinterpret_cast<const uint8_t*>(&g_meta) - base);
        const uint64_t sig_rva64 = meta_rva64 + static_cast<uint64_t>(offsetof(Meta, signature));
        if (sig_rva64 > (std::numeric_limits<uint32_t>::max)()) ccgt_fail_fast();
        const uint32_t sig_rva = static_cast<uint32_t>(sig_rva64);

        uint32_t sig_off32 = 0;
        if (!ccgt_rva_to_fileoff(pe, sig_rva, CCGT::SIGNATURE_LEN, sig_off32)) ccgt_fail_fast();

        uint64_t cert_off = 0;
        uint64_t cert_len = 0;
        ccgt_security_dir_range_or_fail(buf, cert_off, cert_len);

        std::vector<CcgtZeroRange> ranges;
        ranges.reserve(2);
        ranges.push_back({ sig_off32, CCGT::SIGNATURE_LEN });
        if (cert_off && cert_len) {
            ranges.push_back({ cert_off, cert_len });
        }

        ccgt_hash_file_with_zeroed_ranges_or_fail(buf, ranges, out_hash32);
    }

    static inline void ccgt_verify_signature_or_fail(const uint8_t hash32[32]) {
        if (!CCGT::Sig::kPublicKeyValid) ccgt_fail_fast();
        if (CCGT::Sig::kPublicKeyBlobLen > (std::numeric_limits<ULONG>::max)()) ccgt_fail_fast();

        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;

        ccgt_bcrypt_fail_if(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0));

        const NTSTATUS st = BCryptImportKeyPair(
            alg,
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            &key,
            const_cast<PUCHAR>(CCGT::Sig::kPublicKeyBlob),
            static_cast<ULONG>(CCGT::Sig::kPublicKeyBlobLen),
            0
        );
        if (st != 0) {
            if (key) BCryptDestroyKey(key);
            if (alg) BCryptCloseAlgorithmProvider(alg, 0);
            ccgt_fail_fast();
        }

        const NTSTATUS vst = BCryptVerifySignature(
            key,
            nullptr,
            const_cast<PUCHAR>(hash32),
            32,
            const_cast<PUCHAR>(g_meta.signature),
            CCGT::SIGNATURE_LEN,
            0
        );

        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);

        if (vst != 0) ccgt_fail_fast();
    }

    static inline void ccgt_verify_integrity_or_fail() {
        if (g_meta.sig_alg != CCGT::SIG_ALG_ECDSA_P256) ccgt_fail_fast();
        if (g_meta.sig_len != CCGT::SIGNATURE_LEN) ccgt_fail_fast();

        std::vector<uint8_t> file = ccgt_read_self_file_or_fail();
        uint8_t hash32[32];
        ccgt_hash_file_for_signature_or_fail(file, hash32);
        ccgt_verify_signature_or_fail(hash32);
        ccgt::crypto::secure_zero(hash32, sizeof(hash32));
    }

    static inline void reconstruct_key(uint8_t out_key32[32]) {
        for (int i = 0; i < 32; ++i) {
            out_key32[i] = g_meta.key_frag[i] ^ g_meta.key_mask[i];
        }
    }

    static inline void init() {
        if (g_meta.count == 0) return;
        if (g_meta.capacity != CCGT::META_CAPACITY) ccgt_fail_fast();
        if (g_meta.count > CCGT::META_CAPACITY) ccgt_fail_fast();

        ccgt_verify_integrity_or_fail();

        uint8_t key32[32];
        reconstruct_key(key32);

        auto* base = ccgt_module_base_or_fail();
        const uint32_t image_size = ccgt_image_size_or_fail(base);

        for (uint32_t i = 0; i < g_meta.count; ++i) {
            const Region& r = g_meta.regions[i];
            if (!r.rva || !r.len) ccgt_fail_fast();
            if (!ccgt_region_in_bounds(r.rva, r.len, image_size)) ccgt_fail_fast();

            uint8_t* ptr = base + r.rva;

            DWORD oldProt = 0;
            if (!VirtualProtect(ptr, r.len, PAGE_READWRITE, &oldProt)) {
                ccgt_fail_fast();
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
            if (!ok) {
                ccgt::crypto::secure_zero(key32, sizeof(key32));
                ccgt_fail_fast();
            }

            DWORD tmp = 0;
            VirtualProtect(ptr, r.len, oldProt, &tmp);
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
