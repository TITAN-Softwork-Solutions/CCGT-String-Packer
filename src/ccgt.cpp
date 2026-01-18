#include "ccgt.h"

#define NOMINMAX

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <limits>
#include <unordered_set>
#include <string_view>

namespace CCGT::Patcher
{
    static constexpr uint32_t META_CAPACITY = 4096;
    static constexpr size_t   MASTER_KEY_LEN = 32;
    static constexpr size_t   NONCE_LEN = 12;
    static constexpr size_t   CHACHA_BLOCK = 64;

#if defined(_MSC_VER)
#   define CCGT_FORCEINLINE __forceinline
#else
#   define CCGT_FORCEINLINE inline __attribute__((always_inline))
#endif

#pragma pack(push, 1)
    struct Region {
        uint32_t rva;
        uint32_t len;
        uint64_t seed;
    };

    struct Meta {
        uint32_t count;
        uint32_t capacity;
        uint8_t  key_frag[MASTER_KEY_LEN];
        uint8_t  key_mask[MASTER_KEY_LEN];
        Region   regions[META_CAPACITY];
    };
#pragma pack(pop)

    static_assert(sizeof(Region) == 16, "Region packing mismatch");
    static_assert(offsetof(Meta, regions) % alignof(uint32_t) == 0, "Meta alignment unexpected");

    static CCGT_FORCEINLINE void vlog(const Options& opt, const std::string& s)
    {
        if (opt.verbose) {
            std::cout << s << "\n";
        }
    }

    static CCGT_FORCEINLINE bool add_u64_checked(uint64_t a, uint64_t b, uint64_t& out)
    {
        if (b > (std::numeric_limits<uint64_t>::max)() - a) return false;
        out = a + b;
        return true;
    }

    static CCGT_FORCEINLINE bool add_u32_checked(uint32_t a, uint32_t b, uint32_t& out)
    {
        if (b > (std::numeric_limits<uint32_t>::max)() - a) return false;
        out = a + b;
        return true;
    }

    static CCGT_FORCEINLINE bool range_in_bounds_u64(uint64_t off, uint64_t len, uint64_t total)
    {
        if (off > total) return false;
        uint64_t end = 0;
        if (!add_u64_checked(off, len, end)) return false;
        return end <= total;
    }

    static CCGT_FORCEINLINE uint64_t to_u64(size_t v)
    {
        return static_cast<uint64_t>(v);
    }

    static std::vector<uint8_t> read_all(const std::filesystem::path& p)
    {
        std::error_code ec{};
        const auto fsz = std::filesystem::file_size(p, ec);
        if (ec) {
            throw std::runtime_error("failed to stat file size: " + p.string());
        }

        if (fsz < sizeof(IMAGE_DOS_HEADER)) {
            throw std::runtime_error("file too small (not even DOS header)");
        }
        if (fsz > (1024ull * 1024ull * 1024ull)) {
            throw std::runtime_error("refusing to read >1GB file (safety limit)");
        }

        std::ifstream f(p, std::ios::binary);
        if (!f) {
            throw std::runtime_error("failed to open file for reading: " + p.string());
        }

        std::vector<uint8_t> buf(static_cast<size_t>(fsz));
        f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));

        if (!f || f.gcount() != static_cast<std::streamsize>(buf.size())) {
            throw std::runtime_error("short read: " + p.string());
        }

        return buf;
    }

    static void write_all(const std::filesystem::path& p, const std::vector<uint8_t>& buf)
    {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        if (!f) {
            throw std::runtime_error("failed to open file for writing: " + p.string());
        }

        f.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        if (!f) {
            throw std::runtime_error("write failed: " + p.string());
        }

        f.flush();
        if (!f) {
            throw std::runtime_error("flush failed: " + p.string());
        }
    }

    static void gen_random_or_throw(uint8_t* out, size_t n)
    {
        if (!out || n == 0) {
            throw std::runtime_error("gen_random called with invalid buffer");
        }
        if (n > (std::numeric_limits<ULONG>::max)()) {
            throw std::runtime_error("gen_random requested too many bytes");
        }

        const NTSTATUS st = BCryptGenRandom(nullptr, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (st != 0) {
            throw std::runtime_error("BCryptGenRandom failed");
        }
    }

    static uint64_t gen_u64_or_throw()
    {
        uint64_t v = 0;
        gen_random_or_throw(reinterpret_cast<uint8_t*>(&v), sizeof(v));
        if (v == 0) {
            v = 0xA5A5A5A5A5A5A5A5ULL;
        }
        return v;
    }

    static std::string secname8(const IMAGE_SECTION_HEADER& sh)
    {
        char name[9] = {};
        std::memcpy(name, sh.Name, 8);
        return std::string(name);
    }

    static bool is_meta_section_name(const IMAGE_SECTION_HEADER& sh)
    {
        const auto n = secname8(sh);
        return (n.rfind(".ccgtr", 0) == 0) || (n.rfind("ccgtr", 0) == 0) ||
            (n.rfind(".ccgt", 0) == 0) || (n.rfind("ccgt", 0) == 0);
    }

    static bool is_rdata_or_data(const IMAGE_SECTION_HEADER& sh)
    {
        const auto n = secname8(sh);
        return (n.rfind(".rdata", 0) == 0) || (n.rfind(".data", 0) == 0);
    }

    static bool fileoff_is_in_section(const IMAGE_SECTION_HEADER& sh, uint64_t file_off)
    {
        const uint64_t s0 = sh.PointerToRawData;
        const uint64_t sz = sh.SizeOfRawData;
        uint64_t s1 = 0;
        if (!add_u64_checked(s0, sz, s1)) return false;
        return (file_off >= s0) && (file_off < s1);
    }

    static uint32_t fileoff_to_rva_checked(const IMAGE_SECTION_HEADER& sh, uint32_t file_off)
    {
        const uint64_t s0 = sh.PointerToRawData;
        const uint64_t s1 = s0 + sh.SizeOfRawData;

        if (file_off < s0 || file_off >= s1) return 0;

        const uint32_t delta = file_off - sh.PointerToRawData;
        uint32_t out = 0;
        if (!add_u32_checked(sh.VirtualAddress, delta, out)) return 0;
        return out;
    }

    struct DirRange { uint32_t rva; uint32_t size; };

    static bool overlaps_checked(uint32_t rva, uint32_t len, const DirRange& d)
    {
        if (d.rva == 0 || d.size == 0 || len == 0) return false;

        const uint64_t a0 = rva;
        const uint64_t a1 = a0 + static_cast<uint64_t>(len);
        const uint64_t b0 = d.rva;
        const uint64_t b1 = b0 + static_cast<uint64_t>(d.size);

        return (a0 < b1) && (b0 < a1);
    }

    static CCGT_FORCEINLINE uint32_t rotl32(uint32_t x, int r)
    {
        return (x << r) | (x >> (32 - r));
    }

    static CCGT_FORCEINLINE uint32_t load32_le(const uint8_t* p)
    {
        return (uint32_t)p[0]
            | ((uint32_t)p[1] << 8)
            | ((uint32_t)p[2] << 16)
            | ((uint32_t)p[3] << 24);
    }

    static CCGT_FORCEINLINE void store32_le(uint8_t* p, uint32_t v)
    {
        p[0] = (uint8_t)(v);
        p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16);
        p[3] = (uint8_t)(v >> 24);
    }

    static CCGT_FORCEINLINE void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
    {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }

    static CCGT_FORCEINLINE void chacha20_block(uint8_t out64[64], const uint8_t key32[32], uint32_t counter, const uint8_t nonce12[12])
    {
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
    }

    static void chacha20_xor(uint8_t* data, size_t len, const uint8_t key32[32], const uint8_t nonce12[12])
    {
        if (!data || len == 0) return;

        uint8_t block[CHACHA_BLOCK];
        uint32_t counter = 1;
        size_t off = 0;

        while (off < len) {
            chacha20_block(block, key32, counter++, nonce12);
            const size_t n = ((len - off) < CHACHA_BLOCK) ? (len - off) : CHACHA_BLOCK;
            for (size_t i = 0; i < n; ++i) {
                data[off + i] ^= block[i];
            }
            off += n;
        }

        SecureZeroMemory(block, sizeof(block));
    }

    static CCGT_FORCEINLINE uint64_t splitmix64(uint64_t& s)
    {
        s += 0x9E3779B97F4A7C15ULL;
        uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    static void derive_nonce96(uint8_t nonce12[NONCE_LEN], uint64_t seed, uint32_t rva)
    {
        uint64_t x = seed ^ (uint64_t)rva * 0x9E3779B97F4A7C15ULL;
        const uint64_t a = splitmix64(x);
        const uint64_t b = splitmix64(x);

        for (int i = 0; i < 8; ++i) nonce12[i] = (uint8_t)(a >> (8 * i));
        for (int i = 0; i < 4; ++i) nonce12[8 + i] = (uint8_t)(b >> (8 * i));
    }

    Result patch_file(
        const std::filesystem::path& target,
        const std::vector<decltype(scan_strings(std::filesystem::path{}))::value_type > & scanned_strings,
        const Options& opt
    )
    {
        Result res{};

        if (opt.make_backup) {
            auto bak = target;
            bak += ".bak";

            if (!std::filesystem::exists(bak)) {
                vlog(opt, "creating backup: " + bak.string());
                std::filesystem::copy_file(target, bak);
                vlog(opt, "backup created");
            }
            else {
                vlog(opt, "backup already exists: " + bak.string());
            }
        }
        else {
            vlog(opt, "backup disabled");
        }

        auto buf = read_all(target);
        const uint64_t file_sz = to_u64(buf.size());

        if (buf.size() < sizeof(IMAGE_DOS_HEADER)) {
            throw std::runtime_error("file too small");
        }

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            throw std::runtime_error("not a valid MZ (DOS) header");
        }

        if (dos->e_lfanew <= 0) {
            throw std::runtime_error("invalid e_lfanew");
        }

        const uint64_t nt_off = static_cast<uint64_t>(static_cast<uint32_t>(dos->e_lfanew));
        if (!range_in_bounds_u64(nt_off, sizeof(IMAGE_NT_HEADERS64), file_sz)) {
            throw std::runtime_error("NT headers out of bounds");
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + nt_off);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            throw std::runtime_error("not a valid PE signature");
        }
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            throw std::runtime_error("not PE32+ (x64) image");
        }

        const uint16_t nsec = nt->FileHeader.NumberOfSections;
        if (nsec == 0 || nsec > 96) {
            throw std::runtime_error("suspicious section count");
        }

        const uint32_t size_of_headers = nt->OptionalHeader.SizeOfHeaders;
        if (size_of_headers == 0 || size_of_headers > buf.size()) {
            throw std::runtime_error("invalid SizeOfHeaders");
        }

        const uint64_t sec_table_off = nt_off + sizeof(IMAGE_NT_HEADERS64);
        const uint64_t sec_table_len = static_cast<uint64_t>(nsec) * sizeof(IMAGE_SECTION_HEADER);
        if (!range_in_bounds_u64(sec_table_off, sec_table_len, file_sz)) {
            throw std::runtime_error("section table out of file bounds");
        }

        const auto* sect = reinterpret_cast<const IMAGE_SECTION_HEADER*>(buf.data() + sec_table_off);

        if (opt.verbose) {
            vlog(opt, "PE sections:");
            for (uint16_t i = 0; i < nsec; ++i) {
                std::ostringstream oss;
                oss << "  [" << i << "] " << secname8(sect[i])
                    << " VA=0x" << std::hex << sect[i].VirtualAddress
                    << " VSz=0x" << sect[i].Misc.VirtualSize
                    << " Raw=0x" << sect[i].PointerToRawData
                    << " RawSz=0x" << sect[i].SizeOfRawData
                    << std::dec;
                vlog(opt, oss.str());
            }
        }

        std::vector<DirRange> dirs;
        dirs.reserve(12);

        const auto& dd = nt->OptionalHeader.DataDirectory;

        auto push_dir = [&](int idx, const char* name) {
            const uint32_t rva = dd[idx].VirtualAddress;
            const uint32_t sz = dd[idx].Size;

            if (rva == 0 || sz == 0) return;

            dirs.push_back({ rva, sz });

            if (opt.verbose) {
                std::ostringstream oss;
                oss << "directory " << name
                    << " rva=0x" << std::hex << rva
                    << " size=0x" << sz
                    << std::dec;
                vlog(opt, oss.str());
            }
            };

        push_dir(IMAGE_DIRECTORY_ENTRY_EXPORT, "EXPORT");
        push_dir(IMAGE_DIRECTORY_ENTRY_IMPORT, "IMPORT");
        push_dir(IMAGE_DIRECTORY_ENTRY_RESOURCE, "RESOURCE");
        push_dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION, "EXCEPTION");
        push_dir(IMAGE_DIRECTORY_ENTRY_BASERELOC, "BASERELOC");
        push_dir(IMAGE_DIRECTORY_ENTRY_DEBUG, "DEBUG");
        push_dir(IMAGE_DIRECTORY_ENTRY_IAT, "IAT");
        push_dir(IMAGE_DIRECTORY_ENTRY_TLS, "TLS");
        push_dir(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, "BOUND_IMPORT");
        push_dir(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, "DELAY_IMPORT");

        const IMAGE_SECTION_HEADER* meta_sec = nullptr;
        for (uint16_t i = 0; i < nsec; ++i) {
            if (is_meta_section_name(sect[i])) {
                meta_sec = &sect[i];
                break;
            }
        }

        if (!meta_sec) {
            throw std::runtime_error("missing metadata section (.ccgtr). Protected binary must include CCGT runtime header + allocated g_meta.");
        }

        if (meta_sec->PointerToRawData == 0 || meta_sec->SizeOfRawData == 0) {
            throw std::runtime_error("metadata section has no raw data (unexpected)");
        }

        if (meta_sec->SizeOfRawData < sizeof(Meta)) {
            throw std::runtime_error("metadata section too small for Meta");
        }

        if (!range_in_bounds_u64(meta_sec->PointerToRawData, sizeof(Meta), file_sz)) {
            throw std::runtime_error("meta section raw region out of file bounds");
        }

        if (opt.verbose) {
            std::ostringstream oss;
            oss << "meta section: " << secname8(*meta_sec)
                << " raw=0x" << std::hex << meta_sec->PointerToRawData
                << " rawsz=0x" << meta_sec->SizeOfRawData
                << " va=0x" << meta_sec->VirtualAddress
                << std::dec;
            vlog(opt, oss.str());
        }

        Meta meta{};
        meta.count = 0;
        meta.capacity = META_CAPACITY;

        uint8_t master[MASTER_KEY_LEN]{};
        uint8_t mask[MASTER_KEY_LEN]{};

        try {
            gen_random_or_throw(master, sizeof(master));
            gen_random_or_throw(mask, sizeof(mask));
        }
        catch (...) {
            SecureZeroMemory(master, sizeof(master));
            SecureZeroMemory(mask, sizeof(mask));
            throw;
        }

        for (size_t i = 0; i < MASTER_KEY_LEN; ++i) {
            meta.key_mask[i] = mask[i];
            meta.key_frag[i] = master[i] ^ mask[i];
        }

        std::unordered_set<uint64_t> seen_offsets;
        seen_offsets.reserve(scanned_strings.size() * 2ULL);

        vlog(opt, "scanner strings: " + std::to_string(scanned_strings.size()));

        for (size_t idx = 0; idx < scanned_strings.size(); ++idx) {
            if (meta.count >= META_CAPACITY) break;

            const auto& s = scanned_strings[idx];

            const uint64_t file_off = static_cast<uint64_t>(s.file_offset);
            const uint64_t len_reported = static_cast<uint64_t>(s.length);

            auto skip = [&](std::string_view why) {
                res.skipped++;
                if (opt.verbose) {
                    std::ostringstream oss;
                    oss << "skip idx=" << idx
                        << " off=0x" << std::hex << file_off
                        << " len=" << std::dec << len_reported
                        << " reason=" << why;
                    vlog(opt, oss.str());
                }
                };

            if (opt.require_nullterm && !s.null_terminated) { skip("not null-terminated"); continue; }
            if (!s.is_ascii) { skip("non-ascii"); continue; }
            if (!s.issues.empty() && s.issues != "none") { skip("scanner issues present"); continue; }

            if (len_reported < opt.min_len) { skip("below min_len"); continue; }
            if (len_reported > opt.max_len) { skip("above max_len"); continue; }

            if (len_reported > (std::numeric_limits<uint32_t>::max)()) {
                skip("length exceeds u32");
                continue;
            }

            if (file_off >= file_sz) { skip("file offset out of bounds"); continue; }
            if (file_off < size_of_headers) { skip("within headers"); continue; }

            if (!seen_offsets.insert(file_off).second) {
                skip("duplicate file offset");
                continue;
            }

            const IMAGE_SECTION_HEADER* owner = nullptr;
            for (uint16_t si = 0; si < nsec; ++si) {
                if (fileoff_is_in_section(sect[si], file_off)) {
                    owner = &sect[si];
                    break;
                }
            }
            if (!owner) { skip("no owning section"); continue; }
            if (is_meta_section_name(*owner)) { skip("belongs to meta section"); continue; }
            if (!is_rdata_or_data(*owner)) { skip("not in .rdata/.data"); continue; }

            if (file_off > (std::numeric_limits<uint32_t>::max)()) {
                skip("file offset exceeds u32");
                continue;
            }

            const uint32_t file_off32 = static_cast<uint32_t>(file_off);
            const uint32_t rva = fileoff_to_rva_checked(*owner, file_off32);
            if (!rva) { skip("fileoff_to_rva failed"); continue; }

            uint64_t crypto_len64 = len_reported;

            if (opt.include_nullterm_in_crypto && s.null_terminated) {
                const uint64_t null_pos = file_off + len_reported;
                if (null_pos < file_sz && buf[static_cast<size_t>(null_pos)] == 0x00) {
                    crypto_len64 += 1;
                }
            }

            if (crypto_len64 == 0) { skip("crypto_len=0"); continue; }
            if (crypto_len64 > (std::numeric_limits<uint32_t>::max)()) { skip("crypto_len exceeds u32"); continue; }

            if (!range_in_bounds_u64(file_off, crypto_len64, file_sz)) { skip("crypto range out of file bounds"); continue; }

            bool bad = false;
            for (const auto& d : dirs) {
                if (overlaps_checked(rva, static_cast<uint32_t>(crypto_len64), d)) {
                    bad = true;
                    break;
                }
            }
            if (bad) { skip("overlaps PE directory range"); continue; }

            res.candidates++;

            uint64_t seed = 0;
            try {
                seed = gen_u64_or_throw();
            }
            catch (...) {
                skip("failed RNG seed");
                continue;
            }

            uint8_t nonce12[NONCE_LEN]{};
            derive_nonce96(nonce12, seed, rva);

            if (opt.verbose) {
                std::ostringstream oss;
                oss << "encrypt idx=" << idx
                    << " section=" << secname8(*owner)
                    << " off=0x" << std::hex << file_off32
                    << " rva=0x" << rva
                    << " len=" << std::dec << crypto_len64
                    << " seed=0x" << std::hex << seed
                    << std::dec;
                vlog(opt, oss.str());
            }

            chacha20_xor(buf.data() + static_cast<size_t>(file_off),
                static_cast<size_t>(crypto_len64),
                master,
                nonce12);

            meta.regions[meta.count].rva = rva;
            meta.regions[meta.count].len = static_cast<uint32_t>(crypto_len64);
            meta.regions[meta.count].seed = seed;
            meta.count++;

            SecureZeroMemory(nonce12, sizeof(nonce12));
        }

        const uint64_t meta_raw = static_cast<uint64_t>(meta_sec->PointerToRawData);

        if (opt.verbose) {
            std::ostringstream oss;
            oss << "writing meta: raw=0x" << std::hex << meta_raw
                << " size=" << std::dec << sizeof(Meta)
                << " regions=" << meta.count;
            vlog(opt, oss.str());
        }

        std::memcpy(buf.data() + meta_sec->PointerToRawData, &meta, sizeof(Meta));

        res.meta_written = 1;
        res.encrypted = meta.count;

        SecureZeroMemory(master, sizeof(master));
        SecureZeroMemory(mask, sizeof(mask));

        if (!opt.dry_run) {
            write_all(target, buf);
            vlog(opt, "file write complete");
        }
        else {
            vlog(opt, "dry-run enabled: not writing file");
        }

        return res;
    }
}