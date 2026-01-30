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
#include <stdexcept>

#include "../include/ccgt_aead.h"
#include "../include/ccgt_meta.h"
#include "../include/ccgt_secure.h"
#include "ccgt_sig_priv.h"

namespace CCGT::Patcher
{
#if defined(_MSC_VER)
#   define CCGT_FORCEINLINE __forceinline
#else
#   define CCGT_FORCEINLINE inline __attribute__((always_inline))
#endif

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

    static CCGT_FORCEINLINE void bcrypt_check_or_throw(NTSTATUS st, const char* msg)
    {
        if (st != 0) {
            throw std::runtime_error(msg);
        }
    }

    struct HashCtx {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        std::vector<uint8_t> obj;
        ~HashCtx() {
            if (hash) BCryptDestroyHash(hash);
            if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        }
    };

    static HashCtx sha256_start()
    {
        HashCtx ctx;
        bcrypt_check_or_throw(
            BCryptOpenAlgorithmProvider(&ctx.alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
            "BCryptOpenAlgorithmProvider(SHA256) failed"
        );

        ULONG obj_len = 0;
        ULONG cb = 0;
        bcrypt_check_or_throw(
            BCryptGetProperty(ctx.alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0),
            "BCryptGetProperty(OBJECT_LENGTH) failed"
        );

        ctx.obj.resize(obj_len);
        bcrypt_check_or_throw(
            BCryptCreateHash(ctx.alg, &ctx.hash, ctx.obj.data(), obj_len, nullptr, 0, 0),
            "BCryptCreateHash failed"
        );

        return ctx;
    }

    static void sha256_update(HashCtx& ctx, const uint8_t* data, size_t len)
    {
        if (!data || len == 0) return;
        if (len > (std::numeric_limits<ULONG>::max)()) {
            throw std::runtime_error("sha256_update length too large");
        }
        bcrypt_check_or_throw(
            BCryptHashData(ctx.hash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0),
            "BCryptHashData failed"
        );
    }

    static void sha256_finish(HashCtx& ctx, uint8_t out32[32])
    {
        bcrypt_check_or_throw(
            BCryptFinishHash(ctx.hash, out32, 32, 0),
            "BCryptFinishHash failed"
        );
    }

    struct ZeroRange {
        uint64_t off = 0;
        uint64_t len = 0;
    };

    static void normalize_zero_ranges(std::vector<ZeroRange>& ranges)
    {
        if (ranges.empty()) return;
        std::sort(ranges.begin(), ranges.end(), [](const ZeroRange& a, const ZeroRange& b) {
            return a.off < b.off;
        });

        std::vector<ZeroRange> merged;
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

    static void hash_file_with_zeroed_ranges(
        const std::vector<uint8_t>& buf,
        std::vector<ZeroRange> ranges,
        uint8_t out_hash32[32]
    )
    {
        normalize_zero_ranges(ranges);

        HashCtx ctx = sha256_start();
        static constexpr size_t kZeroChunk = 4096;
        uint8_t zeros[kZeroChunk] = {};

        uint64_t pos = 0;
        for (const auto& r : ranges) {
            if (!range_in_bounds_u64(r.off, r.len, to_u64(buf.size()))) {
                throw std::runtime_error("zero range out of bounds");
            }
            if (r.off > pos) {
                const uint64_t n = r.off - pos;
                sha256_update(ctx, buf.data() + pos, static_cast<size_t>(n));
            }
            uint64_t left = r.len;
            while (left) {
                const size_t chunk = (left > kZeroChunk) ? kZeroChunk : static_cast<size_t>(left);
                sha256_update(ctx, zeros, chunk);
                left -= chunk;
            }
            pos = r.off + r.len;
        }
        if (pos < buf.size()) {
            sha256_update(ctx, buf.data() + pos, buf.size() - static_cast<size_t>(pos));
        }
        sha256_finish(ctx, out_hash32);
    }

    static void sign_hash_p256(const uint8_t hash32[32], uint8_t out_sig64[CCGT::SIGNATURE_LEN])
    {
        auto get_exe_dir = []() -> std::filesystem::path {
            std::vector<wchar_t> path(260);
            for (;;) {
                DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
                if (len == 0) break;
                if (len < path.size() - 1) {
                    path.resize(len + 1);
                    break;
                }
                if (path.size() >= 32768) break;
                path.resize(path.size() * 2);
            }
            return std::filesystem::path(path.data()).parent_path();
        };

        auto try_load_priv_from_file = [&](std::vector<uint8_t>& out_blob) -> bool {
            const auto exe_dir = get_exe_dir();
            const std::vector<std::filesystem::path> candidates = {
                exe_dir / "ccgt_priv.bin",
                std::filesystem::current_path() / "ccgt_priv.bin"
            };

            for (const auto& p : candidates) {
                std::error_code ec{};
                const auto sz = std::filesystem::file_size(p, ec);
                if (ec || sz == 0 || sz > 4096) continue;

                std::ifstream f(p, std::ios::binary);
                if (!f) continue;

                out_blob.resize(static_cast<size_t>(sz));
                f.read(reinterpret_cast<char*>(out_blob.data()), static_cast<std::streamsize>(out_blob.size()));
                if (!f || f.gcount() != static_cast<std::streamsize>(out_blob.size())) {
                    out_blob.clear();
                    continue;
                }
                return true;
            }
            return false;
        };

        const uint8_t* key_blob = CCGT::Sig::kPrivateKeyBlob;
        size_t key_blob_len = CCGT::Sig::kPrivateKeyBlobLen;
        std::vector<uint8_t> file_blob;

        if (!CCGT::Sig::kPrivateKeyValid) {
            if (!try_load_priv_from_file(file_blob)) {
                throw std::runtime_error("signing key not configured");
            }
            key_blob = file_blob.data();
            key_blob_len = file_blob.size();
        }

        if (key_blob_len > (std::numeric_limits<ULONG>::max)()) {
            throw std::runtime_error("signing key blob too large");
        }

        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;

        bcrypt_check_or_throw(
            BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0),
            "BCryptOpenAlgorithmProvider(ECDSA_P256) failed"
        );

        const NTSTATUS st = BCryptImportKeyPair(
            alg,
            nullptr,
            BCRYPT_ECCPRIVATE_BLOB,
            &key,
            const_cast<PUCHAR>(key_blob),
            static_cast<ULONG>(key_blob_len),
            0
        );
        if (st != 0) {
            if (key) BCryptDestroyKey(key);
            if (alg) BCryptCloseAlgorithmProvider(alg, 0);
            throw std::runtime_error("BCryptImportKeyPair failed");
        }

        ULONG cb_sig = 0;
        bcrypt_check_or_throw(
            BCryptSignHash(key, nullptr, const_cast<PUCHAR>(hash32), 32, out_sig64, CCGT::SIGNATURE_LEN, &cb_sig, 0),
            "BCryptSignHash failed"
        );

        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(alg, 0);

        if (cb_sig != CCGT::SIGNATURE_LEN) {
            throw std::runtime_error("unexpected signature size");
        }
    }

    static void sign_meta_or_throw(
        CCGT::Meta& meta,
        std::vector<uint8_t>& buf,
        uint64_t meta_raw,
        uint64_t cert_off,
        uint64_t cert_len
    )
    {
        meta.sig_alg = CCGT::SIG_ALG_ECDSA_P256;
        meta.sig_len = static_cast<uint32_t>(CCGT::SIGNATURE_LEN);
        std::memset(meta.signature, 0, sizeof(meta.signature));

        if (!range_in_bounds_u64(meta_raw, sizeof(CCGT::Meta), to_u64(buf.size()))) {
            throw std::runtime_error("meta raw range out of bounds");
        }

        std::memcpy(buf.data() + meta_raw, &meta, sizeof(CCGT::Meta));

        const uint64_t sig_off = meta_raw + offsetof(CCGT::Meta, signature);

        std::vector<ZeroRange> ranges;
        ranges.reserve(2);
        ranges.push_back({ sig_off, CCGT::SIGNATURE_LEN });
        if (cert_off && cert_len) {
            ranges.push_back({ cert_off, cert_len });
        }

        uint8_t hash32[32];
        hash_file_with_zeroed_ranges(buf, ranges, hash32);
        sign_hash_p256(hash32, meta.signature);
        ccgt::crypto::secure_zero(hash32, sizeof(hash32));
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
        uint64_t cert_off = 0;
        uint64_t cert_len = 0;

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

        const uint32_t cert_dir_off = dd[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        const uint32_t cert_dir_sz = dd[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        if (cert_dir_off != 0 && cert_dir_sz != 0) {
            cert_off = cert_dir_off;
            cert_len = cert_dir_sz;
            if (!range_in_bounds_u64(cert_off, cert_len, file_sz)) {
                throw std::runtime_error("certificate directory out of file bounds");
            }
            if (opt.verbose) {
                std::ostringstream oss;
                oss << "certificate dir: off=0x" << std::hex << cert_off
                    << " size=0x" << cert_len
                    << std::dec;
                vlog(opt, oss.str());
            }
        }

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

        if (meta_sec->SizeOfRawData < sizeof(CCGT::Meta)) {
            throw std::runtime_error("metadata section too small for Meta (need bigger .ccgtr section)");
        }

        if (!range_in_bounds_u64(meta_sec->PointerToRawData, sizeof(CCGT::Meta), file_sz)) {
            throw std::runtime_error("meta section raw region out of file bounds");
        }

        const uint64_t meta_raw = static_cast<uint64_t>(meta_sec->PointerToRawData);

        if (opt.verbose) {
            std::ostringstream oss;
            oss << "meta section: " << secname8(*meta_sec)
                << " raw=0x" << std::hex << meta_sec->PointerToRawData
                << " rawsz=0x" << meta_sec->SizeOfRawData
                << " va=0x" << meta_sec->VirtualAddress
                << std::dec;
            vlog(opt, oss.str());
        }

        CCGT::Meta meta{};
        meta.count = 0;
        meta.capacity = CCGT::META_CAPACITY;

        uint8_t master[CCGT::MASTER_KEY_LEN]{};
        uint8_t mask[CCGT::MASTER_KEY_LEN]{};

        try {
            gen_random_or_throw(master, sizeof(master));
            gen_random_or_throw(mask, sizeof(mask));
        }
        catch (...) {
            SecureZeroMemory(master, sizeof(master));
            SecureZeroMemory(mask, sizeof(mask));
            throw;
        }

        for (size_t i = 0; i < CCGT::MASTER_KEY_LEN; ++i) {
            meta.key_mask[i] = mask[i];
            meta.key_frag[i] = master[i] ^ mask[i];
        }

        std::unordered_set<uint64_t> seen_offsets;
        seen_offsets.reserve(scanned_strings.size() * 2ULL);

        vlog(opt, "scanner strings: " + std::to_string(scanned_strings.size()));

        for (size_t idx = 0; idx < scanned_strings.size(); ++idx) {
            if (meta.count >= CCGT::META_CAPACITY) break;

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

            if (!seen_offsets.insert(file_off).second) { skip("duplicate file offset"); continue; }

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
            if (crypto_len64 > (std::numeric_limits<uint32_t>::max)()) {
                skip("crypto_len exceeds u32");
                continue;
            }

            if (!range_in_bounds_u64(file_off, crypto_len64, file_sz)) {
                skip("crypto range out of file bounds");
                continue;
            }

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

            const uint32_t crypto_len32 = static_cast<uint32_t>(crypto_len64);

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

            uint8_t aad[16];
            
            std::memcpy(aad + 0, &rva, 4);
            std::memcpy(aad + 4, &crypto_len32, 4);
            std::memcpy(aad + 8, &seed, 8);

            uint8_t tag[16];
            ccgt::crypto::seal_chacha20_poly1305_inplace(
                buf.data() + static_cast<size_t>(file_off),
                static_cast<size_t>(crypto_len64),
                master,
                seed,
                rva,
                aad,
                sizeof(aad),
                tag
            );

            meta.regions[meta.count].rva = rva;
            meta.regions[meta.count].len = crypto_len32;
            meta.regions[meta.count].seed = seed;
            std::memcpy(meta.regions[meta.count].tag, tag, 16);
            meta.count++;

            ccgt::crypto::secure_zero(tag, sizeof(tag));
            ccgt::crypto::secure_zero(aad, sizeof(aad));
        }

        sign_meta_or_throw(meta, buf, meta_raw, cert_off, cert_len);

        if (opt.verbose) {
            std::ostringstream oss;
            oss << "writing meta: raw=0x" << std::hex << meta_raw
                << " size=" << std::dec << sizeof(CCGT::Meta)
                << " regions=" << meta.count;
            vlog(opt, oss.str());
        }

        std::memcpy(buf.data() + meta_sec->PointerToRawData, &meta, sizeof(CCGT::Meta));

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
