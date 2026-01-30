#include "ccgt_keygen.h"

#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <stdexcept>

namespace CCGT::Keygen {
    static void bcrypt_check_or_throw(NTSTATUS st, const char* msg) {
        if (st != 0) {
            throw std::runtime_error(msg);
        }
    }

    static std::filesystem::path exe_dir_or_throw() {
        std::vector<wchar_t> path(260);
        for (;;) {
            DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
            if (len == 0) {
                throw std::runtime_error("GetModuleFileNameW failed");
            }
            if (len < path.size() - 1) {
                path.resize(len + 1);
                break;
            }
            if (path.size() >= 32768) {
                throw std::runtime_error("executable path too long");
            }
            path.resize(path.size() * 2);
        }
        std::filesystem::path p(path.data());
        return p.parent_path();
    }

    static bool read_text_file(const std::filesystem::path& p, std::string& out) {
        std::ifstream f(p, std::ios::binary);
        if (!f) return false;
        std::ostringstream oss;
        oss << f.rdbuf();
        out = oss.str();
        return true;
    }

    static std::string format_blob(const std::vector<uint8_t>& blob) {
        std::ostringstream oss;
        oss << "{";
        for (size_t i = 0; i < blob.size(); ++i) {
            if (i % 12 == 0) {
                oss << "\n    ";
            }
            oss << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(blob[i]);
            if (i + 1 < blob.size()) {
                oss << ", ";
            }
        }
        oss << "\n}";
        return oss.str();
    }

    static void write_header(
        const std::filesystem::path& p,
        const char* valid_name,
        const char* blob_name,
        const std::vector<uint8_t>& blob
    ) {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        if (!f) {
            throw std::runtime_error("failed to write: " + p.string());
        }

        f << "#pragma once\n\n";
        f << "#include <cstddef>\n";
        f << "#include <cstdint>\n\n";
        f << "namespace CCGT::Sig {\n\n";
        f << "inline constexpr bool " << valid_name << " = true;\n";
        f << "inline constexpr uint8_t " << blob_name << "[] = " << format_blob(blob) << ";\n";
        f << "inline constexpr size_t " << blob_name << "Len = sizeof(" << blob_name << ");\n\n";
        f << "} // namespace CCGT::Sig\n";

        if (!f) {
            throw std::runtime_error("write failed: " + p.string());
        }
    }

    static void write_binary(const std::filesystem::path& p, const std::vector<uint8_t>& blob) {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        if (!f) {
            throw std::runtime_error("failed to write: " + p.string());
        }
        f.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
        if (!f) {
            throw std::runtime_error("write failed: " + p.string());
        }
    }

    static void generate_keypair(std::vector<uint8_t>& out_priv, std::vector<uint8_t>& out_pub) {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;

        bcrypt_check_or_throw(
            BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0),
            "BCryptOpenAlgorithmProvider(ECDSA_P256) failed"
        );

        bcrypt_check_or_throw(
            BCryptGenerateKeyPair(alg, &key, 256, 0),
            "BCryptGenerateKeyPair failed"
        );

        bcrypt_check_or_throw(
            BCryptFinalizeKeyPair(key, 0),
            "BCryptFinalizeKeyPair failed"
        );

        ULONG cb_priv = 0;
        ULONG cb_pub = 0;
        bcrypt_check_or_throw(
            BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &cb_priv, 0),
            "BCryptExportKey(private) size failed"
        );
        bcrypt_check_or_throw(
            BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &cb_pub, 0),
            "BCryptExportKey(public) size failed"
        );

        out_priv.resize(cb_priv);
        out_pub.resize(cb_pub);

        bcrypt_check_or_throw(
            BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB, out_priv.data(), cb_priv, &cb_priv, 0),
            "BCryptExportKey(private) failed"
        );
        bcrypt_check_or_throw(
            BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, out_pub.data(), cb_pub, &cb_pub, 0),
            "BCryptExportKey(public) failed"
        );

        if (key) BCryptDestroyKey(key);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    }

    static bool looks_configured(const std::string& s, const char* key_name) {
        if (s.find(std::string(key_name) + " = true") != std::string::npos) return true;
        if (s.find(std::string(key_name) + "=true") != std::string::npos) return true;
        return false;
    }

    static bool resolve_key_paths(std::filesystem::path& priv_out, std::filesystem::path& pub_out) {
        const auto cwd = std::filesystem::current_path();
        const auto exe_dir = exe_dir_or_throw();

        const std::vector<std::filesystem::path> roots = {
            exe_dir,
            exe_dir.parent_path(),
            exe_dir.parent_path().parent_path(),
            cwd
        };

        for (const auto& root : roots) {
            const auto priv = root / "src" / "ccgt_sig_priv.h";
            const auto pub = root / "include" / "ccgt_sig_pub.h";
            if (std::filesystem::exists(priv) && std::filesystem::exists(pub)) {
                priv_out = priv;
                pub_out = pub;
                return true;
            }
        }
        return false;
    }

    Status ensure_keys(std::string& out_msg) {
        try {
            std::filesystem::path priv_path;
            std::filesystem::path pub_path;
            if (!resolve_key_paths(priv_path, pub_path)) {
                out_msg = "unable to locate src/ccgt_sig_priv.h and include/ccgt_sig_pub.h";
                return Status::Failed;
            }

            std::string priv_txt;
            std::string pub_txt;
            const bool priv_ok = read_text_file(priv_path, priv_txt);
            const bool pub_ok = read_text_file(pub_path, pub_txt);
            if (priv_ok && pub_ok &&
                looks_configured(priv_txt, "kPrivateKeyValid") &&
                looks_configured(pub_txt, "kPublicKeyValid"))
            {
                out_msg = "keys already configured in headers";
                return Status::AlreadyConfigured;
            }

            std::vector<uint8_t> priv;
            std::vector<uint8_t> pub;
            generate_keypair(priv, pub);

            write_header(priv_path, "kPrivateKeyValid", "kPrivateKeyBlob", priv);
            write_header(pub_path, "kPublicKeyValid", "kPublicKeyBlob", pub);
            const auto priv_bin = exe_dir_or_throw() / "ccgt_priv.bin";
            write_binary(priv_bin, priv);

            out_msg = "generated keypair and wrote headers";
            return Status::Generated;
        }
        catch (const std::exception& e) {
            out_msg = e.what();
            return Status::Failed;
        }
    }

    bool private_key_file_exists() {
        try {
            const auto exe_dir = exe_dir_or_throw();
            const std::vector<std::filesystem::path> candidates = {
                exe_dir / "ccgt_priv.bin",
                std::filesystem::current_path() / "ccgt_priv.bin"
            };
            for (const auto& p : candidates) {
                std::error_code ec{};
                if (std::filesystem::exists(p, ec) && !ec) {
                    return true;
                }
            }
        }
        catch (...) {
        }
        return false;
    }
}
