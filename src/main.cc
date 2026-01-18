#include <iostream>
#include <filesystem>
#include <string>

#include "strings.h"
#include "ccgt.h"

static void usage() {
    std::cerr <<
        "usage:\n"
        "  ccgt <binary.exe> [--scan] [--dry-run] [-v|--verbose] [--min N] [--max N] [--no-backup]\n"
        "\n"
        "notes:\n"
        "  - default action is PATCH (encrypt strings + write meta)\n"
        "  - --scan prints findings only\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    std::filesystem::path target = argv[1];
    if (!std::filesystem::exists(target)) {
        std::cerr << "error: file not found\n";
        return 1;
    }

    bool scan_only = false;

    CCGT::Patcher::Options opt{};
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];

        if (a == "--scan") scan_only = true;
        else if (a == "--dry-run") opt.dry_run = true;
        else if (a == "-v" || a == "--verbose") opt.verbose = true;
        else if (a == "--no-backup") opt.make_backup = false;
        else if (a == "--min" && i + 1 < argc) { opt.min_len = (size_t)std::stoul(argv[++i]); }
        else if (a == "--max" && i + 1 < argc) { opt.max_len = (size_t)std::stoul(argv[++i]); }
        else {
            std::cerr << "unknown arg: " << a << "\n";
            usage();
            return 1;
        }
    }

    auto vlog = [&](const std::string& s) {
        if (opt.verbose) std::cout << s << "\n";
        };

    try {
        vlog("target: " + target.string());

        auto results = scan_strings(target);

        if (scan_only) {
            for (const auto& s : results) {
                std::cout
                    << "offset=0x" << std::hex << s.file_offset
                    << " len=" << std::dec << s.length
                    << " nullterm=" << (s.null_terminated ? "yes" : "no")
                    << " ascii=" << (s.is_ascii ? "yes" : "no")
                    << " issues=" << s.issues
                    << "\n";
            }
            std::cout << "\nTotal strings: " << results.size() << "\n";
            return 0;
        }

        auto pr = CCGT::Patcher::patch_file(target, results, opt);

        std::cout << "patched: " << target.string() << "\n";
        std::cout << "scanned strings: " << results.size() << "\n";
        std::cout << "candidates: " << pr.candidates << "\n";
        std::cout << "encrypted: " << pr.encrypted << "\n";
        std::cout << "skipped: " << pr.skipped << "\n";
        std::cout << "meta written: " << (pr.meta_written ? "yes" : "no") << "\n";

        if (opt.dry_run) {
            std::cout << "dry-run: yes (no bytes written)\n";
        }

        if (opt.verbose) {
            std::cout << "\noptions:\n";
            std::cout << "  backup: " << (opt.make_backup ? "yes" : "no") << "\n";
            std::cout << "  min_len: " << opt.min_len << "\n";
            std::cout << "  max_len: " << opt.max_len << "\n";
            std::cout << "  require_nullterm: " << (opt.require_nullterm ? "yes" : "no") << "\n";
            std::cout << "  include_nullterm_in_crypto: " << (opt.include_nullterm_in_crypto ? "yes" : "no") << "\n";
        }
    }
    catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 2;
    }

    return 0;
}