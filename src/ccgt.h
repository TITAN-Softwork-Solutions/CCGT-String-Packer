#pragma once
#include <filesystem>
#include <vector>
#include <cstdint>

#include "strings.h"

namespace CCGT::Patcher
{
    struct Options {
        size_t min_len = 4;
        size_t max_len = 1024;
        bool   require_nullterm = true;   // only patch null-terminated strings
        bool   include_nullterm_in_crypto = true; // encrypt the terminating '\0' too
        bool   make_backup = true;        // writes <file>.bak once
        bool   dry_run = false;           // don't write modified bytes
        bool   verbose = false;
    };

    struct Result {
        uint32_t candidates = 0;
        uint32_t encrypted = 0;
        uint32_t skipped = 0;
        uint32_t meta_written = 0;
    };

    Result patch_file(
        const std::filesystem::path& target,
        const std::vector<decltype(scan_strings(std::filesystem::path{}))::value_type > & scanned_strings,
        const Options& opt = {}
    );
}